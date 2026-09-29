"""Signed append-only provider evidence and idempotent restart handling."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import tempfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from smf.ai.models import (
    AdvisoryEvidenceReference,
    AIConfigurationState,
    AIEvidenceClass,
    AIFinishReason,
    AIOperation,
    AIProviderOutcome,
    AIProviderRequest,
    AIProviderResult,
    AIProviderState,
    AITarget,
    TransientAIProviderBytes,
)
from smf.ai.prerequisites import (
    AIProviderPrerequisites,
    AIProviderVerifierConfiguration,
    verify_provider_prerequisites,
)
from smf.ai.provider import (
    AIProvider,
    _invoke_ai_provider,
    invoke_ai_provider,
    provider_decision_id,
    provider_input_issue,
)
from smf.ai.telemetry import ai_provider_event
from smf.security.ai_policy import canonical_ai_json
from smf.security.schema import validate_security_schema

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def provider_evidence_dir(root: Path, request: AIProviderRequest) -> Path:
    for value in (
        request.run_id,
        request.workload_id,
        request.workflow_attempt_id,
        request.provider_request_id,
        request.provider_attempt_id,
    ):
        if not _SAFE.fullmatch(value) or value in {".", ".."}:
            raise ValueError("Unsafe AI provider evidence identity")
    path = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.workflow_attempt_id
        / "ai-provider"
        / request.provider_request_id
        / request.provider_attempt_id
    )
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("AI provider evidence path escapes output root")
    return path


def _sign(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    if not _SAFE.fullmatch(key_id):
        raise ValueError("Unsafe evidence signing key identity")
    signed = dict(payload)
    signed["proof"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(canonical_ai_json(payload))).decode("ascii"),
    }
    return signed


def _verify(payload: dict[str, Any], keys: Mapping[str, Ed25519PublicKey]) -> None:
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("AI provider evidence lacks trusted proof")
    key_id = proof.get("key_id")
    if proof.get("algorithm") != "ed25519" or not isinstance(key_id, str) or key_id not in keys:
        raise ValueError("AI provider evidence proof is untrusted")
    unsigned = dict(payload)
    unsigned.pop("proof")
    try:
        signature = base64.b64decode(proof.get("value", ""), validate=True)
        keys[key_id].verify(signature, canonical_ai_json(unsigned))
    except (TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("AI provider evidence proof is invalid") from exc


def _publish(path: Path, payload: dict[str, Any]) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == payload:
            return False
        raise FileExistsError(f"Conflicting immutable AI provider evidence: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ai-provider-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if json.loads(path.read_text(encoding="utf-8")) != payload:
                raise FileExistsError(
                    f"Conflicting immutable AI provider evidence: {path}"
                ) from None
            return False
        return True
    finally:
        temporary.unlink(missing_ok=True)


def _load_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid AI provider evidence") from exc
    if not isinstance(payload, dict):
        raise ValueError("AI provider evidence must be an object")
    return payload


def _request_from_bindings(value: object) -> AIProviderRequest:
    if not isinstance(value, dict):
        raise ValueError("AI provider request binding must be an object")
    fields = dict(value)
    try:
        fields["operation"] = AIOperation(fields["operation"])
        fields["target"] = AITarget(fields["target"])
        fields["configuration_state"] = AIConfigurationState(fields["configuration_state"])
        fields["source_artifact_ids"] = tuple(fields["source_artifact_ids"])
        fields["advisory_evidence"] = tuple(
            AdvisoryEvidenceReference(**item) for item in fields["advisory_evidence"]
        )
        return AIProviderRequest(**fields)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("AI provider request binding is invalid") from exc


def write_provider_preparation(
    root: Path,
    request: AIProviderRequest,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    payload = {
        "schema_version": "1.0",
        "decision_id": provider_decision_id(request),
        "request_digest": request.request_digest,
        "request": request.bindings(),
        "state": "prepared",
        "evidence_refs": [
            request.sec02_result_ref,
            request.prompt_policy_ref,
            request.prompt_template_ref,
            request.transport_policy_ref,
            request.configuration_ref,
            request.retention_policy_ref,
            request.access_policy_ref,
        ],
    }
    signed = _sign(payload, signing_key, key_id)
    validate_security_schema("ai-provider-preparation.schema.json", signed)
    path = provider_evidence_dir(root, request) / "preparation.json"
    _publish(path, signed)
    return path


def load_provider_preparation(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    payload = _load_object(path)
    _verify(payload, verification_keys)
    validate_security_schema("ai-provider-preparation.schema.json", payload)
    request = _request_from_bindings(payload["request"])
    expected_refs = [
        request.sec02_result_ref,
        request.prompt_policy_ref,
        request.prompt_template_ref,
        request.transport_policy_ref,
        request.configuration_ref,
        request.retention_policy_ref,
        request.access_policy_ref,
    ]
    if (
        payload["decision_id"] != provider_decision_id(request)
        or payload["request_digest"] != request.request_digest
        or payload["evidence_refs"] != expected_refs
    ):
        raise ValueError("AI provider preparation binding mismatch")
    return payload


def write_invocation_marker(
    root: Path,
    request: AIProviderRequest,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> tuple[Path, bool]:
    payload = {
        "schema_version": "1.0",
        "decision_id": provider_decision_id(request),
        "request_digest": request.request_digest,
        "state": "invocation_started",
    }
    path = provider_evidence_dir(root, request) / "invocation.json"
    return path, _publish(path, _sign(payload, signing_key, key_id))


def load_invocation_marker(
    path: Path,
    request: AIProviderRequest,
    *,
    verification_keys: Mapping[str, Ed25519PublicKey],
) -> dict[str, Any]:
    payload = _load_object(path)
    _verify(payload, verification_keys)
    if set(payload) != {
        "schema_version",
        "decision_id",
        "request_digest",
        "state",
        "proof",
    } or (
        payload["schema_version"] != "1.0"
        or payload["state"] != "invocation_started"
        or payload["decision_id"] != provider_decision_id(request)
        or payload["request_digest"] != request.request_digest
    ):
        raise ValueError("AI provider invocation marker binding mismatch")
    return payload


def _validate_result(payload: dict[str, Any]) -> AIProviderRequest:
    validate_security_schema("ai-provider-result.schema.json", payload)
    request = _request_from_bindings(payload["request"])
    if payload["decision_id"] != provider_decision_id(request):
        raise ValueError("AI provider decision identity mismatch")
    expected_refs = [
        request.sec02_result_ref,
        request.prompt_policy_ref,
        request.prompt_template_ref,
        request.transport_policy_ref,
        request.configuration_ref,
        request.retention_policy_ref,
        request.access_policy_ref,
    ]
    if payload["state"] != "outcome_unknown" and payload["evidence_refs"] != expected_refs:
        raise ValueError("AI provider result evidence references are not request-bound")
    succeeded = payload["state"] == "succeeded"
    response_fields = (
        payload["response_digest"],
        payload["response_byte_count"],
        payload["finish_reason"],
    )
    if succeeded:
        if (
            any(value is None for value in response_fields)
            or payload["response_byte_count"] < 1
            or payload["finish_reason"] != "stop"
            or payload["blocker_codes"]
            or not payload["provider_invoked"]
            or len(payload["evidence_refs"]) != 7
        ):
            raise ValueError("AI provider success is not reconstructable")
    elif any(value is not None for value in response_fields):
        raise ValueError("Non-success provider result cannot retain response evidence")
    elif not payload["blocker_codes"]:
        raise ValueError("Non-success provider result requires an explicit blocker")
    if payload["evidence_class"] == "operational_verified":
        raise ValueError("AIP-01 cannot persist operational provider evidence")
    for flag in (
        "generated",
        "executed",
        "validated",
        "parity_passed",
        "certified",
        "human_approved",
    ):
        if payload[flag] is not False:
            raise ValueError("AI provider result cannot assert downstream success")
    return request


def write_provider_result(
    root: Path,
    result: AIProviderResult,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    if "protected_data_detected" in result.blocker_codes:
        raise ValueError("Protected AI provider input cannot produce durable evidence")
    payload = _sign(result.to_dict(), signing_key, key_id)
    request = _validate_result(payload)
    path = provider_evidence_dir(root, request) / "result.json"
    _publish(path, payload)
    _publish(path.with_name("telemetry.json"), ai_provider_event(payload))
    return path


def load_provider_result(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    payload = _load_object(path)
    _verify(payload, verification_keys)
    _validate_result(payload)
    return payload


def recover_provider_telemetry(
    result_path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> Path:
    result = load_provider_result(result_path, verification_keys=verification_keys)
    telemetry = result_path.with_name("telemetry.json")
    _publish(telemetry, ai_provider_event(result))
    return telemetry


def _loaded_result(payload: dict[str, Any]) -> AIProviderResult:
    value = dict(payload)
    value.pop("proof")
    value["state"] = AIProviderState(value["state"])
    value["evidence_class"] = AIEvidenceClass(value["evidence_class"])
    value["finish_reason"] = (
        AIFinishReason(value["finish_reason"]) if value["finish_reason"] else None
    )
    value["blocker_codes"] = tuple(value["blocker_codes"])
    value["evidence_refs"] = tuple(value["evidence_refs"])
    return AIProviderResult(**value)


def execute_provider_attempt(
    request: AIProviderRequest,
    transient_input: TransientAIProviderBytes,
    provider: AIProvider,
    *,
    evidence_root: Path,
    signing_key: Ed25519PrivateKey,
    key_id: str,
    verification_keys: Mapping[str, Ed25519PublicKey],
    prerequisites: AIProviderPrerequisites | None = None,
    verifier_configuration: AIProviderVerifierConfiguration | None = None,
    now: datetime | None = None,
) -> AIProviderOutcome:
    """Fail closed when an attempt caller also selects its verification roots."""

    # None of the per-attempt cryptographic arguments are authority: accepting
    # any of them would let a request caller mint both assertions and roots.
    # Keep the signature for compatibility while the authenticated composition
    # boundary remains explicitly deferred.
    del (
        evidence_root,
        signing_key,
        key_id,
        verification_keys,
        prerequisites,
        verifier_configuration,
        now,
    )
    if provider_input_issue(request, transient_input) == "protected_data_detected":
        return invoke_ai_provider(request, transient_input, provider)
    transient_input.clear()
    return AIProviderOutcome(
        AIProviderResult(
            schema_version="1.0",
            decision_id=provider_decision_id(request),
            request=request.bindings(),
            state=AIProviderState.BLOCKED_MISSING,
            blocker_codes=("governed_verifier_unavailable",),
            evidence_refs=(),
            evidence_class=provider.evidence_class,
            response_digest=None,
            response_byte_count=None,
            finish_reason=None,
            input_tokens=0,
            output_tokens=0,
            elapsed_ms=0,
            provider_invoked=False,
        ),
        None,
    )


def _execute_provider_attempt(
    request: AIProviderRequest,
    transient_input: TransientAIProviderBytes,
    provider: AIProvider,
    *,
    evidence_root: Path,
    signing_key: Ed25519PrivateKey,
    key_id: str,
    verification_keys: Mapping[str, Ed25519PublicKey],
    prerequisites: AIProviderPrerequisites | None = None,
    verifier_configuration: AIProviderVerifierConfiguration | None = None,
    now: datetime | None = None,
) -> AIProviderOutcome:
    """Persist and invoke exactly once; ambiguous restarts become outcome-unknown."""

    evidence_dir = provider_evidence_dir(evidence_root, request)
    result_path = evidence_dir / "result.json"
    invocation_path = evidence_dir / "invocation.json"
    if provider_input_issue(request, transient_input) == "protected_data_detected":
        return invoke_ai_provider(request, transient_input, provider)
    if result_path.exists():
        try:
            payload = load_provider_result(result_path, verification_keys=verification_keys)
            if payload["request"] != request.bindings():
                raise ValueError("Provider attempt identity was reused for another request")
            recover_provider_telemetry(result_path, verification_keys=verification_keys)
            return AIProviderOutcome(_loaded_result(payload), None)
        finally:
            transient_input.clear()
    if invocation_path.exists():
        try:
            load_invocation_marker(invocation_path, request, verification_keys=verification_keys)
            load_provider_preparation(
                evidence_dir / "preparation.json", verification_keys=verification_keys
            )
        finally:
            transient_input.clear()
        result = AIProviderResult(
            schema_version="1.0",
            decision_id=provider_decision_id(request),
            request=request.bindings(),
            state=AIProviderState.OUTCOME_UNKNOWN,
            blocker_codes=("prior_invocation_outcome_unknown",),
            evidence_refs=(),
            evidence_class=provider.evidence_class,
            response_digest=None,
            response_byte_count=None,
            finish_reason=None,
            input_tokens=0,
            output_tokens=0,
            elapsed_ms=0,
            provider_invoked=True,
        )
        # The marker may belong to a currently running caller.  Returning an
        # explicit unknown state is safe; publishing it would race that caller's
        # eventual canonical terminal result.
        return AIProviderOutcome(result, None)

    prerequisite_check = verify_provider_prerequisites(
        request,
        prerequisites,
        verifier_configuration=verifier_configuration,
        now=now,
    )
    if prerequisite_check.state is not None:
        transient_input.clear()
        result = AIProviderResult(
            schema_version="1.0",
            decision_id=provider_decision_id(request),
            request=request.bindings(),
            state=prerequisite_check.state,
            blocker_codes=(str(prerequisite_check.blocker_code),),
            evidence_refs=prerequisite_check.evidence_refs,
            evidence_class=provider.evidence_class,
            response_digest=None,
            response_byte_count=None,
            finish_reason=None,
            input_tokens=0,
            output_tokens=0,
            elapsed_ms=0,
            provider_invoked=False,
        )
        write_provider_result(evidence_root, result, signing_key=signing_key, key_id=key_id)
        return AIProviderOutcome(result, None)

    write_provider_preparation(evidence_root, request, signing_key=signing_key, key_id=key_id)
    rechecked = verify_provider_prerequisites(
        request,
        prerequisites,
        verifier_configuration=verifier_configuration,
        now=now,
    )
    if rechecked.state is not None or rechecked.snapshots != prerequisite_check.snapshots:
        transient_input.clear()
        result = AIProviderResult(
            schema_version="1.0",
            decision_id=provider_decision_id(request),
            request=request.bindings(),
            state=AIProviderState.INVALID_BINDING,
            blocker_codes=("trusted_prerequisite_changed_before_invocation",),
            evidence_refs=prerequisite_check.evidence_refs,
            evidence_class=provider.evidence_class,
            response_digest=None,
            response_byte_count=None,
            finish_reason=None,
            input_tokens=0,
            output_tokens=0,
            elapsed_ms=0,
            provider_invoked=False,
        )
        write_provider_result(evidence_root, result, signing_key=signing_key, key_id=key_id)
        return AIProviderOutcome(result, None)
    _, invocation_claimed = write_invocation_marker(
        evidence_root, request, signing_key=signing_key, key_id=key_id
    )
    if not invocation_claimed:
        try:
            if result_path.exists():
                payload = load_provider_result(result_path, verification_keys=verification_keys)
                recover_provider_telemetry(result_path, verification_keys=verification_keys)
                return AIProviderOutcome(_loaded_result(payload), None)
            load_invocation_marker(invocation_path, request, verification_keys=verification_keys)
            return AIProviderOutcome(
                AIProviderResult(
                    schema_version="1.0",
                    decision_id=provider_decision_id(request),
                    request=request.bindings(),
                    state=AIProviderState.OUTCOME_UNKNOWN,
                    blocker_codes=("invocation_in_progress_or_outcome_unknown",),
                    evidence_refs=(),
                    evidence_class=provider.evidence_class,
                    response_digest=None,
                    response_byte_count=None,
                    finish_reason=None,
                    input_tokens=0,
                    output_tokens=0,
                    elapsed_ms=0,
                    provider_invoked=True,
                ),
                None,
            )
        finally:
            transient_input.clear()
    if verifier_configuration is None:
        outcome = invoke_ai_provider(
            request,
            transient_input,
            provider,
            prerequisites=prerequisites,
            now=now,
            _expected_prerequisite_snapshots=prerequisite_check.snapshots,
        )
    else:
        outcome = _invoke_ai_provider(
            request,
            transient_input,
            provider,
            prerequisites=prerequisites,
            verifier_configuration=verifier_configuration,
            now=now,
            _expected_prerequisite_snapshots=prerequisite_check.snapshots,
        )
    write_provider_result(evidence_root, outcome.result, signing_key=signing_key, key_id=key_id)
    return outcome
