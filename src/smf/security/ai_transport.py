"""Mandatory egress guard for every governed AI request and retry."""

from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import time
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from smf.security.ai_admission import contains_protected_data
from smf.security.ai_manifest import load_ai_context_result
from smf.security.ai_models import QualifiedAIContext
from smf.security.ai_transport_attestation import (
    verify_runtime_evidence,
    verify_submission_evidence,
)
from smf.security.ai_transport_manifest import (
    load_dispatch_marker,
    load_transport_preparation,
    load_transport_result,
    recover_transport_telemetry,
    transport_decision_id,
    transport_evidence_dir,
    write_dispatch_marker,
    write_transport_preparation,
    write_transport_result,
)
from smf.security.ai_transport_models import (
    AITransportCancelled,
    AITransportRequest,
    AITransportResponse,
    AITransportResult,
    AITransportState,
    TransientAIBytes,
)
from smf.security.ai_transport_policy import (
    AIEndpointBinding,
    AITransportPolicy,
    load_ai_endpoint_binding,
    load_ai_transport_policy,
)


def _send_https_once(
    *,
    url: str,
    method: str,
    payload: bytes,
    media_type: str,
    credential: bytes,
    max_response_bytes: int,
) -> AITransportResponse:
    """Perform one HTTPS exchange to the already verified endpoint.

    This concrete boundary deliberately has no redirect or fallback loop.  A 3xx
    response is returned to the guard and its Location header is never resolved.
    """

    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname is None or parsed.port is not None:
        raise ValueError("Transport received a non-canonical HTTPS endpoint")
    try:
        token = credential.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Credential is not an opaque ASCII transport token") from exc
    if not token or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token):
        raise ValueError("Credential is not a safe opaque transport token")
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        port=443,
        timeout=30,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            method,
            parsed.path,
            body=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": media_type,
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        body = response.read(max_response_bytes + 1)
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        return AITransportResponse(
            status_code=response.status,
            body=body,
            media_type=content_type,
        )
    finally:
        connection.close()


def _result(
    request: AITransportRequest,
    state: AITransportState,
    blockers: tuple[str, ...],
    evidence_refs: tuple[str, ...],
    *,
    elapsed_ms: int = 0,
    authorized: bool = False,
    attempted: bool = False,
    response_status: int | None = None,
    response_digest: str | None = None,
    response_byte_count: int | None = None,
    context_qualified: bool = False,
) -> AITransportResult:
    return AITransportResult(
        schema_version="1.0",
        decision_id=transport_decision_id(request),
        request=request.bindings(),
        state=state,
        blocker_codes=blockers,
        evidence_refs=evidence_refs,
        response_status=response_status,
        response_digest=response_digest,
        response_byte_count=response_byte_count,
        elapsed_ms=max(0, elapsed_ms),
        context_qualified=context_qualified,
        submission_authorized=authorized,
        transport_attempted=attempted,
        response_received=state is AITransportState.RESPONSE_RECEIVED,
    )


def _persist(
    evidence_root: Path,
    result: AITransportResult,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> AITransportResult:
    write_transport_result(evidence_root, result, signing_key=signing_key, key_id=key_id)
    return result


def _loaded_result(payload: dict[str, Any]) -> AITransportResult:
    value = dict(payload)
    value.pop("proof")
    value["state"] = AITransportState(value["state"])
    for name in ("blocker_codes", "evidence_refs"):
        value[name] = tuple(value[name])
    return AITransportResult(**value)


def _policy_bindings_valid(
    request: AITransportRequest, policy: AITransportPolicy, binding: AIEndpointBinding
) -> tuple[str, ...]:
    blockers: list[str] = []
    if policy.status == "pending" or binding.status == "pending":
        blockers.append("transport_configuration_pending")
    elif policy.status == "denied" or binding.status == "denied":
        blockers.append("transport_configuration_denied")
    elif policy.status != "active" or binding.status != "active":
        blockers.append("transport_configuration_invalid")
    exact_policy = (
        request.transport_policy_id == policy.policy_id
        and request.transport_policy_version == policy.policy_version
        and request.transport_policy_digest == policy.policy_digest
    )
    if not exact_policy:
        blockers.append("transport_policy_binding_mismatch")
    allowed = policy.providers.get(request.provider_id)
    if (
        allowed is None
        or request.model_id not in allowed["models"]
        or request.endpoint_binding_id not in allowed["bindings"]
    ):
        blockers.append("transport_destination_not_allowed")
    if (
        request.endpoint_binding_id != binding.binding_id
        or request.endpoint_binding_digest != binding.binding_digest
        or request.endpoint_binding_ref != binding.evidence_ref
        or request.deployment_id != binding.deployment_id
        or request.environment_id != binding.environment_id
        or request.provider_id != binding.provider_id
        or request.model_id != binding.model_id
        or request.identity_binding_id != binding.identity_binding_id
        or request.credential_resolution_id != binding.secret_binding_id
        or request.retry_ordinal > policy.max_retries
    ):
        blockers.append("endpoint_binding_mismatch")
    if request.payload_byte_count > policy.max_payload_bytes:
        blockers.append("payload_limit_exceeded")
    return tuple(sorted(set(blockers)))


def _sec02_valid(
    request: AITransportRequest,
    context: QualifiedAIContext,
    result: dict[str, Any],
) -> bool:
    binding = result["request"]
    return bool(
        result["state"] == "qualified_offline"
        and result["context_qualified"] is True
        and result["decision_id"] == request.sec02_decision_id == context.decision_id
        and result["content_digest"] == request.sec02_result_digest
        and result["context_digest"] == request.context_digest == context.digest
        and result["context_byte_count"] == request.context_byte_count == len(context.value)
        and hashlib.sha256(context.value).hexdigest() == request.context_digest
        and binding["client_id"] == request.client_id
        and binding["deployment_id"] == request.deployment_id
        and binding["environment_id"] == request.environment_id
        and binding["workload_id"] == request.workload_id
        and binding["workload_digest"] == request.workload_digest
        and binding["boundary_id"] == request.boundary_id
        and binding["subject_id"] == request.subject_id
        and binding["source_closure_digest"] == request.source_closure_digest
        and binding["run_id"] == request.run_id
        and binding["attempt_id"] == request.workflow_attempt_id
        and binding["provider_id"] == request.provider_id
        and binding["model_id"] == request.model_id
        and binding["endpoint_binding_id"] == request.endpoint_binding_id
        and result["permitted_artifact_ids"] == list(request.permitted_artifact_ids)
        and binding["readiness_result_id"] == request.readiness_result_id
        and binding["readiness_manifest_digest"] == request.readiness_manifest_digest
        and binding["classification_evidence_id"] == request.classification_evidence_id
        and result["evidence_refs"][2] == request.classification_decision_id
    )


def _guarded_ai_transport(
    request: AITransportRequest,
    *,
    payload: TransientAIBytes,
    context: QualifiedAIContext,
    credential: TransientAIBytes,
    transport_policy_path: Path,
    endpoint_binding_path: Path,
    sec02_result_path: Path,
    submission_evidence: dict[str, Any] | None,
    identity_evidence: dict[str, Any] | None,
    credential_evidence: dict[str, Any] | None,
    payload_classification_evidence: dict[str, Any] | None,
    configuration_keys: Mapping[str, Ed25519PublicKey],
    sec02_keys: Mapping[str, Ed25519PublicKey],
    identity_keys: Mapping[str, Ed25519PublicKey],
    credential_keys: Mapping[str, Ed25519PublicKey],
    payload_classification_keys: Mapping[str, Ed25519PublicKey],
    submission_keys: Mapping[str, Ed25519PublicKey],
    evidence_keys: Mapping[str, Ed25519PublicKey],
    evidence_root: Path,
    evidence_signing_key: Ed25519PrivateKey,
    evidence_key_id: str,
    now: datetime | None = None,
) -> AITransportResult:
    """Validate, evidence and dispatch exactly one redirect-disabled request."""

    evidence_dir = transport_evidence_dir(evidence_root, request)
    result_path = evidence_dir / "result.json"
    dispatch_path = evidence_dir / "dispatch.json"
    if result_path.exists():
        try:
            existing = load_transport_result(result_path, verification_keys=evidence_keys)
            if existing["request"] != request.bindings():
                expected = dict(request.bindings())
                expected["payload_digest"] = existing["request"]["payload_digest"]
                protected_retry = (
                    existing["blocker_codes"] == ["protected_data_detected"]
                    and existing["request"] == expected
                )
                if not protected_retry:
                    raise ValueError("Transport attempt identity was reused for another request")
            recover_transport_telemetry(result_path, verification_keys=evidence_keys)
            return _loaded_result(existing)
        finally:
            payload.clear()
            credential.clear()
            context.clear()
    if dispatch_path.exists():
        try:
            load_dispatch_marker(dispatch_path, request, verification_keys=evidence_keys)
            preparation = load_transport_preparation(
                evidence_dir / "preparation.json", verification_keys=evidence_keys
            )
        except ValueError:
            invalid = _result(
                request,
                AITransportState.INVALID_BINDING,
                ("dispatch_evidence_invalid",),
                (),
            )
            payload.clear()
            credential.clear()
            context.clear()
            return _persist(evidence_root, invalid, evidence_signing_key, evidence_key_id)
        unknown = _result(
            request,
            AITransportState.OUTCOME_UNKNOWN,
            ("prior_dispatch_outcome_unknown",),
            tuple(preparation["evidence_refs"]),
            authorized=True,
            attempted=True,
            context_qualified=True,
        )
        payload.clear()
        credential.clear()
        context.clear()
        # A dispatch marker may belong to an active concurrent claimant.  Returning
        # an explicit unknown state is safe; publishing it would race and overwrite
        # the claimant's eventual canonical terminal result.
        return unknown

    refs: list[str] = [request.sec02_result_ref, request.endpoint_binding_ref]
    try:
        policy = load_ai_transport_policy(
            transport_policy_path, verification_keys=configuration_keys
        )
        endpoint = load_ai_endpoint_binding(
            endpoint_binding_path, verification_keys=configuration_keys
        )
        sec02 = load_ai_context_result(sec02_result_path, verification_keys=sec02_keys)
    except (OSError, ValueError):
        result = _result(
            request,
            AITransportState.BLOCKED_MISSING,
            ("trusted_prerequisite_unavailable",),
            tuple(refs),
        )
        payload.clear()
        credential.clear()
        context.clear()
        return _persist(evidence_root, result, evidence_signing_key, evidence_key_id)

    blockers = _policy_bindings_valid(request, policy, endpoint)
    if blockers:
        if "transport_configuration_pending" in blockers:
            state = AITransportState.BLOCKED_PENDING
        elif "transport_configuration_denied" in blockers:
            state = AITransportState.DENIED
        else:
            state = AITransportState.INVALID_BINDING
        result = _result(request, state, blockers, tuple(refs))
        payload.clear()
        credential.clear()
        context.clear()
        return _persist(evidence_root, result, evidence_signing_key, evidence_key_id)

    if not _sec02_valid(request, context, sec02):
        result = _result(
            request,
            AITransportState.INVALID_BINDING,
            ("sec02_binding_invalid",),
            tuple(refs),
        )
        payload.clear()
        credential.clear()
        context.clear()
        return _persist(evidence_root, result, evidence_signing_key, evidence_key_id)

    payload_value = payload.value
    try:
        payload_text = payload_value.decode("utf-8")
        parsed = json.loads(payload_text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = None
        payload_text = ""
    if (
        parsed is None
        or not isinstance(parsed, dict)
        or not parsed
        or len(payload_value) != request.payload_byte_count
        or hashlib.sha256(payload_value).hexdigest() != request.payload_digest
        or contains_protected_data(payload_text)
    ):
        code = (
            "protected_data_detected"
            if contains_protected_data(payload_text)
            else "payload_invalid"
        )
        evidence_request = request
        if code == "protected_data_detected":
            evidence_request = replace(
                request,
                payload_digest=hashlib.sha256(b"protected-payload-withheld").hexdigest(),
            )
        result = _result(
            evidence_request,
            AITransportState.DENIED,
            (code,),
            tuple(refs),
            context_qualified=True,
        )
        payload.clear()
        credential.clear()
        context.clear()
        return _persist(evidence_root, result, evidence_signing_key, evidence_key_id)

    current = now or datetime.now(UTC)
    attestations = (
        verify_runtime_evidence(
            identity_evidence,
            request,
            kind="identity_binding",
            evidence_id=request.identity_evidence_id,
            evidence_digest=request.identity_evidence_digest,
            verification_keys=identity_keys,
            now=current,
        ),
        verify_runtime_evidence(
            credential_evidence,
            request,
            kind="credential_resolution",
            evidence_id=request.credential_evidence_id,
            evidence_digest=request.credential_evidence_digest,
            verification_keys=credential_keys,
            now=current,
        ),
        verify_runtime_evidence(
            payload_classification_evidence,
            request,
            kind="payload_classification",
            evidence_id=request.payload_classification_evidence_id,
            evidence_digest=request.payload_classification_evidence_digest,
            verification_keys=payload_classification_keys,
            now=current,
        ),
        verify_submission_evidence(
            submission_evidence,
            request,
            authority=policy.submission_authority,
            verification_keys=submission_keys,
            now=current,
        ),
    )
    for attestation_state, attestation_code, decision_id in attestations:
        if decision_id:
            refs.append(decision_id)
        if attestation_state is not None:
            result = _result(
                request,
                attestation_state,
                (str(attestation_code),),
                tuple(refs),
                context_qualified=True,
            )
            payload.clear()
            credential.clear()
            context.clear()
            return _persist(evidence_root, result, evidence_signing_key, evidence_key_id)

    write_transport_preparation(
        evidence_root,
        request,
        tuple(refs),
        signing_key=evidence_signing_key,
        key_id=evidence_key_id,
    )

    # Re-read both protected snapshots at the last possible point. A policy or endpoint
    # mutation after qualification cannot change the destination or permission set.
    try:
        current_policy = load_ai_transport_policy(
            transport_policy_path, verification_keys=configuration_keys
        )
        current_endpoint = load_ai_endpoint_binding(
            endpoint_binding_path, verification_keys=configuration_keys
        )
    except (OSError, ValueError):
        current_policy = None
        current_endpoint = None
    if (
        current_policy is None
        or current_endpoint is None
        or current_policy.snapshot != policy.snapshot
        or current_endpoint.snapshot != endpoint.snapshot
    ):
        result = _result(
            request,
            AITransportState.INVALID_BINDING,
            ("configuration_changed_before_dispatch",),
            tuple(refs),
            authorized=True,
            context_qualified=True,
        )
        payload.clear()
        credential.clear()
        context.clear()
        return _persist(evidence_root, result, evidence_signing_key, evidence_key_id)

    _, dispatch_claimed = write_dispatch_marker(
        evidence_root,
        request,
        signing_key=evidence_signing_key,
        key_id=evidence_key_id,
    )
    if not dispatch_claimed:
        # Another worker atomically claimed this exact attempt.  It alone may send
        # and publish the canonical terminal result; this invocation never races it.
        if result_path.exists():
            existing = load_transport_result(result_path, verification_keys=evidence_keys)
            recover_transport_telemetry(result_path, verification_keys=evidence_keys)
            payload.clear()
            credential.clear()
            context.clear()
            return _loaded_result(existing)
        payload.clear()
        credential.clear()
        context.clear()
        return _result(
            request,
            AITransportState.OUTCOME_UNKNOWN,
            ("dispatch_in_progress_or_outcome_unknown",),
            tuple(refs),
            authorized=True,
            attempted=True,
            context_qualified=True,
        )
    started = time.monotonic_ns()
    response: AITransportResponse | None = None
    try:
        response = _send_https_once(
            url=endpoint.url,
            method=request.method,
            payload=payload_value,
            media_type=request.media_type,
            credential=credential.value,
            max_response_bytes=policy.max_response_bytes,
        )
        elapsed = (time.monotonic_ns() - started) // 1_000_000
        try:
            response_text = response.body.decode("utf-8")
            response_payload = json.loads(response_text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            response_text = ""
            response_payload = None
        if 300 <= response.status_code <= 399:
            result = _result(
                request,
                AITransportState.REDIRECT_REJECTED,
                ("redirect_rejected",),
                tuple(refs),
                elapsed_ms=elapsed,
                authorized=True,
                attempted=True,
                response_status=response.status_code,
                context_qualified=True,
            )
        elif (
            response.status_code < 200
            or response.status_code >= 300
            or response.media_type != "application/json"
            or not response.body
            or len(response.body) > policy.max_response_bytes
            or not isinstance(response_payload, dict)
            or not response_payload
            or contains_protected_data(response_text)
        ):
            result = _result(
                request,
                AITransportState.TRANSPORT_FAILED,
                ("provider_response_rejected",),
                tuple(refs),
                elapsed_ms=elapsed,
                authorized=True,
                attempted=True,
                response_status=response.status_code,
                context_qualified=True,
            )
        else:
            result = _result(
                request,
                AITransportState.RESPONSE_RECEIVED,
                (),
                tuple(refs),
                elapsed_ms=elapsed,
                authorized=True,
                attempted=True,
                response_status=response.status_code,
                response_digest=hashlib.sha256(response.body).hexdigest(),
                response_byte_count=len(response.body),
                context_qualified=True,
            )
    except AITransportCancelled:
        result = _result(
            request,
            AITransportState.CANCELLED,
            ("transport_cancelled",),
            tuple(refs),
            elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
            authorized=True,
            attempted=True,
            context_qualified=True,
        )
    except TimeoutError:
        result = _result(
            request,
            AITransportState.TIMED_OUT,
            ("transport_timed_out",),
            tuple(refs),
            elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
            authorized=True,
            attempted=True,
            context_qualified=True,
        )
    except Exception:
        result = _result(
            request,
            AITransportState.TRANSPORT_FAILED,
            ("transport_error",),
            tuple(refs),
            elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
            authorized=True,
            attempted=True,
            context_qualified=True,
        )
    finally:
        payload.clear()
        credential.clear()
        context.clear()
    return _persist(evidence_root, result, evidence_signing_key, evidence_key_id)


def guarded_ai_transport(
    request: AITransportRequest,
    *,
    payload: TransientAIBytes,
    context: QualifiedAIContext,
    credential: TransientAIBytes,
    transport_policy_path: Path,
    endpoint_binding_path: Path,
    sec02_result_path: Path,
    submission_evidence: dict[str, Any] | None,
    identity_evidence: dict[str, Any] | None,
    credential_evidence: dict[str, Any] | None,
    payload_classification_evidence: dict[str, Any] | None,
    configuration_keys: Mapping[str, Ed25519PublicKey],
    sec02_keys: Mapping[str, Ed25519PublicKey],
    identity_keys: Mapping[str, Ed25519PublicKey],
    credential_keys: Mapping[str, Ed25519PublicKey],
    payload_classification_keys: Mapping[str, Ed25519PublicKey],
    submission_keys: Mapping[str, Ed25519PublicKey],
    evidence_keys: Mapping[str, Ed25519PublicKey],
    evidence_root: Path,
    evidence_signing_key: Ed25519PrivateKey,
    evidence_key_id: str,
    now: datetime | None = None,
) -> AITransportResult:
    """Run the egress guard and clear every transient buffer on every exit path."""

    try:
        return _guarded_ai_transport(
            request,
            payload=payload,
            context=context,
            credential=credential,
            transport_policy_path=transport_policy_path,
            endpoint_binding_path=endpoint_binding_path,
            sec02_result_path=sec02_result_path,
            submission_evidence=submission_evidence,
            identity_evidence=identity_evidence,
            credential_evidence=credential_evidence,
            payload_classification_evidence=payload_classification_evidence,
            configuration_keys=configuration_keys,
            sec02_keys=sec02_keys,
            identity_keys=identity_keys,
            credential_keys=credential_keys,
            payload_classification_keys=payload_classification_keys,
            submission_keys=submission_keys,
            evidence_keys=evidence_keys,
            evidence_root=evidence_root,
            evidence_signing_key=evidence_signing_key,
            evidence_key_id=evidence_key_id,
            now=now,
        )
    finally:
        payload.clear()
        credential.clear()
        context.clear()
