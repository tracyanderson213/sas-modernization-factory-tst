"""Fail-closed, offline qualification of bounded AI context."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.readiness.manifest import load_manifest
from smf.security.ai_models import (
    AIAdmissionOutcome,
    AIAdmissionState,
    AIContextAdmissionResult,
    AIContextRequest,
    QualifiedAIContext,
)
from smf.security.ai_policy import AIContextPolicy, ai_digest, canonical_ai_json
from smf.security.schema import validate_security_schema
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_PATH_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,255}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_DOB = re.compile(r"(?i)\b(?:dob|date[_ -]?of[_ -]?birth)\s*[:=]\s*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b")
_PATIENT_ID = re.compile(
    r"(?i)\b(?:mrn|member(?:[_ -]?(?:id|number))?|patient[_ -]?id)"
    r"\s*(?::|=|\s)\s*[A-Za-z0-9-]{4,}\b"
)
_PHONE = re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)")
_SECRET = re.compile(
    r"(?i)(?<![A-Za-z0-9])secret[-_. ]*canary(?:[-_. ]|$)|"
    r"\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|authorization)\s*[:=]\s*[^\s,;]+"
)
_SAS_STEP_START = re.compile(
    r"(?im)(?:^|;)\s*(?:data\s+[A-Za-z_%][A-Za-z0-9_.%]*|proc\s+[A-Za-z][A-Za-z0-9_]*)\b[^;]*;"
)
_SAS_STEP_END = re.compile(r"(?im)(?:^|;)\s*(?:run|quit)\s*;")
_SAS_MACRO = re.compile(r"(?is)(?:^|;)\s*%macro\s+[A-Za-z_%][A-Za-z0-9_%]*\b.*?%mend\s*;")
_SAS_INCLUDE = re.compile(r"(?im)(?:^|;)\s*%include\s+[^;]+;")
_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMMENT_LINE = re.compile(r"(?m)^\s*\*[^;]*;")


def classification_payload(evidence: dict[str, Any]) -> bytes:
    unsigned = dict(evidence)
    unsigned.pop("proof", None)
    return canonical_ai_json(unsigned)


def classification_digest(evidence: dict[str, Any]) -> str:
    return ai_digest(evidence)


def _decoded_views(text: str) -> tuple[str, ...]:
    views = [text]
    decoded = text
    for _ in range(2):
        candidate = unquote(decoded)
        if candidate == decoded:
            break
        views.append(candidate)
        decoded = candidate
    for token in re.findall(r"[A-Za-z0-9+/=_-]{16,}", text):
        try:
            padded = token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4)
            candidate = base64.b64decode(padded, validate=True).decode("utf-8")
            views.append(candidate)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            continue
    return tuple(views)


def _contains_protected_data(text: str) -> bool:
    patterns = (_EMAIL, _SSN, _DOB, _PATIENT_ID, _PHONE, _SECRET)
    return any(pattern.search(view) for view in _decoded_views(text) for pattern in patterns)


def contains_protected_data(text: str) -> bool:
    """Return whether plain or simply encoded text contains protected data or secrets."""

    if _contains_protected_data(text):
        return True
    try:
        structured = json.loads(text)
    except json.JSONDecodeError:
        return bool(sanitize_discovery_value(text) != text)
    return bool(sanitize_discovery_value(structured) != structured)


def _has_meaningful_sas_entrypoint(text: str) -> bool:
    return bool(
        (_SAS_STEP_START.search(text) and _SAS_STEP_END.search(text))
        or _SAS_MACRO.search(text)
        or _SAS_INCLUDE.search(text)
    )


def sanitize_provider_diagnostic(value: object) -> str:
    """Return a bounded category only; provider text is never retained."""

    if value is None:
        return "provider_error_absent"
    text = str(value)
    if _contains_protected_data(text) or sanitize_discovery_value(text) != text:
        return "provider_error_redacted"
    return "provider_error_present"


def _safe_source_path(root: Path, logical_path: object) -> Path:
    if not isinstance(logical_path, str) or not logical_path or not logical_path.isascii():
        raise ValueError("Canonical artifact path is missing or unsafe")
    decoded = unquote(logical_path)
    candidate = Path(decoded)
    if candidate.is_absolute() or any(
        part in {"", ".", ".."} or not _SAFE_PATH_PART.fullmatch(part) for part in candidate.parts
    ):
        raise ValueError("Canonical artifact path escapes the source boundary")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError("Canonical artifact path escapes the source boundary")
    return resolved


def _state_result(
    request: AIContextRequest,
    state: AIAdmissionState,
    blockers: tuple[str, ...],
    checks: tuple[dict[str, str], ...],
    *,
    classification_decision_id: str = "unverified",
    permitted_artifacts: tuple[str, ...] = (),
    permitted_fields: tuple[str, ...] = (),
    context_digest: str | None = None,
    context_byte_count: int | None = None,
) -> AIContextAdmissionResult:
    decision_id = "ai-" + ai_digest(
        {"contract": "smf-ai-context-admission-v1", "request": request.safe_bindings()}
    )
    qualified = state is AIAdmissionState.QUALIFIED_OFFLINE
    result = AIContextAdmissionResult(
        schema_version="1.0",
        decision_id=decision_id,
        request=request.safe_bindings(),
        state=state,
        blocker_codes=blockers,
        checks=checks,
        evidence_refs=(
            request.readiness_result_id,
            request.classification_evidence_id,
            classification_decision_id,
        ),
        permitted_artifact_ids=permitted_artifacts,
        permitted_fields=permitted_fields,
        context_digest=context_digest,
        context_byte_count=context_byte_count,
        terminal_disposition="context_qualified_offline" if qualified else "context_not_qualified",
        context_qualified=qualified,
    )
    unsigned = result.to_dict()
    unsigned["content_digest"] = ""
    return AIContextAdmissionResult(**{**result.__dict__, "content_digest": ai_digest(unsigned)})


def _verify_classification(
    evidence: dict[str, Any] | None,
    request: AIContextRequest,
    policy: AIContextPolicy,
    now: datetime,
) -> tuple[AIAdmissionState | None, str, dict[str, tuple[str, str]], dict[str, str], str]:
    if evidence is None:
        return AIAdmissionState.BLOCKED_MISSING, "classification_missing", {}, {}, "unverified"
    try:
        validate_security_schema("ai-classification-evidence.schema.json", evidence)
    except ValueError:
        return AIAdmissionState.INVALID_BINDING, "classification_invalid", {}, {}, "unverified"
    if classification_digest(evidence) != request.classification_evidence_digest:
        return (
            AIAdmissionState.INVALID_BINDING,
            "classification_digest_mismatch",
            {},
            {},
            "unverified",
        )
    if evidence["evidence_id"] != request.classification_evidence_id:
        return (
            AIAdmissionState.INVALID_BINDING,
            "classification_binding_mismatch",
            {},
            {},
            "unverified",
        )
    expected = request.safe_bindings()
    expected.pop("classification_evidence_id")
    expected.pop("classification_evidence_digest")
    if evidence["bindings"] != expected:
        return (
            AIAdmissionState.INVALID_BINDING,
            "classification_binding_mismatch",
            {},
            {},
            "unverified",
        )
    if (
        evidence["authority"] != policy.classification_authority
        or evidence["purpose"] != request.decision_purpose
    ):
        return (
            AIAdmissionState.INVALID_BINDING,
            "classification_authority_invalid",
            {},
            {},
            "unverified",
        )
    try:
        issued = datetime.fromisoformat(evidence["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))
        if issued.tzinfo is None or expires.tzinfo is None or now < issued or now >= expires:
            return AIAdmissionState.INVALID_BINDING, "classification_expired", {}, {}, "unverified"
    except ValueError:
        return AIAdmissionState.INVALID_BINDING, "classification_time_invalid", {}, {}, "unverified"
    proof = evidence["proof"]
    key_id = proof["key_id"]
    if key_id not in policy.verification_keys:
        return (
            AIAdmissionState.INVALID_BINDING,
            "classification_key_untrusted",
            {},
            {},
            "unverified",
        )
    try:
        public = base64.b64decode(policy.verification_keys[key_id], validate=True)
        signature = base64.b64decode(proof["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, classification_payload(evidence)
        )
    except (TypeError, ValueError, binascii.Error, InvalidSignature):
        return (
            AIAdmissionState.INVALID_BINDING,
            "classification_signature_invalid",
            {},
            {},
            "unverified",
        )
    if evidence["state"] == "pending":
        return (
            AIAdmissionState.BLOCKED_PENDING,
            "classification_pending",
            {},
            {},
            evidence["decision_id"],
        )
    if evidence["state"] == "denied":
        return AIAdmissionState.DENIED, "classification_denied", {}, {}, evidence["decision_id"]
    artifacts = {
        item["artifact_id"]: (item["classification"], item["sha256"])
        for item in evidence["artifacts"]
    }
    fields = {item["field_id"]: item["classification"] for item in evidence["fields"]}
    if len(artifacts) != len(evidence["artifacts"]) or len(fields) != len(evidence["fields"]):
        return (
            AIAdmissionState.INVALID_BINDING,
            "classification_identity_ambiguous",
            {},
            {},
            "unverified",
        )
    return None, "classification_verified", artifacts, fields, evidence["decision_id"]


def qualify_ai_context(
    request: AIContextRequest,
    *,
    readiness_manifest: Path,
    source_root: Path,
    policy: AIContextPolicy,
    classification_evidence: dict[str, Any] | None,
    now: datetime | None = None,
) -> AIAdmissionOutcome:
    """Qualify immutable bytes for offline use. This function performs no transport."""

    blockers: list[str] = []
    if policy.status == "pending":
        blockers.append("context_policy_pending")
    elif policy.status == "denied":
        return AIAdmissionOutcome(
            _state_result(request, AIAdmissionState.DENIED, ("context_policy_denied",), ()), None
        )
    elif policy.status != "active":
        blockers.append("context_policy_invalid")
    if policy.protected_data_in_prompt_allowed:
        blockers.append("protected_data_policy_invalid")
    exact_policy = (
        request.context_policy_id == policy.policy_id
        and request.context_policy_version == policy.policy_version
        and request.context_policy_digest == policy.policy_digest
        and request.classification_policy_id == policy.classification_policy_id
        and request.classification_policy_version == policy.classification_policy_version
        and request.classification_policy_digest == policy.classification_policy_digest
        and request.retention_policy_ref == policy.retention_policy_ref
        and request.access_policy_ref == policy.access_policy_ref
    )
    if not exact_policy:
        blockers.append("policy_binding_mismatch")
    if request.provider_id not in policy.allowed_providers:
        blockers.append("provider_not_allowed")
    else:
        if request.model_id not in policy.allowed_providers[request.provider_id]:
            blockers.append("model_not_allowed")
        if request.endpoint_binding_id not in policy.endpoint_bindings[request.provider_id]:
            blockers.append("endpoint_binding_not_allowed")
    if set(request.requested_fields) - set(policy.allowed_fields):
        blockers.append("field_not_allowed")
    if blockers:
        state = (
            AIAdmissionState.BLOCKED_PENDING
            if "context_policy_pending" in blockers
            else AIAdmissionState.INVALID_BINDING
        )
        return AIAdmissionOutcome(_state_result(request, state, tuple(sorted(blockers)), ()), None)

    manifest = load_manifest(readiness_manifest)
    identity = {
        "workload_id": request.workload_id,
        "boundary_id": request.boundary_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
    }
    binding = manifest["policy_snapshot"].get("prerequisite_binding", {})
    deployment = {
        "client_id": request.client_id,
        "deployment_id": request.deployment_id,
        "environment_id": request.environment_id,
    }
    if (
        manifest["classification"] != "READY"
        or any(manifest.get(key) != value for key, value in identity.items())
        or any(binding.get(key) != value for key, value in deployment.items())
        or manifest["workload_digest"] != request.workload_digest
        or manifest["result_id"] != request.readiness_result_id
        or manifest["content_digest"] != request.readiness_manifest_digest
    ):
        return AIAdmissionOutcome(
            _state_result(
                request,
                AIAdmissionState.INVALID_BINDING,
                ("readiness_binding_invalid",),
                (),
            ),
            None,
        )

    workload = manifest["qualification_input"]["workload"]
    artifacts_raw = workload.get("artifacts", [])
    artifacts: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for artifact in artifacts_raw:
        artifact_id = artifact.get("artifact_id")
        if (
            not isinstance(artifact_id, str)
            or not _SAFE_ID.fullmatch(artifact_id)
            or artifact_id.casefold() in folded
        ):
            return AIAdmissionOutcome(
                _state_result(
                    request,
                    AIAdmissionState.INVALID_BINDING,
                    ("artifact_identity_ambiguous",),
                    (),
                ),
                None,
            )
        folded.add(artifact_id.casefold())
        artifacts[artifact_id] = artifact
    boundary_items = workload.get("boundaries", [])
    boundary_ids = [item.get("boundary_id") for item in boundary_items]
    if any(
        not isinstance(item, str) or not _SAFE_ID.fullmatch(item) for item in boundary_ids
    ) or len({item.casefold() for item in boundary_ids}) != len(boundary_ids):
        return AIAdmissionOutcome(
            _state_result(
                request, AIAdmissionState.INVALID_BINDING, ("boundary_identity_ambiguous",), ()
            ),
            None,
        )
    boundaries = [item for item in boundary_items if item.get("boundary_id") == request.boundary_id]
    if len(boundaries) != 1:
        return AIAdmissionOutcome(
            _state_result(
                request, AIAdmissionState.INVALID_BINDING, ("boundary_identity_ambiguous",), ()
            ),
            None,
        )
    closure_ids = boundaries[0].get("artifact_ids", [])
    if (
        not closure_ids
        or len(closure_ids) > 4096
        or len(closure_ids) != len(set(closure_ids))
        or set(closure_ids) != set(request.requested_artifact_ids)
        or request.subject_id not in closure_ids
        or any(item not in artifacts for item in closure_ids)
    ):
        return AIAdmissionOutcome(
            _state_result(
                request, AIAdmissionState.INVALID_BINDING, ("source_closure_incomplete",), ()
            ),
            None,
        )
    subject = artifacts[request.subject_id]
    if subject.get("kind") != "sas_program":
        return AIAdmissionOutcome(
            _state_result(
                request, AIAdmissionState.BLOCKED_AMBIGUOUS, ("subject_not_sas_program",), ()
            ),
            None,
        )

    canonical_inventory: list[dict[str, str]] = []
    source_bytes: dict[str, bytes] = {}
    total_bytes = 0
    for artifact_id in sorted(closure_ids):
        artifact = artifacts[artifact_id]
        kind = artifact.get("kind")
        if kind not in policy.allowed_artifact_kinds:
            blockers.append("artifact_kind_not_allowed")
            continue
        try:
            path = _safe_source_path(source_root, artifact.get("logical_path"))
        except ValueError:
            blockers.append("artifact_path_invalid")
            continue
        observed_size = path.stat().st_size
        if observed_size < 1 or observed_size > policy.max_context_bytes:
            blockers.append("context_limit_exceeded")
            continue
        with path.open("rb") as handle:
            raw = handle.read(policy.max_context_bytes + 1)
        total_bytes += len(raw)
        if len(raw) != observed_size:
            blockers.append("artifact_digest_mismatch")
            continue
        if len(raw) > policy.max_context_bytes or total_bytes > policy.max_context_bytes:
            blockers.append("context_limit_exceeded")
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if artifact.get("checksum") != digest:
            blockers.append("artifact_digest_mismatch")
            continue
        safe_metadata = {
            "artifact_id": artifact_id,
            "kind": str(kind),
            "logical_path": str(artifact.get("logical_path")),
        }
        metadata_text = json.dumps(safe_metadata, sort_keys=True)
        if (
            _contains_protected_data(metadata_text)
            or sanitize_discovery_value(metadata_text) != metadata_text
        ):
            blockers.append("artifact_metadata_protected")
            continue
        canonical_inventory.append({**safe_metadata, "sha256": digest})
        source_bytes[artifact_id] = raw
    if blockers:
        return AIAdmissionOutcome(
            _state_result(
                request,
                AIAdmissionState.BLOCKED_AMBIGUOUS,
                tuple(sorted(set(blockers))),
                (),
            ),
            None,
        )
    if ai_digest(canonical_inventory) != request.source_closure_digest:
        return AIAdmissionOutcome(
            _state_result(
                request, AIAdmissionState.INVALID_BINDING, ("source_closure_digest_mismatch",), ()
            ),
            None,
        )

    classification_state, code, classified_artifacts, classified_fields, classification_id = (
        _verify_classification(classification_evidence, request, policy, now or datetime.now(UTC))
    )
    if classification_state is not None:
        return AIAdmissionOutcome(_state_result(request, classification_state, (code,), ()), None)
    if set(classified_artifacts) != set(closure_ids) or set(classified_fields) != set(
        request.requested_fields
    ):
        return AIAdmissionOutcome(
            _state_result(
                request,
                AIAdmissionState.INVALID_BINDING,
                ("classification_inventory_incomplete",),
                (),
                classification_decision_id=classification_id,
            ),
            None,
        )
    inventory_digests = {item["artifact_id"]: item["sha256"] for item in canonical_inventory}
    if any(
        inventory_digests.get(artifact_id) != classified_digest
        for artifact_id, (_, classified_digest) in classified_artifacts.items()
    ):
        return AIAdmissionOutcome(
            _state_result(
                request,
                AIAdmissionState.INVALID_BINDING,
                ("classification_artifact_digest_mismatch",),
                (),
                classification_decision_id=classification_id,
            ),
            None,
        )
    if any(
        classification != "non_protected" for classification, _ in classified_artifacts.values()
    ) or any(value != "permitted" for value in classified_fields.values()):
        return AIAdmissionOutcome(
            _state_result(
                request,
                AIAdmissionState.DENIED,
                ("classification_not_permitted",),
                (),
                classification_decision_id=classification_id,
            ),
            None,
        )

    segments: list[bytes] = []
    for artifact_id in sorted(source_bytes):
        raw = source_bytes[artifact_id]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            blockers.append("artifact_encoding_ambiguous")
            continue
        if any(ord(character) < 32 and character not in "\n\r\t" for character in text):
            blockers.append("artifact_encoding_ambiguous")
            continue
        if _contains_protected_data(text) or sanitize_discovery_value(text) != text:
            blockers.append("protected_data_detected")
            continue
        if artifact_id == request.subject_id:
            meaningful = _COMMENT_LINE.sub("", _COMMENT_BLOCK.sub("", text)).strip()
            if not meaningful or not _has_meaningful_sas_entrypoint(meaningful):
                blockers.append("subject_not_meaningful")
                continue
        segments.append(f"-- artifact:{artifact_id}\n".encode() + raw + b"\n")
    if blockers:
        return AIAdmissionOutcome(
            _state_result(
                request,
                AIAdmissionState.BLOCKED_AMBIGUOUS,
                tuple(sorted(set(blockers))),
                (),
                classification_decision_id=classification_id,
            ),
            None,
        )
    assembled = b"".join(segments)
    if not assembled or len(assembled) > policy.max_context_bytes:
        code = "context_empty" if not assembled else "context_limit_exceeded"
        return AIAdmissionOutcome(
            _state_result(
                request,
                AIAdmissionState.BLOCKED_AMBIGUOUS,
                (code,),
                (),
                classification_decision_id=classification_id,
            ),
            None,
        )
    digest = hashlib.sha256(assembled).hexdigest()
    checks = (
        {"check_id": "readiness_replayed", "status": "pass"},
        {"check_id": "classification_verified", "status": "pass"},
        {"check_id": "source_bytes_reverified", "status": "pass"},
        {"check_id": "protected_data_scan", "status": "pass"},
        {"check_id": "allowlist_intersection", "status": "pass"},
    )
    result = _state_result(
        request,
        AIAdmissionState.QUALIFIED_OFFLINE,
        (),
        checks,
        classification_decision_id=classification_id,
        permitted_artifacts=tuple(sorted(source_bytes)),
        permitted_fields=tuple(sorted(request.requested_fields)),
        context_digest=digest,
        context_byte_count=len(assembled),
    )
    context = QualifiedAIContext(bytearray(assembled), result.decision_id, digest)
    return AIAdmissionOutcome(result, context)
