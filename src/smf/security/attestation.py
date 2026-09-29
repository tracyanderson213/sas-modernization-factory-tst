"""Verification of attempt-bound activation evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.security.configuration import SecurityConfiguration, canonical_json
from smf.security.models import ReasonCode, ResolutionState, SecretResolutionRequest

_BOUND_FIELDS = (
    "client_id",
    "deployment_id",
    "environment_id",
    "workload_id",
    "workload_digest",
    "boundary_id",
    "subject_id",
    "source_sha256",
    "run_id",
    "attempt_id",
    "consumer_id",
    "consumer_contract_version",
    "identity_binding_id",
    "secret_binding_id",
    "security_policy_id",
    "security_policy_version",
    "security_policy_digest",
    "configuration_digest",
    "readiness_result_id",
    "readiness_manifest_digest",
    "qualified_snapshot_ref",
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACTIVATION_FIELDS = {
    *_BOUND_FIELDS,
    "evidence_id",
    "state",
    "authority",
    "purpose",
    "decision_id",
    "owner_assignment_ref",
    "issued_at",
    "expires_at",
    "proof",
}


def activation_payload(evidence: dict[str, Any]) -> bytes:
    unsigned = dict(evidence)
    unsigned.pop("proof", None)
    return canonical_json(unsigned)


def activation_digest(evidence: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(evidence)).hexdigest()


def verify_activation(
    evidence: dict[str, Any] | None,
    request: SecretResolutionRequest,
    config: SecurityConfiguration,
    *,
    purpose: str,
    now: datetime | None = None,
) -> tuple[ResolutionState | None, ReasonCode | None, str | None]:
    if evidence is None:
        return ResolutionState.BLOCKED_MISSING, ReasonCode.APPROVAL_MISSING, None
    if set(evidence) != _ACTIVATION_FIELDS:
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    if activation_digest(evidence) != request.activation_evidence_digest:
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    if evidence.get("evidence_id") != request.activation_evidence_id:
        return ResolutionState.INVALID_BINDING, ReasonCode.BINDING_MISMATCH, None
    state = evidence.get("state")
    if state not in {"approved", "pending", "denied"}:
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    if evidence.get("authority") != config.authority or evidence.get("purpose") != purpose:
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    if any(evidence.get(field) != getattr(request, field) for field in _BOUND_FIELDS):
        return ResolutionState.INVALID_BINDING, ReasonCode.BINDING_MISMATCH, None
    for required in ("decision_id", "owner_assignment_ref", "issued_at", "expires_at"):
        if not isinstance(evidence.get(required), str) or not evidence[required]:
            return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    if not _SAFE_ID.fullmatch(evidence["decision_id"]) or not _SAFE_ID.fullmatch(
        evidence["owner_assignment_ref"]
    ):
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    try:
        issued = datetime.fromisoformat(evidence["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))
        current = now or datetime.now(UTC)
        if (
            issued.tzinfo is None
            or expires.tzinfo is None
            or current < issued
            or current >= expires
        ):
            return ResolutionState.EXPIRED, ReasonCode.APPROVAL_EXPIRED, None
    except ValueError:
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    proof = evidence.get("proof")
    if not isinstance(proof, dict) or set(proof) != {"algorithm", "key_id", "value"}:
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    key_id = proof.get("key_id")
    if (
        proof.get("algorithm") != "ed25519"
        or not isinstance(key_id, str)
        or key_id not in config.verification_keys
    ):
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    try:
        public = base64.b64decode(config.verification_keys[key_id], validate=True)
        signature = base64.b64decode(proof["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, activation_payload(evidence))
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidSignature):
        return ResolutionState.INVALID_BINDING, ReasonCode.ACTIVATION_INVALID, None
    if state == "pending":
        return ResolutionState.BLOCKED_PENDING, ReasonCode.APPROVAL_PENDING, None
    if state == "denied":
        return ResolutionState.DENIED, ReasonCode.APPROVAL_DENIED, None
    return None, None, str(evidence["decision_id"])
