"""Verification of request-bound AI submission and runtime binding evidence."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.security.ai_policy import ai_digest, canonical_ai_json
from smf.security.ai_transport_models import AITransportRequest, AITransportState
from smf.security.schema import validate_security_schema

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PROTECTED = re.compile(r"(?i)(?:\d{3}-\d{2}-\d{4}|(?:ssn|mrn|patient|secret|token)[._:-])")


def attestation_payload(evidence: dict[str, Any]) -> bytes:
    unsigned = dict(evidence)
    unsigned.pop("proof", None)
    return canonical_ai_json(unsigned)


def attestation_digest(evidence: dict[str, Any]) -> str:
    return ai_digest(evidence)


def _verify_signature(
    evidence: dict[str, Any], verification_keys: Mapping[str, Ed25519PublicKey]
) -> bool:
    proof = evidence.get("proof")
    if not isinstance(proof, dict):
        return False
    key_id = proof.get("key_id")
    if (
        set(proof) != {"algorithm", "key_id", "value"}
        or proof.get("algorithm") != "ed25519"
        or not isinstance(key_id, str)
        or key_id not in verification_keys
    ):
        return False
    try:
        signature = base64.b64decode(proof["value"], validate=True)
        verification_keys[key_id].verify(signature, attestation_payload(evidence))
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidSignature):
        return False
    return True


def _valid_time(evidence: dict[str, Any], now: datetime) -> bool:
    try:
        issued = datetime.fromisoformat(evidence["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False
    return issued.tzinfo is not None and expires.tzinfo is not None and issued <= now < expires


def verify_submission_evidence(
    evidence: dict[str, Any] | None,
    request: AITransportRequest,
    *,
    authority: str,
    verification_keys: Mapping[str, Ed25519PublicKey],
    now: datetime | None = None,
) -> tuple[AITransportState | None, str | None, str | None]:
    if evidence is None:
        return AITransportState.BLOCKED_MISSING, "submission_evidence_missing", None
    try:
        validate_security_schema("ai-submission-evidence.schema.json", evidence)
    except ValueError:
        return AITransportState.INVALID_BINDING, "submission_evidence_invalid", None
    if (
        attestation_digest(evidence) != request.submission_evidence_digest
        or evidence["evidence_id"] != request.submission_evidence_id
        or evidence["authority"] != authority
        or evidence["purpose"] != "ai-prompt-submit"
        or not _SAFE.fullmatch(evidence["decision_id"])
        or _PROTECTED.search(evidence["decision_id"])
        or evidence["bindings"] != request.evidence_bindings("submission")
        or not _valid_time(evidence, now or datetime.now(UTC))
        or not _verify_signature(evidence, verification_keys)
    ):
        return AITransportState.INVALID_BINDING, "submission_evidence_invalid", None
    if evidence["state"] == "pending":
        return AITransportState.BLOCKED_PENDING, "submission_pending", evidence["decision_id"]
    if evidence["state"] == "denied":
        return AITransportState.DENIED, "submission_denied", evidence["decision_id"]
    return None, None, evidence["decision_id"]


def verify_runtime_evidence(
    evidence: dict[str, Any] | None,
    request: AITransportRequest,
    *,
    kind: str,
    evidence_id: str,
    evidence_digest: str,
    verification_keys: Mapping[str, Ed25519PublicKey],
    now: datetime | None = None,
) -> tuple[AITransportState | None, str | None, str | None]:
    """Verify small, externally issued runtime-binding decisions.

    These documents deliberately bind the complete transport request. They cannot carry
    credential or payload material and are not accepted as submission authority.
    """

    code = f"{kind}_evidence"
    if evidence is None:
        return AITransportState.BLOCKED_MISSING, f"{code}_missing", None
    required = {
        "schema_version",
        "evidence_id",
        "kind",
        "state",
        "decision_id",
        "issued_at",
        "expires_at",
        "bindings",
        "proof",
    }
    if (
        set(evidence) != required
        or evidence.get("schema_version") != "1.0"
        or evidence.get("kind") != kind
        or evidence.get("evidence_id") != evidence_id
        or evidence.get("state") not in {"approved", "pending", "denied"}
        or evidence.get("bindings") != request.evidence_bindings(kind)
        or not isinstance(evidence.get("decision_id"), str)
        or not _SAFE.fullmatch(evidence["decision_id"])
        or _PROTECTED.search(evidence["decision_id"])
        or attestation_digest(evidence) != evidence_digest
        or not _valid_time(evidence, now or datetime.now(UTC))
        or not _verify_signature(evidence, verification_keys)
    ):
        return AITransportState.INVALID_BINDING, f"{code}_invalid", None
    if evidence["state"] == "pending":
        return AITransportState.BLOCKED_PENDING, f"{kind}_pending", evidence["decision_id"]
    if evidence["state"] == "denied":
        return AITransportState.DENIED, f"{kind}_denied", evidence["decision_id"]
    return None, None, str(evidence["decision_id"])
