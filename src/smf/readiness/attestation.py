"""Verification of governed readiness evidence attestations."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.readiness.policy import canonical_json


def attestation_payload(evidence: dict[str, Any]) -> bytes:
    """Return the canonical bytes signed by an evidence-producing authority."""

    unsigned = dict(evidence)
    unsigned.pop("proof", None)
    return canonical_json(unsigned).encode("utf-8")


def has_valid_attestation(
    evidence: dict[str, Any],
    *,
    allowed_authorities: tuple[str, ...],
    allowed_acquisition_sources: tuple[str, ...],
    allowed_key_ids: tuple[str, ...],
    verification_keys: dict[str, str],
) -> bool:
    """Verify provenance labels and an Ed25519 proof over the complete record."""

    if (
        evidence.get("authority") not in allowed_authorities
        or evidence.get("acquisition_source") not in allowed_acquisition_sources
    ):
        return False
    proof = evidence.get("proof")
    if not isinstance(proof, dict) or proof.get("algorithm") != "ed25519":
        return False
    key_id = proof.get("key_id")
    value = proof.get("value")
    if not isinstance(key_id, str) or key_id not in allowed_key_ids:
        return False
    if not isinstance(value, str) or key_id not in verification_keys:
        return False
    try:
        public_bytes = base64.b64decode(verification_keys[key_id], validate=True)
        signature = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, attestation_payload(evidence)
        )
    except (ValueError, binascii.Error, InvalidSignature):
        return False
    return True
