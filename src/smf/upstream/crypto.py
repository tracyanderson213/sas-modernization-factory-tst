"""Canonical digests and Ed25519 proof verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def unsigned_payload(payload: dict[str, Any]) -> bytes:
    value = dict(payload)
    value.pop("proof", None)
    return canonical_bytes(value)


def verify_proof(
    payload: dict[str, Any], *, trusted_keys: dict[str, str], allowed_key_ids: set[str]
) -> str:
    proof = payload.get("proof")
    if not isinstance(proof, dict) or set(proof) != {"algorithm", "key_id", "value"}:
        raise ValueError("Upstream evidence proof is missing or malformed")
    key_id = proof.get("key_id")
    if proof.get("algorithm") != "ed25519" or key_id not in allowed_key_ids:
        raise ValueError("Upstream evidence proof uses an untrusted authority")
    try:
        public_bytes = base64.b64decode(trusted_keys[str(key_id)], validate=True)
        signature = base64.b64decode(str(proof["value"]), validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, unsigned_payload(payload)
        )
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("Upstream evidence signature is invalid") from exc
    return str(key_id)


def sign_payload(payload: dict[str, Any], *, private_key_path: Path, key_id: str) -> None:
    if private_key_path.is_symlink() or not private_key_path.is_file():
        raise ValueError("Qualification signing key is missing or unsafe")
    try:
        key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("Qualification signing key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Qualification signing key must be Ed25519")
    payload["proof"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(unsigned_payload(payload))).decode("ascii"),
    }
