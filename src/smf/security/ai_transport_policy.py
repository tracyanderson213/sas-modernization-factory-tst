"""Trusted portable policy and protected endpoint-binding loaders."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.security.ai_policy import ai_digest, canonical_ai_json
from smf.security.schema import validate_security_schema

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PROTECTED = re.compile(r"(?i)(?:\d{3}-\d{2}-\d{4}|(?:ssn|mrn|patient|secret|token)[._:-])")


@dataclass(frozen=True)
class AITransportPolicy:
    policy_id: str
    policy_version: str
    policy_digest: str
    status: str
    providers: MappingProxyType[str, MappingProxyType[str, tuple[str, ...]]]
    max_payload_bytes: int
    max_response_bytes: int
    max_retries: int
    submission_authority: str
    snapshot: bytes


@dataclass(frozen=True)
class AIEndpointBinding:
    binding_id: str
    binding_digest: str
    status: str
    deployment_id: str
    environment_id: str
    provider_id: str
    model_id: str
    identity_binding_id: str
    secret_binding_id: str
    tls_profile_ref: str
    url: str
    evidence_ref: str
    snapshot: bytes


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid AI transport configuration") from exc
    if not isinstance(value, dict):
        raise ValueError("AI transport configuration must be an object")
    return value, bytes(raw)


def _verify_document(
    payload: dict[str, Any], keys: Mapping[str, Ed25519PublicKey], *, digest_field: str
) -> None:
    proof = payload.get("proof")
    if not isinstance(proof, dict) or set(proof) != {"algorithm", "key_id", "value"}:
        raise ValueError("AI transport configuration lacks trusted proof")
    key_id = proof.get("key_id")
    if proof.get("algorithm") != "ed25519" or not isinstance(key_id, str) or key_id not in keys:
        raise ValueError("AI transport configuration proof is untrusted")
    unsigned = dict(payload)
    unsigned.pop("proof")
    supplied = unsigned.pop(digest_field)
    if supplied != ai_digest(unsigned):
        raise ValueError("AI transport configuration digest mismatch")
    signed = dict(payload)
    signed.pop("proof")
    try:
        signature = base64.b64decode(proof["value"], validate=True)
        keys[key_id].verify(signature, canonical_ai_json(signed))
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("AI transport configuration proof is invalid") from exc


def load_ai_transport_policy(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> AITransportPolicy:
    payload, snapshot = _load_json(path)
    validate_security_schema("ai-transport-policy.schema.json", payload)
    _verify_document(payload, verification_keys, digest_field="policy_digest")
    for field in ("policy_id", "policy_version", "submission_authority"):
        if not _SAFE.fullmatch(payload[field]) or _PROTECTED.search(payload[field]):
            raise ValueError(f"Unsafe AI transport policy {field}")
    providers: dict[str, MappingProxyType[str, tuple[str, ...]]] = {}
    folded: set[str] = set()
    for item in payload["providers"]:
        provider_id = item["provider_id"]
        if (
            not _SAFE.fullmatch(provider_id)
            or _PROTECTED.search(provider_id)
            or provider_id.casefold() in folded
        ):
            raise ValueError("Duplicate or case-ambiguous provider")
        folded.add(provider_id.casefold())
        models = tuple(item["model_ids"])
        bindings = tuple(item["endpoint_binding_ids"])
        if (
            any(not _SAFE.fullmatch(value) or _PROTECTED.search(value) for value in models)
            or any(not _SAFE.fullmatch(value) or _PROTECTED.search(value) for value in bindings)
            or len({value.casefold() for value in models}) != len(models)
            or len({value.casefold() for value in bindings}) != len(bindings)
        ):
            raise ValueError("Duplicate or case-ambiguous transport allowlist")
        providers[provider_id] = MappingProxyType({"models": models, "bindings": bindings})
    return AITransportPolicy(
        policy_id=payload["policy_id"],
        policy_version=payload["policy_version"],
        policy_digest=payload["policy_digest"],
        status=payload["status"],
        providers=MappingProxyType(providers),
        max_payload_bytes=payload["max_payload_bytes"],
        max_response_bytes=payload["max_response_bytes"],
        max_retries=payload["max_retries"],
        submission_authority=payload["submission_authority"],
        snapshot=snapshot,
    )


def _canonical_https_url(value: str) -> str:
    if not value.isascii() or unquote(value) != value or any(char.isspace() for char in value):
        raise ValueError("Endpoint URL is not canonical ASCII")
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port is not None
        or hostname != hostname.lower()
        or hostname.endswith(".")
        or not parsed.path.startswith("/")
        or "//" in parsed.path
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise ValueError("Endpoint URL is not an approved canonical HTTPS destination")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Endpoint URL cannot use an IP literal")
    return value


def load_ai_endpoint_binding(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> AIEndpointBinding:
    payload, snapshot = _load_json(path)
    validate_security_schema("ai-endpoint-binding.schema.json", payload)
    _verify_document(payload, verification_keys, digest_field="binding_digest")
    for field in (
        "binding_id",
        "deployment_id",
        "environment_id",
        "provider_id",
        "model_id",
        "identity_binding_id",
        "secret_binding_id",
        "tls_profile_ref",
    ):
        if not _SAFE.fullmatch(payload[field]) or _PROTECTED.search(payload[field]):
            raise ValueError(f"Unsafe endpoint binding {field}")
    return AIEndpointBinding(
        binding_id=payload["binding_id"],
        binding_digest=payload["binding_digest"],
        status=payload["status"],
        deployment_id=payload["deployment_id"],
        environment_id=payload["environment_id"],
        provider_id=payload["provider_id"],
        model_id=payload["model_id"],
        identity_binding_id=payload["identity_binding_id"],
        secret_binding_id=payload["secret_binding_id"],
        tls_profile_ref=payload["tls_profile_ref"],
        url=_canonical_https_url(payload["url"]),
        evidence_ref=payload["evidence_ref"],
        snapshot=snapshot,
    )
