"""Strict loading of portable policy and protected provider bindings."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

from smf.security.models import BindingStatus

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class _UniqueLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueLoader, node: yaml.Node, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate configuration key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True)
class IdentityBinding:
    binding_id: str
    tenant: str
    issuer: str
    audience: str
    authentication_flow: str


@dataclass(frozen=True)
class SecretBinding:
    binding_id: str
    namespace: str
    auth_mount: str
    role: str
    engine: str
    path: str
    version: str
    previous_version: str | None


@dataclass(frozen=True)
class SecurityConfiguration:
    policy_id: str
    policy_version: str
    policy_digest: str
    configuration_digest: str
    status: BindingStatus
    endpoint: str
    tls_profile_ref: str
    authority: str
    verification_keys: Mapping[str, str]
    min_lease_seconds: int
    identity_bindings: Mapping[str, IdentityBinding]
    secret_bindings: Mapping[str, SecretBinding]
    snapshot_bytes: bytes


def _load(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Invalid security configuration") from exc
    if not isinstance(value, dict):
        raise ValueError("Security configuration must be an object")
    return value, raw


def _keys(value: dict[str, Any], allowed: set[str], required: set[str], label: str) -> None:
    if set(value) - allowed or not required.issubset(value):
        raise ValueError(f"{label} contains unknown or missing fields")


def _safe(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE.fullmatch(value):
        raise ValueError(f"{label} must be a safe identifier")
    return value


def _scope(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or value.startswith(("/", "\\"))
    ):
        raise ValueError(f"Unsafe {label}")
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    else:
        raise ValueError(f"Unsafe {label}")
    parts = re.split(r"[/\\]", decoded)
    if any(not _SAFE.fullmatch(part) or part in {".", ".."} for part in parts):
        raise ValueError(f"Unsafe {label}")
    return value


def _https_url(value: object, label: str, *, origin_only: bool = False) -> str:
    parsed = urlparse(value) if isinstance(value, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (origin_only and parsed.path not in {"", "/"})
    ):
        expected = "origin" if origin_only else "URL"
        raise ValueError(f"{label} must be an HTTPS {expected}")
    assert isinstance(value, str)
    return value


def _audience(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise ValueError("audience must be a non-empty bounded value")
    return value


def load_security_configuration(policy_path: Path, binding_path: Path) -> SecurityConfiguration:
    policy, policy_bytes = _load(policy_path)
    binding, binding_bytes = _load(binding_path)
    _keys(
        policy,
        {
            "version",
            "deployment_identity",
            "identity",
            "secrets",
            "policy_id",
            "ai",
            "promotion",
            "source_control",
        },
        {"version", "identity", "secrets"},
        "Security policy",
    )
    identity_policy = policy["identity"]
    secret_policy = policy["secrets"]
    if not isinstance(identity_policy, dict) or not isinstance(secret_policy, dict):
        raise ValueError("Security provider policy must be objects")
    if identity_policy.get("provider") != "microsoft-entra-id-active-directory":
        raise ValueError("Unsupported identity provider")
    if secret_policy.get("provider") != "hashicorp-vault":
        raise ValueError("Unsupported secret provider")
    policy_states = (
        identity_policy.get("workload_authentication_binding_status"),
        secret_policy.get("binding_status"),
    )
    if any(item not in {"active", "pending", "denied"} for item in policy_states):
        raise ValueError("Unknown provider binding status")
    _keys(
        binding,
        {
            "schema_version",
            "status",
            "endpoint",
            "tls_profile_ref",
            "authority",
            "verification_keys",
            "min_lease_seconds",
            "identity_bindings",
            "secret_bindings",
        },
        set(
            {
                "schema_version",
                "status",
                "endpoint",
                "tls_profile_ref",
                "authority",
                "verification_keys",
                "min_lease_seconds",
                "identity_bindings",
                "secret_bindings",
            }
        ),
        "Protected binding",
    )
    if binding["schema_version"] != "1.0":
        raise ValueError("Unsupported protected binding schema_version")
    try:
        status = BindingStatus(binding["status"])
    except (ValueError, TypeError) as exc:
        raise ValueError("Unknown binding status") from exc
    if "denied" in policy_states:
        status = BindingStatus.DENIED
    elif "pending" in policy_states:
        status = BindingStatus.PENDING
    endpoint = _https_url(binding["endpoint"], "Vault endpoint", origin_only=True)
    identity_items = binding["identity_bindings"]
    secret_items = binding["secret_bindings"]
    if (
        not isinstance(identity_items, list)
        or not identity_items
        or not isinstance(secret_items, list)
        or not secret_items
    ):
        raise ValueError("Protected bindings must be non-empty arrays")
    identities: dict[str, IdentityBinding] = {}
    canonical_identity_ids: set[str] = set()
    for item in identity_items:
        if not isinstance(item, dict):
            raise ValueError("Identity binding must be an object")
        _keys(
            item,
            {"binding_id", "tenant", "issuer", "audience", "authentication_flow"},
            set({"binding_id", "tenant", "issuer", "audience", "authentication_flow"}),
            "Identity binding",
        )
        binding_id = _safe(item["binding_id"], "identity binding_id")
        if binding_id.casefold() in canonical_identity_ids:
            raise ValueError("Duplicate identity binding_id")
        canonical_identity_ids.add(binding_id.casefold())
        if item["authentication_flow"] != "workload_identity_federation":
            raise ValueError("Unsupported authentication flow")
        identities[binding_id] = IdentityBinding(
            binding_id,
            _safe(item["tenant"], "tenant"),
            _https_url(item["issuer"], "issuer"),
            _audience(item["audience"]),
            item["authentication_flow"],
        )
    secrets: dict[str, SecretBinding] = {}
    canonical_secret_ids: set[str] = set()
    for item in secret_items:
        if not isinstance(item, dict):
            raise ValueError("Secret binding must be an object")
        _keys(
            item,
            {
                "binding_id",
                "namespace",
                "auth_mount",
                "role",
                "engine",
                "path",
                "version",
                "previous_version",
            },
            set({"binding_id", "namespace", "auth_mount", "role", "engine", "path", "version"}),
            "Secret binding",
        )
        binding_id = _safe(item["binding_id"], "secret binding_id")
        if binding_id.casefold() in canonical_secret_ids:
            raise ValueError("Duplicate secret binding_id")
        canonical_secret_ids.add(binding_id.casefold())
        if item["engine"] != "kv-v2":
            raise ValueError("Unsupported secret engine")
        version = _safe(item["version"], "secret version")
        previous_version_value = item.get("previous_version")
        previous_version = (
            _safe(previous_version_value, "previous secret version")
            if previous_version_value is not None
            else None
        )
        if previous_version == version:
            raise ValueError("previous secret version must differ from current version")
        secrets[binding_id] = SecretBinding(
            binding_id,
            _scope(item["namespace"], "namespace"),
            _scope(item["auth_mount"], "auth mount"),
            _scope(item["role"], "role"),
            item["engine"],
            _scope(item["path"], "secret path"),
            version,
            previous_version,
        )
    verification_keys = binding["verification_keys"]
    if (
        not isinstance(verification_keys, dict)
        or not verification_keys
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in verification_keys.items())
    ):
        raise ValueError("verification_keys must be a non-empty string map")
    for key_id, encoded_key in verification_keys.items():
        _safe(key_id, "verification key_id")
        try:
            if len(base64.b64decode(encoded_key, validate=True)) != 32:
                raise ValueError("verification key must be an Ed25519 public key")
        except (binascii.Error, ValueError) as exc:
            raise ValueError("verification key must be an Ed25519 public key") from exc
    min_lease = binding["min_lease_seconds"]
    if not isinstance(min_lease, int) or isinstance(min_lease, bool) or min_lease < 1:
        raise ValueError("min_lease_seconds must be positive")
    snapshot = policy_bytes + b"\x00" + binding_bytes
    return SecurityConfiguration(
        policy_id=_safe(policy.get("policy_id", "humana-security-policy"), "policy_id"),
        policy_version=_safe(str(policy["version"]), "policy_version"),
        policy_digest=hashlib.sha256(policy_bytes).hexdigest(),
        configuration_digest=hashlib.sha256(snapshot).hexdigest(),
        status=status,
        endpoint=endpoint,
        tls_profile_ref=_safe(binding["tls_profile_ref"], "tls_profile_ref"),
        authority=_safe(binding["authority"], "authority"),
        verification_keys=MappingProxyType(dict(verification_keys)),
        min_lease_seconds=min_lease,
        identity_bindings=MappingProxyType(identities),
        secret_bindings=MappingProxyType(secrets),
        snapshot_bytes=snapshot,
    )


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
