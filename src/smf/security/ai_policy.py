"""Strict loading for offline AI-context policy."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from smf.security.schema import validate_security_schema

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
            raise ValueError("Duplicate AI policy key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def canonical_ai_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def ai_digest(value: object) -> str:
    return hashlib.sha256(canonical_ai_json(value)).hexdigest()


@dataclass(frozen=True)
class AIContextPolicy:
    policy_id: str
    policy_version: str
    policy_digest: str
    status: str
    classification_policy_id: str
    classification_policy_version: str
    classification_policy_digest: str
    classification_authority: str
    verification_keys: MappingProxyType[str, str]
    allowed_providers: MappingProxyType[str, tuple[str, ...]]
    endpoint_bindings: MappingProxyType[str, tuple[str, ...]]
    allowed_artifact_kinds: tuple[str, ...]
    allowed_fields: tuple[str, ...]
    retention_policy_ref: str
    access_policy_ref: str
    protected_data_in_prompt_allowed: bool
    max_context_bytes: int
    snapshot: dict[str, Any]


def _unique_safe(values: object, label: str) -> tuple[str, ...]:
    if not isinstance(values, list) or not values:
        raise ValueError(f"{label} must be a non-empty list")
    if any(not isinstance(item, str) or not _SAFE.fullmatch(item) for item in values):
        raise ValueError(f"{label} contains an unsafe identifier")
    if len({item.casefold() for item in values}) != len(values):
        raise ValueError(f"{label} contains duplicate or case-ambiguous identifiers")
    return tuple(values)


def load_ai_context_policy(path: Path) -> AIContextPolicy:
    try:
        raw = path.read_text(encoding="utf-8")
        payload = yaml.load(raw, Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Invalid AI context policy") from exc
    if not isinstance(payload, dict):
        raise ValueError("AI context policy must be an object")
    validate_security_schema("ai-context-policy.schema.json", payload)
    unsigned = dict(payload)
    supplied_digest = unsigned.pop("policy_digest")
    if supplied_digest != ai_digest(unsigned):
        raise ValueError("AI context policy digest mismatch")
    for field in (
        "policy_id",
        "policy_version",
        "classification_policy_id",
        "classification_policy_version",
        "classification_authority",
        "retention_policy_ref",
        "access_policy_ref",
    ):
        if not _SAFE.fullmatch(str(payload[field])):
            raise ValueError(f"Unsafe AI context policy {field}")
    keys = payload["verification_keys"]
    if not isinstance(keys, dict) or not keys:
        raise ValueError("AI context policy requires verification keys")
    folded: set[str] = set()
    for key_id, value in keys.items():
        if (
            not isinstance(key_id, str)
            or not _SAFE.fullmatch(key_id)
            or key_id.casefold() in folded
        ):
            raise ValueError("Invalid or duplicate AI policy verification key")
        folded.add(key_id.casefold())
        try:
            if len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError("Invalid AI policy verification key")
        except (TypeError, binascii.Error) as exc:
            raise ValueError("Invalid AI policy verification key") from exc
    providers: dict[str, tuple[str, ...]] = {}
    endpoints: dict[str, tuple[str, ...]] = {}
    for provider in payload["providers"]:
        provider_id = str(provider["provider_id"])
        if not _SAFE.fullmatch(provider_id) or provider_id.casefold() in {
            item.casefold() for item in providers
        }:
            raise ValueError("Invalid or duplicate AI provider")
        providers[provider_id] = _unique_safe(provider["model_ids"], "model_ids")
        endpoints[provider_id] = _unique_safe(
            provider["endpoint_binding_ids"], "endpoint_binding_ids"
        )
    return AIContextPolicy(
        policy_id=str(payload["policy_id"]),
        policy_version=str(payload["policy_version"]),
        policy_digest=str(payload["policy_digest"]),
        status=str(payload["status"]),
        classification_policy_id=str(payload["classification_policy_id"]),
        classification_policy_version=str(payload["classification_policy_version"]),
        classification_policy_digest=str(payload["classification_policy_digest"]),
        classification_authority=str(payload["classification_authority"]),
        verification_keys=MappingProxyType(dict(keys)),
        allowed_providers=MappingProxyType(providers),
        endpoint_bindings=MappingProxyType(endpoints),
        allowed_artifact_kinds=_unique_safe(
            payload["allowed_artifact_kinds"], "allowed_artifact_kinds"
        ),
        allowed_fields=_unique_safe(payload["allowed_fields"], "allowed_fields"),
        retention_policy_ref=str(payload["retention_policy_ref"]),
        access_policy_ref=str(payload["access_policy_ref"]),
        protected_data_in_prompt_allowed=bool(payload["protected_data_in_prompt_allowed"]),
        max_context_bytes=int(payload["max_context_bytes"]),
        snapshot=payload,
    )


def humana_ai_blockers(path: Path) -> tuple[str, ...]:
    """Return explicit offline blockers from the existing deployment policy."""

    payload = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    if not isinstance(payload, dict) or not isinstance(payload.get("ai"), dict):
        return ("ai_policy_missing",)
    ai = payload["ai"]
    blockers: list[str] = []
    if ai.get("binding_status") == "pending":
        blockers.append("endpoint_binding_pending")
    elif ai.get("binding_status") != "active":
        blockers.append("endpoint_binding_invalid")
    for field, code in (
        ("approved_endpoint_bindings", "endpoint_binding_missing"),
        ("approved_model_bindings", "model_binding_missing"),
        ("allowed_context_fields", "field_allowlist_missing"),
        ("allowed_artifact_kinds", "artifact_allowlist_missing"),
        ("classification_authority", "classification_authority_missing"),
        ("retention_policy_ref", "retention_policy_missing"),
        ("access_policy_ref", "access_policy_missing"),
        ("submission_authority", "submission_authority_missing"),
    ):
        if not ai.get(field):
            blockers.append(code)
    if ai.get("protected_data_in_prompt_allowed") is not False:
        blockers.append("protected_data_policy_invalid")
    return tuple(blockers)
