"""Strict loading for governed upstream policy and inventory."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value
from smf.upstream.models import AdoptionDisposition
from smf.upstream.schema import validate_inventory, validate_policy
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_COMMIT = re.compile(r"^[a-f0-9]{40}$")


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate upstream configuration key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True)
class UpstreamPolicy:
    payload: dict[str, Any]
    policy_digest: str


@dataclass(frozen=True)
class UpstreamInventory:
    payload: dict[str, Any]
    inventory_digest: str


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
        else:
            value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate upstream configuration key")
        result[key] = value
    return result


def _safe_text(value: object, label: str) -> None:
    if not isinstance(value, str) or contains_protected_data(value):
        raise ValueError(f"Unsafe or protected data in upstream {label}")
    if sanitize_discovery_value(value) != value:
        raise ValueError(f"Unsafe or protected data in upstream {label}")


def load_upstream_policy(path: Path) -> UpstreamPolicy:
    raw = _load(path, "Upstream policy")
    validate_policy(raw)
    key_ids = set(raw["verification_keys"])
    provenance_names = (
        "acquisition_provenance",
        "observer_provenance",
        "supporting_evidence_provenance",
        "qualification_provenance",
        "prerequisite_provenance",
    )
    if any(not set(raw[name]["key_ids"]).issubset(key_ids) for name in provenance_names):
        raise ValueError("Upstream policy references an unknown verification key")
    observer = raw["observer_provenance"]
    supporting = raw["supporting_evidence_provenance"]
    qualifier = raw["qualification_provenance"]
    if set(observer["key_ids"]) & set(qualifier["key_ids"]):
        raise ValueError("Observer and qualification signing keys must be distinct")
    if set(observer["key_ids"]) & set(supporting["key_ids"]):
        raise ValueError("Observer and supporting-evidence signing keys must be distinct")
    for field in ("policy_id", "policy_version", "scope_kind"):
        _safe_text(raw[field], field)
    return UpstreamPolicy(raw, digest_value(raw))


def load_upstream_inventory(path: Path) -> UpstreamInventory:
    raw = _load(path, "Expected upstream inventory")
    validate_inventory(raw)
    entries = raw["upstreams"]
    if not entries:
        raise ValueError("Expected upstream inventory cannot be empty")
    ids = [str(item["upstream_id"]) for item in entries]
    origins = [str(item["canonical_origin"]).casefold() for item in entries]
    revisions = [
        (origin, str(item["revision"])) for origin, item in zip(origins, entries, strict=True)
    ]
    if len(ids) != len(set(ids)) or len({item.casefold() for item in ids}) != len(ids):
        raise ValueError("Expected upstream identity is duplicated or case-ambiguous")
    if len(origins) != len(set(origins)) or len(revisions) != len(set(revisions)):
        raise ValueError("Expected upstream origin/revision identity is ambiguous")
    usable = False
    for item in entries:
        _safe_text(item["upstream_id"], "identity")
        parsed = urlparse(item["canonical_origin"])
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("Upstream canonical origin must be an HTTPS URL")
        if item["revision_type"] == "git_commit" and not _COMMIT.fullmatch(item["revision"]):
            raise ValueError("Git upstream revision must be a full lowercase commit SHA")
        if item["revision_type"] == "sha256" and not _SHA256.fullmatch(item["revision"]):
            raise ValueError("Artifact upstream revision must be a SHA-256 digest")
        capability_ids = [entry["capability_id"] for entry in item["capabilities"]]
        limitation_ids = [entry["limitation_id"] for entry in item["limitations"]]
        if len(capability_ids) != len(set(capability_ids)) or len(limitation_ids) != len(
            set(limitation_ids)
        ):
            raise ValueError("Upstream capability or limitation identity is duplicated")
        disposition = AdoptionDisposition(item["disposition"])
        if disposition is AdoptionDisposition.FORK_AND_HARDEN:
            raise ValueError("No fork-and-harden upstream disposition is currently approved")
        if disposition not in {AdoptionDisposition.PATTERNS_ONLY, AdoptionDisposition.REJECT}:
            usable = True
    if not usable:
        raise ValueError("Expected inventory has no eligible adoption subject")
    return UpstreamInventory(raw, digest_value(raw))
