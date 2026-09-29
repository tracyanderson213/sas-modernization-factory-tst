"""Configuration binding for the offline migration contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import yaml

from smf.deployment import load_deployment_snapshot

_SAFE_ROLE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SENSITIVE = re.compile(
    rb"(?i)(secret-canary|phi-canary|pii-canary|password[\"']?\s*[:=]|"
    rb"client[_-]?secret[\"']?\s*[:=]|access[_-]?token[\"']?\s*[:=]|bearer\s+[a-z0-9])"
)
_GATEWAY_CONFIGURATION_KEYS = {"schema_version", "provider", "mode"}


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate configuration key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _read_policy(path: Path, role: str) -> dict[str, Any]:
    if _SENSITIVE.search(path.name.encode("utf-8")):
        raise ValueError(f"Configuration role {role} has an unsafe reference")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Configuration role {role} must reference a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"Configuration role {role} is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    current = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    ):
        raise ValueError("configuration_mutated_during_qualification")
    if _SENSITIVE.search(raw):
        raise ValueError(f"Configuration role {role} contains protected or credential material")
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Configuration role {role} is not valid YAML or JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Configuration role {role} must contain an object")
    if role == "gateway_configuration" and (
        set(value) != _GATEWAY_CONFIGURATION_KEYS
        or value.get("schema_version") != "1.0"
        or value.get("provider") != "humana-ai-gateway"
        or value.get("mode") != "preflight"
    ):
        raise ValueError(
            "Gateway configuration must use schema_version 1.0, provider "
            "humana-ai-gateway, mode preflight, and no additional fields"
        )
    return {
        "role": role,
        "reference": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "byte_count": len(raw),
    }


def acquire_request_artifacts(
    role_paths: tuple[tuple[str, Path], ...],
) -> tuple[list[dict[str, Any]], str | None]:
    roles = [role for role, _ in role_paths]
    if any(not _SAFE_ROLE.fullmatch(role) for role in roles) or len(set(roles)) != len(roles):
        raise ValueError("Request artifact roles are unsafe or duplicate")
    artifacts = [_read_policy(path, role) for role, path in role_paths]
    if not artifacts:
        return [], None
    digest = hashlib.sha256(
        json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return artifacts, digest


def acquire_configuration_manifest(
    factory_config: Path, role_paths: tuple[tuple[str, Path], ...]
) -> tuple[dict[str, Any], dict[str, str]]:
    snapshot = load_deployment_snapshot(factory_config)
    artifacts, _ = acquire_request_artifacts(role_paths)
    files: list[dict[str, Any]] = []
    for item, raw in zip(snapshot.file_inventory, snapshot.snapshot_bytes, strict=True):
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("Deployment configuration changed during qualification")
        files.append(
            {
                "role": f"factory_bundle:{item['path']}",
                "reference": item["path"],
                "sha256": item["sha256"],
                "byte_count": len(raw),
            }
        )
    files.extend(artifacts)
    material = {"files": files, "factory_bundle_digest": snapshot.bundle_digest}
    bundle_digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    manifest = {
        "schema_version": "1.0",
        "client_id": snapshot.client_id,
        "deployment_id": snapshot.deployment_id,
        "environment_id": snapshot.environment_id,
        "factory_bundle_digest": snapshot.bundle_digest,
        "configuration_bundle_digest": bundle_digest,
        "files": files,
    }
    return manifest, {
        "client_id": snapshot.client_id,
        "deployment_id": snapshot.deployment_id,
        "environment_id": snapshot.environment_id,
    }
