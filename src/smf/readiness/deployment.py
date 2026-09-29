"""Deployment binding for readiness admission without client-specific core logic."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlparse

from smf.readiness.models import ReadinessPolicy
from smf.readiness.policy import digest_value, load_readiness_policy
from smf.strict_yaml import load_unique_yaml


@dataclass(frozen=True)
class DeploymentReadinessBinding:
    required: bool
    policy_path: Path
    policy: ReadinessPolicy
    configuration_digest: str | None
    configuration_paths: tuple[Path, ...]
    client_id: str | None = None
    deployment_id: str | None = None
    environment_id: str | None = None


def _bound_path(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or urlparse(value).scheme:
        raise ValueError(f"Readiness binding {label} must be a non-empty relative path")
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    relative = Path(decoded)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"Readiness binding {label} escapes the deployment directory")
    has_symlink = any(
        root.joinpath(*relative.parts[:index]).is_symlink()
        for index in range(1, len(relative.parts) + 1)
    )
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"Readiness binding {label} escapes the deployment directory")
    if not resolved.is_file() or has_symlink:
        raise ValueError(f"Readiness binding {label} is not a regular deployment file")
    return resolved


def load_deployment_readiness(path: Path) -> DeploymentReadinessBinding:
    raw = load_unique_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Factory deployment configuration must be an object")
    identity = raw.get("deployment_identity")
    identity_values: tuple[str | None, str | None, str | None]
    if identity is None:
        # Retained for older, non-production test bindings. Governed conversion
        # does not treat an identity-less binding as deterministic authority.
        identity_values = (None, None, None)
    elif not isinstance(identity, dict) or set(identity) != {
        "client_id",
        "deployment_id",
        "environment_id",
    }:
        raise ValueError("Factory deployment identity must contain exact identity fields")
    else:
        values = tuple(identity[key] for key in ("client_id", "deployment_id", "environment_id"))
        if any(
            not isinstance(value, str)
            or not value
            or value in {".", ".."}
            or not value.replace("-", "").replace(".", "").isalnum()
            for value in values
        ):
            raise ValueError("Factory deployment identity contains an unsafe identifier")
        identity_values = cast(tuple[str, str, str], values)
    readiness = raw.get("readiness")
    if not isinstance(readiness, dict):
        raise ValueError("Factory deployment configuration requires a readiness binding")
    if not set(readiness).issubset({"required", "policy", "configuration_files"}) or not {
        "required",
        "policy",
    }.issubset(readiness):
        raise ValueError(
            "Readiness binding must contain required, policy, and optional configuration_files"
        )
    if not isinstance(readiness["required"], bool):
        raise ValueError("Readiness binding required must be a boolean")
    binding_root = path.parent.resolve()
    policy_path = _bound_path(binding_root, readiness["policy"], "policy")
    policy = load_readiness_policy(policy_path)
    policy_binding = policy.prerequisite_binding or {}
    if all(identity_values) and policy_binding:
        expected_identity = tuple(
            policy_binding.get(key) for key in ("client_id", "deployment_id", "environment_id")
        )
        if expected_identity != identity_values:
            raise ValueError("Factory and readiness policy deployment identities differ")
    configured = readiness.get("configuration_files", [])
    if not isinstance(configured, list) or not all(isinstance(item, str) for item in configured):
        raise ValueError("Readiness binding configuration_files must be an array of paths")
    if len(configured) != len(set(configured)):
        raise ValueError("Readiness binding configuration_files must be unique")
    configuration_paths = tuple(
        _bound_path(binding_root, item, "configuration file") for item in configured
    )
    configuration_digest = (
        digest_value(
            {
                "files": [
                    {
                        "path": item.relative_to(binding_root).as_posix(),
                        "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
                    }
                    for item in configuration_paths
                ]
            }
        )
        if configuration_paths
        else None
    )
    expected_digest = (
        policy.prerequisite_binding.get("configuration_digest")
        if policy.prerequisite_binding is not None
        else None
    )
    if expected_digest is not None and configuration_digest is None:
        raise ValueError("Readiness binding requires configuration_files for prerequisite policy")
    if expected_digest is not None and configuration_digest != expected_digest:
        raise ValueError("Readiness configuration snapshot digest mismatch")
    return DeploymentReadinessBinding(
        required=readiness["required"],
        policy_path=policy_path,
        policy=policy,
        configuration_digest=configuration_digest,
        configuration_paths=configuration_paths,
        client_id=identity_values[0],
        deployment_id=identity_values[1],
        environment_id=identity_values[2],
    )
