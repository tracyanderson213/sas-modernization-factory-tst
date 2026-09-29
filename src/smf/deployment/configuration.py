"""Strict, network-free loading and preflight of deployment configuration."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from jsonschema import Draft202012Validator

from smf.readiness.deployment import DeploymentReadinessBinding, load_deployment_readiness
from smf.readiness.manifest import load_manifest
from smf.readiness.policy import digest_value
from smf.strict_yaml import load_unique_yaml

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_SECRET_MARKER = re.compile(
    r"(?i)(password|passwd|client[_-]?secret|access[_-]?token|bearer\s+|dapi[a-z0-9]+|secret-canary)"
)
_REQUIRED_ROLES = (
    "workspace",
    "identity",
    "secret_provider",
    "catalog",
    "target_schema",
    "scratch_scope",
    "output_scope",
    "source_read_scope",
    "runtime_version",
    "compute_policy",
    "network_policy",
    "concurrency_limit",
    "timeout_seconds",
    "cleanup_retention_policy",
    "logging_audit_policy",
    "validation_policy",
)
_VALIDATED_SNAPSHOT_TOKEN = object()
_SNAPSHOT_SEAL_KEY = os.urandom(32)


class BindingState(StrEnum):
    PLACEHOLDER = "placeholder"
    PENDING = "pending"
    ACTIVE = "active"
    DENIED = "denied"


@dataclass(frozen=True)
class DeploymentSnapshot:
    schema_version: str
    client_id: str
    deployment_id: str
    environment_id: str
    template_status: BindingState
    bindings: tuple[dict[str, str], ...]
    protected_data: dict[str, str]
    compute_policy_state: str
    compute_policy_digest: str
    configuration_digest: str
    bundle_digest: str
    file_inventory: tuple[dict[str, str], ...]
    readiness: DeploymentReadinessBinding
    snapshot_bytes: tuple[bytes, ...]
    _validation_token: object
    _validation_seal: str


def _deployment_snapshot_seal(snapshot: DeploymentSnapshot) -> str:
    payload = {
        "schema_version": snapshot.schema_version,
        "client_id": snapshot.client_id,
        "deployment_id": snapshot.deployment_id,
        "environment_id": snapshot.environment_id,
        "template_status": snapshot.template_status.value,
        "bindings": snapshot.bindings,
        "protected_data": snapshot.protected_data,
        "compute_policy_state": snapshot.compute_policy_state,
        "compute_policy_digest": snapshot.compute_policy_digest,
        "configuration_digest": snapshot.configuration_digest,
        "bundle_digest": snapshot.bundle_digest,
        "file_inventory": snapshot.file_inventory,
        "snapshot_sha256": [hashlib.sha256(item).hexdigest() for item in snapshot.snapshot_bytes],
        "readiness_policy_digest": snapshot.readiness.policy.policy_digest,
    }
    return hmac.new(
        _SNAPSHOT_SEAL_KEY,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def require_validated_deployment_snapshot(snapshot: DeploymentSnapshot) -> None:
    """Reject constructed or internally inconsistent deployment snapshots."""

    if snapshot._validation_token is not _VALIDATED_SNAPSHOT_TOKEN:
        raise ValueError("Compute selection requires a validated deployment snapshot")
    if not hmac.compare_digest(snapshot._validation_seal, _deployment_snapshot_seal(snapshot)):
        raise ValueError("Deployment snapshot validation seal is invalid")
    if len(snapshot.file_inventory) != len(snapshot.snapshot_bytes):
        raise ValueError("Deployment snapshot inventory is inconsistent")
    observed = tuple(
        {"path": item["path"], "sha256": hashlib.sha256(raw).hexdigest()}
        for item, raw in zip(snapshot.file_inventory, snapshot.snapshot_bytes, strict=True)
    )
    if observed != snapshot.file_inventory:
        raise ValueError("Deployment snapshot bytes do not match its immutable inventory")
    expected_configuration = digest_value(
        {
            "files": [
                item
                for item in observed
                if item["path"]
                in {
                    "factory.yaml",
                    "databricks.yaml",
                    "compute-policy.yaml",
                    "security-policy.yaml",
                    "validation-policy.yaml",
                }
            ]
        }
    )
    expected_bundle = hashlib.sha256(
        json.dumps(observed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if (
        expected_configuration != snapshot.configuration_digest
        or expected_bundle != snapshot.bundle_digest
        or not any(item["path"] == "compute-policy.yaml" for item in observed)
    ):
        raise ValueError("Deployment snapshot governed digest binding is invalid")


@dataclass(frozen=True)
class DeploymentPreflightResult:
    schema_version: str
    client_id: str
    deployment_id: str
    environment_id: str
    configuration_digest: str
    bundle_digest: str
    status: str
    terminal_disposition: str
    blockers: tuple[dict[str, str], ...]
    lifecycle: dict[str, bool]
    file_inventory: tuple[dict[str, str], ...]
    readiness_evidence: dict[str, str] | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_yaml(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        payload = load_unique_yaml(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid deployment configuration YAML") from exc
    if not isinstance(payload, dict):
        raise ValueError("Deployment configuration must be an object")
    return payload, raw


def _schema(name: str) -> dict[str, Any]:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _validate_schema(name: str, payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(payload),
        key=lambda item: list(item.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.path)) or '<root>'}: {item.message}" for item in errors
        )
        raise ValueError(f"Deployment schema validation failed: {detail}")


def _identity(payload: dict[str, Any], label: str) -> tuple[str, str, str]:
    identity = payload.get("deployment_identity")
    if not isinstance(identity, dict) or set(identity) != {
        "client_id",
        "deployment_id",
        "environment_id",
    }:
        raise ValueError(f"{label} requires an exact deployment_identity")
    values = tuple(identity[key] for key in ("client_id", "deployment_id", "environment_id"))
    if any(not isinstance(value, str) or not _SAFE_ID.fullmatch(value) for value in values):
        raise ValueError(f"{label} deployment identity contains an unsafe identifier")
    return values


def _bound_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or urlparse(value).scheme:
        raise ValueError(f"{label} must be a relative deployment path")
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    candidate = Path(decoded)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError(f"{label} escapes the deployment directory")
    unresolved = root / candidate
    has_symlink = any(
        root.joinpath(*candidate.parts[:index]).is_symlink()
        for index in range(1, len(candidate.parts) + 1)
    )
    resolved = unresolved.resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file() or has_symlink:
        raise ValueError(f"{label} is not a regular deployment file")
    return resolved


def _reject_secret(value: str, label: str) -> None:
    parsed = urlparse(value)
    if parsed.username or parsed.password or _SECRET_MARKER.search(value) or "=" in value:
        raise ValueError(f"{label} contains an embedded credential")


def _validate_verification_keys(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} verification_keys must be an object")
    for key_id, encoded_key in value.items():
        _reject_payload_secrets(key_id, label)
        if not isinstance(encoded_key, str):
            raise ValueError(f"{label} verification key must be base64 text")
        try:
            public_key = base64.b64decode(encoded_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"{label} verification key is not valid base64") from exc
        if len(public_key) != 32:
            raise ValueError(f"{label} verification key is not an Ed25519 public key")


def _reject_payload_secrets(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                _reject_payload_secrets(key, label)
            if key == "verification_keys":
                _validate_verification_keys(item, label)
            else:
                _reject_payload_secrets(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_payload_secrets(item, label)
    elif isinstance(value, str):
        parsed = urlparse(value)
        if parsed.username or parsed.password or _SECRET_MARKER.search(value):
            raise ValueError(f"{label} contains an embedded credential")


def load_deployment_snapshot(path: Path) -> DeploymentSnapshot:
    """Load immutable bytes and validate the complete deployment template."""

    factory_path = path.resolve()
    if not factory_path.is_file() or factory_path.is_symlink():
        raise ValueError("Factory configuration must be a regular file")
    root = factory_path.parent
    factory, factory_bytes = _load_yaml(factory_path)
    _reject_payload_secrets(factory, "Factory configuration")
    allowed = {
        "schema_version",
        "deployment_identity",
        "template_status",
        "deployment",
        "readiness",
        "routing",
        "telemetry",
    }
    if set(factory) - allowed or not {
        "schema_version",
        "deployment_identity",
        "template_status",
        "deployment",
        "readiness",
    }.issubset(factory):
        raise ValueError("Factory deployment configuration has unknown or missing fields")
    if factory["schema_version"] != "1.0":
        raise ValueError("Unsupported deployment schema_version")
    try:
        template_status = BindingState(factory["template_status"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Unknown deployment template_status") from exc
    expected_identity = _identity(factory, "Factory configuration")
    deployment = factory["deployment"]
    if not isinstance(deployment, dict) or set(deployment) != {"provider", "configuration"}:
        raise ValueError("Factory deployment provider binding is malformed")
    if deployment["provider"] != "databricks":
        raise ValueError("Unsupported deployment provider")
    databricks_path = _bound_file(root, deployment["configuration"], "Provider configuration")
    databricks, databricks_bytes = _load_yaml(databricks_path)
    _reject_payload_secrets(databricks, "Provider configuration")
    _validate_schema("deployment-configuration.schema.json", databricks)
    if _identity(databricks, "Provider configuration") != expected_identity:
        raise ValueError("Mixed-environment deployment identity")

    readiness_binding = factory["readiness"]
    if not isinstance(readiness_binding, dict):
        raise ValueError("Factory readiness binding is malformed")
    early_scan_paths = [_bound_file(root, readiness_binding.get("policy"), "Readiness policy")]
    configured_files = readiness_binding.get("configuration_files", [])
    if not isinstance(configured_files, list):
        raise ValueError("Readiness configuration_files must be an array")
    early_scan_paths.extend(
        _bound_file(root, item, "Readiness configuration file") for item in configured_files
    )
    for scan_path in dict.fromkeys(early_scan_paths):
        scan_payload, _ = _load_yaml(scan_path)
        _reject_payload_secrets(scan_payload, "Deployment configuration")

    bindings = databricks["bindings"]
    roles = [item["role"] for item in bindings]
    canonical_binding_ids = {item["binding_id"].casefold() for item in bindings}
    if tuple(roles) != _REQUIRED_ROLES or len(canonical_binding_ids) != len(bindings):
        raise ValueError("Deployment bindings are missing, out of order, or duplicate")
    normalized: list[dict[str, str]] = []
    for item in bindings:
        try:
            state = BindingState(item["state"])
        except (TypeError, ValueError) as exc:
            raise ValueError("Unknown deployment binding state") from exc
        value = item["value"]
        _reject_secret(value, f"Deployment binding {item['binding_id']}")
        if state is BindingState.ACTIVE and value.strip().upper() in {"", "REQUIRED", "PENDING"}:
            raise ValueError("Active deployment binding has no meaningful value")
        normalized.append({**item, "state": state.value})
    by_role = {item["role"]: item for item in normalized}
    if by_role["compute_policy"]["value"] != "compute-policy.yaml":
        raise ValueError("Databricks compute_policy must bind compute-policy.yaml")

    readiness = load_deployment_readiness(factory_path)
    if readiness.policy.prerequisite_binding is None:
        raise ValueError("Deployment readiness policy lacks prerequisite identity binding")
    policy_identity = tuple(
        readiness.policy.prerequisite_binding[key]
        for key in ("client_id", "deployment_id", "environment_id")
    )
    if policy_identity != expected_identity:
        raise ValueError("Mixed-environment readiness policy identity")

    configuration_paths = readiness.configuration_paths
    relative_paths = [item.relative_to(root).as_posix() for item in configuration_paths]
    if len({item.casefold() for item in relative_paths}) != len(relative_paths):
        raise ValueError("Duplicate normalized deployment configuration path")
    expected_paths = (
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
    )
    if tuple(relative_paths) != expected_paths:
        raise ValueError("Deployment configuration scope is incomplete")
    compute_policy_state = "missing"
    compute_policy_digest = ""
    for configuration_path in configuration_paths:
        payload, _ = _load_yaml(configuration_path)
        _reject_payload_secrets(payload, "Deployment configuration")
        identity_files = {
            "databricks.yaml",
            "compute-policy.yaml",
            "security-policy.yaml",
            "validation-policy.yaml",
        }
        if configuration_path.name in identity_files and (
            (
                tuple(payload.get(key) for key in ("client_id", "deployment_id", "environment_id"))
                if configuration_path.name == "compute-policy.yaml"
                else _identity(payload, "Deployment configuration")
            )
            != expected_identity
        ):
            raise ValueError("Mixed-environment deployment identity")
        if configuration_path.name == "compute-policy.yaml":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            from smf.execution.databricks_compute import (
                compute_policy_from_dict,
                verify_compute_policy_authority,
            )

            compute_policy = compute_policy_from_dict(payload)
            compute_policy_state = compute_policy.policy_state.value
            compute_policy_digest = compute_policy.policy_digest
            if compute_policy.workspace_binding_id != by_role["workspace"]["binding_id"]:
                raise ValueError("Compute policy workspace binding is inconsistent")
            if (
                compute_policy.policy_state.value == "active"
                and by_role["compute_policy"]["state"] != BindingState.ACTIVE.value
            ):
                raise ValueError("Active compute policy lacks an active deployment binding")
            try:
                authority_keys = {
                    key_id: Ed25519PublicKey.from_public_bytes(
                        base64.b64decode(value, validate=True)
                    )
                    for key_id, value in readiness.policy.verification_keys.items()
                }
            except (ValueError, TypeError) as exc:
                raise ValueError("Readiness policy contains an invalid authority key") from exc
            verify_compute_policy_authority(
                compute_policy,
                authority_keys=authority_keys,
                allowed_authorities=readiness.policy.evidence_authorities.get("approval", ()),
                allowed_key_ids=readiness.policy.evidence_key_ids.get("approval", ()),
            )
    readiness_payload, _ = _load_yaml(readiness.policy_path)
    _reject_payload_secrets(readiness_payload, "Readiness policy")
    inventory_paths = (
        factory_path,
        readiness.policy_path,
        *(item for item in configuration_paths if item != factory_path),
    )
    if len(set(inventory_paths)) != len(inventory_paths):
        raise ValueError("Duplicate canonical deployment file role")
    inventory = tuple(
        {
            "path": item.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
        }
        for item in inventory_paths
    )
    bundle_digest = hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    snapshot = DeploymentSnapshot(
        schema_version="1.0",
        client_id=expected_identity[0],
        deployment_id=expected_identity[1],
        environment_id=expected_identity[2],
        template_status=template_status,
        bindings=tuple(normalized),
        protected_data=dict(databricks["protected_data"]),
        compute_policy_state=compute_policy_state,
        compute_policy_digest=compute_policy_digest,
        configuration_digest=readiness.configuration_digest or "",
        bundle_digest=bundle_digest,
        file_inventory=inventory,
        readiness=readiness,
        snapshot_bytes=tuple(item.read_bytes() for item in inventory_paths),
        _validation_token=_VALIDATED_SNAPSHOT_TOKEN,
        _validation_seal="",
    )
    return replace(snapshot, _validation_seal=_deployment_snapshot_seal(snapshot))


def preflight_deployment(
    path: Path,
    readiness_manifest: Path | None = None,
    *,
    workload_id: str | None = None,
    run_id: str | None = None,
    attempt_id: str | None = None,
) -> DeploymentPreflightResult:
    """Evaluate configuration only; never contacts providers or resolves credentials."""

    snapshot = load_deployment_snapshot(path)
    blockers: list[dict[str, str]] = []
    readiness_evidence: dict[str, str] | None = None
    for binding in snapshot.bindings:
        state = BindingState(binding["state"])
        if state is BindingState.DENIED:
            blockers.append(
                {"code": "binding_denied", "binding_id": binding["binding_id"], "state": state}
            )
        elif state is not BindingState.ACTIVE:
            blockers.append(
                {
                    "code": (
                        "binding_pending"
                        if state is BindingState.PENDING
                        else "binding_placeholder"
                    ),
                    "binding_id": binding["binding_id"],
                    "state": state,
                }
            )
    if snapshot.compute_policy_state == "pending":
        blockers.append(
            {
                "code": "compute_policy_pending",
                "binding_id": "compute-policy",
                "state": "pending",
            }
        )
    elif snapshot.compute_policy_state == "denied":
        blockers.append(
            {
                "code": "compute_policy_denied",
                "binding_id": "compute-policy",
                "state": "denied",
            }
        )
    elif snapshot.compute_policy_state != "active":
        blockers.append(
            {
                "code": "compute_policy_inactive",
                "binding_id": "compute-policy",
                "state": snapshot.compute_policy_state,
            }
        )
    if snapshot.template_status is not BindingState.ACTIVE:
        blockers.append(
            {
                "code": "template_not_active",
                "binding_id": "deployment-template",
                "state": snapshot.template_status,
            }
        )
    if not blockers:
        if readiness_manifest is None:
            blockers.append(
                {
                    "code": "readiness_evidence_missing",
                    "binding_id": "readiness-manifest",
                    "state": "missing",
                }
            )
        else:
            manifest = load_manifest(readiness_manifest)
            readiness_evidence = {
                "result_id": str(manifest["result_id"]),
                "manifest_digest": str(manifest["content_digest"]),
                "policy_id": str(manifest["policy_id"]),
                "policy_version": str(manifest["policy_version"]),
                "policy_digest": str(manifest["policy_digest"]),
                "workload_id": str(manifest["workload_id"]),
                "run_id": str(manifest["run_id"]),
                "attempt_id": str(manifest["attempt_id"]),
            }
            expected = {
                "client_id": snapshot.client_id,
                "deployment_id": snapshot.deployment_id,
                "environment_id": snapshot.environment_id,
                "configuration_digest": snapshot.configuration_digest,
            }
            prerequisite_binding = manifest["policy_snapshot"].get("prerequisite_binding", {})
            mismatched = [
                key for key, value in expected.items() if prerequisite_binding.get(key) != value
            ]
            checklist = manifest.get("prerequisite_checklist", [])
            expected_context = {
                "workload_id": workload_id,
                "run_id": run_id,
                "attempt_id": attempt_id,
            }
            context_mismatch = any(
                value is None or manifest.get(key) != value
                for key, value in expected_context.items()
            )
            policy = snapshot.readiness.policy
            policy_mismatch = any(
                manifest.get(key) != value
                for key, value in {
                    "policy_id": policy.policy_id,
                    "policy_version": policy.policy_version,
                    "policy_digest": policy.policy_digest,
                }.items()
            )
            if (
                manifest.get("classification") != "READY"
                or mismatched
                or context_mismatch
                or policy_mismatch
                or len(checklist) != len(policy.prerequisites)
                or any(item.get("state") != "pass" for item in checklist)
            ):
                blockers.append(
                    {
                        "code": "readiness_evidence_mismatch",
                        "binding_id": "readiness-manifest",
                        "state": "invalid",
                    }
                )
    denied = any(item["code"] == "binding_denied" for item in blockers)
    status = "qualified" if not blockers else ("blocked" if denied else "unresolved")
    return DeploymentPreflightResult(
        schema_version="1.0",
        client_id=snapshot.client_id,
        deployment_id=snapshot.deployment_id,
        environment_id=snapshot.environment_id,
        configuration_digest=snapshot.configuration_digest,
        bundle_digest=snapshot.bundle_digest,
        status=status,
        terminal_disposition=status,
        blockers=tuple(blockers),
        lifecycle={
            "template_generated": True,
            "preflight_qualified": status == "qualified",
            "preflight_blocked": status != "qualified",
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "human_approved": False,
        },
        file_inventory=snapshot.file_inventory,
        readiness_evidence=readiness_evidence,
    )


def initialize_deployment_template(template: str, output: Path) -> tuple[Path, ...]:
    """Publish the reviewed repository template without overwriting differing bytes."""

    if template != "humana":
        raise ValueError("Unknown deployment template")
    source = files("smf.deployment.templates").joinpath(template)
    names = (
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
        "readiness-policy.yaml",
    )
    output.mkdir(parents=True, exist_ok=True)
    published: list[Path] = []
    for name in names:
        content = source.joinpath(name).read_bytes()
        target = output / name
        if target.exists():
            collision = (
                not target.is_file()
                or target.is_symlink()
                or not hmac.compare_digest(target.read_bytes(), content)
            )
            if collision:
                raise FileExistsError(f"Deployment template collision: {target}")
            published.append(target)
            continue
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=output, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if not hmac.compare_digest(target.read_bytes(), content):
                    raise FileExistsError(f"Deployment template collision: {target}") from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        published.append(target)
    return tuple(published)
