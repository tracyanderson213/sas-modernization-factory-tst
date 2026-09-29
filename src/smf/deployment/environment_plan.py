"""Deterministic, offline environment-plan contract for DBENV-01."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

import yaml
from jsonschema import Draft202012Validator

from smf.deployment.configuration import DeploymentSnapshot, load_deployment_snapshot
from smf.immutable_files import ensure_directory, publish_json, read_published_json

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SECRET = re.compile(
    r"(?i)(password|passwd|client[_-]?secret|access[_-]?token|api[_-]?key|"
    r"bearer\s+|dapi[a-z0-9]+|secret-canary)"
)
_RESULT_NAME = "environment-plan.result.json"
_TELEMETRY_NAME = "environment-plan.telemetry.json"


class _UniqueLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueLoader, node: yaml.Node, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate environment-plan configuration key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True)
class EnvironmentPlanRequest:
    factory_config_path: Path
    environment_config_path: Path
    output_root: Path
    run_id: str
    attempt_id: str


@dataclass(frozen=True)
class PreparedEnvironmentPlan:
    result: dict[str, Any]
    telemetry: dict[str, Any]


def _schema(name: str) -> dict[str, Any]:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Packaged {name} is not an object")
    return payload


def _validate(name: str, payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(payload),
        key=lambda item: list(item.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.path)) or '<root>'}: {item.message}" for item in errors
        )
        raise ValueError(f"Environment-plan schema validation failed: {detail}")


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe environment-plan {label}")
    if _SECRET.search(value):
        raise ValueError(f"Environment-plan {label} contains a credential marker")
    return value


def _reject_secrets(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and _SECRET.search(key):
                raise ValueError("Environment-plan configuration contains a credential field")
            _reject_secrets(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secrets(item)
    elif isinstance(value, str) and _SECRET.search(value):
        raise ValueError("Environment-plan configuration contains a credential marker")


def _read_regular(path: Path, label: str) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if any(parent.is_symlink() for parent in (absolute, *absolute.parents)):
        raise ValueError(f"{label} has a symlink ancestor")
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise ValueError(f"{label} is missing or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"{label} changed while being acquired")
        return raw
    finally:
        os.close(descriptor)


def _load_yaml_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    return payload


def load_environment_plan_config(path: Path) -> tuple[dict[str, Any], bytes]:
    """Acquire and validate the strict environment contract without resolving references."""

    raw = _read_regular(path, "Environment-plan configuration")
    payload = _load_yaml_bytes(raw, "Environment-plan configuration")
    _reject_secrets(payload)
    _validate("environment-plan-config.schema.json", payload)
    identity = cast(dict[str, Any], payload["deployment_identity"])
    for field in ("client_id", "deployment_id", "environment_id"):
        _safe_id(identity[field], field)
    for value in _walk_reference_values(payload):
        if value is not None:
            _safe_id(value, "opaque reference")
    _validate_active_sections(payload)
    return payload, raw


def _walk_reference_values(value: object, key: str = "") -> list[object]:
    found: list[object] = []
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key.endswith("_reference") or child_key.endswith("_references"):
                if isinstance(child, list):
                    found.extend(child)
                else:
                    found.append(child)
            else:
                found.extend(_walk_reference_values(child, child_key))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_reference_values(child, key))
    return found


def _validate_active_sections(config: dict[str, Any]) -> None:
    def require(section: str, values: list[object]) -> None:
        payload = cast(dict[str, Any], config[section])
        if payload["state"] == "active" and any(value is None or value == [] for value in values):
            raise ValueError(f"Active environment-plan {section} has unresolved references")

    workspace = cast(dict[str, Any], config["workspace"])
    require(
        "workspace",
        [
            workspace["host_reference"],
            workspace["workspace_reference"],
            workspace["auth_context_reference"],
            workspace["principal_reference"],
            None if workspace["auth_method"] == "pending" else workspace["auth_method"],
        ],
    )
    catalog = cast(dict[str, Any], config["unity_catalog"])
    schemas = cast(dict[str, Any], catalog["logical_schemas"])
    require("unity_catalog", [catalog["catalog_reference"], *schemas.values()])
    volumes = cast(dict[str, Any], config["volumes"])
    require(
        "volumes",
        [volumes[key] for key in ("landing", "artifact", "validation", "checkpoint")],
    )
    compute = cast(dict[str, Any], config["compute"])
    compute_values: list[object] = []
    if compute["selection"] == "existing":
        compute_values = [compute["existing_compute_reference"]]
    elif compute["selection"] == "governed_request":
        governed = cast(dict[str, Any] | None, compute["governed_request"])
        compute_values = [] if governed is None else list(governed.values())
    require("compute", compute_values or [None])
    git = cast(dict[str, Any], config["git"])
    require("git", [git["repository_reference"]])
    vault = cast(dict[str, Any], config["vault"])
    require(
        "vault",
        [
            vault["vault_reference"],
            vault["origin_reference"],
            vault["namespace_reference"],
            vault["mount_reference"],
            None if vault["auth_method"] == "pending" else vault["auth_method"],
            vault["audience_reference"],
            vault["role_reference"],
            vault["secret_binding_references"],
        ],
    )
    gateway = cast(dict[str, Any], config["ai_gateway"])
    require(
        "ai_gateway",
        [
            gateway["origin_reference"],
            gateway["gateway_reference"],
            gateway["configuration_reference"],
            gateway["anthropic_route_reference"],
            gateway["anthropic_model_reference"],
        ],
    )
    packages = cast(dict[str, Any], config["packages"])
    require(
        "packages",
        [
            packages["repository_reference"],
            packages["offline_bundle_reference"],
            packages["offline_wheel_reference"],
            packages["offline_jar_reference"],
            packages["offline_native_reference"],
        ],
    )
    sources = cast(dict[str, Any], config["sources"])
    for prefix in ("sas_program", "sas7bdat", "source_system"):
        if sources[f"{prefix}_state"] == "active" and sources[f"{prefix}_reference"] is None:
            raise ValueError(f"Active environment-plan {prefix} has an unresolved reference")


def _implementation_manifest() -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    resources = (
        (
            "smf/deployment/environment_plan.py",
            files("smf.deployment").joinpath("environment_plan.py"),
        ),
        ("smf/deployment/configuration.py", files("smf.deployment").joinpath("configuration.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        ("smf/cli/main.py", files("smf.cli").joinpath("main.py")),
        *(
            (name, files("smf.schemas").joinpath(name))
            for name in (
                "environment-plan-config.schema.json",
                "environment-plan-result.schema.json",
                "environment-plan-telemetry.schema.json",
            )
        ),
    )
    for name, resource in resources:
        inventory.append(
            {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        )
    return inventory


def _load_inputs(
    request: EnvironmentPlanRequest,
) -> tuple[DeploymentSnapshot, dict[str, Any], bytes]:
    factory = Path(os.path.abspath(os.fspath(request.factory_config_path)))
    environment = Path(os.path.abspath(os.fspath(request.environment_config_path)))
    if factory.parent != environment.parent:
        raise ValueError("Factory and environment configuration must share an authorized directory")
    factory_before = _read_regular(factory, "Factory configuration")
    environment_config, environment_bytes = load_environment_plan_config(environment)
    snapshot = load_deployment_snapshot(factory)
    if factory_before != _read_regular(factory, "Factory configuration"):
        raise ValueError("Factory configuration changed while loading the deployment snapshot")
    if len(snapshot.file_inventory) != len(snapshot.snapshot_bytes):
        raise ValueError("Factory snapshot inventory and bytes are inconsistent")
    for item, expected_bytes in zip(snapshot.file_inventory, snapshot.snapshot_bytes, strict=True):
        governed = factory.parent / item["path"]
        current = _read_regular(governed, "Governed factory configuration")
        if current != expected_bytes or hashlib.sha256(current).hexdigest() != item["sha256"]:
            raise ValueError("Governed factory configuration changed during snapshot acquisition")
    configured_identity = cast(dict[str, str], environment_config["deployment_identity"])
    snapshot_identity = (snapshot.client_id, snapshot.deployment_id, snapshot.environment_id)
    if (
        tuple(configured_identity[key] for key in ("client_id", "deployment_id", "environment_id"))
        != snapshot_identity
    ):
        raise ValueError("Environment contract identity does not match the factory snapshot")
    return snapshot, environment_config, environment_bytes


def _plan_path(request: EnvironmentPlanRequest, environment_id: str) -> Path:
    run_id = _safe_id(request.run_id, "run_id")
    attempt_id = _safe_id(request.attempt_id, "attempt_id")
    environment = _safe_id(environment_id, "environment_id")
    return (
        request.output_root
        / "runs"
        / run_id
        / "environments"
        / environment
        / "plan-attempts"
        / attempt_id
        / _RESULT_NAME
    )


def _claims() -> dict[str, bool]:
    return {
        "provider_contacted": False,
        "authenticated": False,
        "infrastructure_mutated": False,
        "environment_ready": False,
        "source_ready": False,
        "generated": False,
        "executed": False,
        "validated": False,
        "reconciled": False,
        "parity_passed": False,
        "migration_complete": False,
        "promoted": False,
        "certified": False,
        "human_approved": False,
        "lifecycle_closed": False,
    }


_PROBE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "workspace": (),
    "catalog": ("workspace",),
    "volumes": ("catalog",),
    "compute": ("workspace",),
    "git": ("workspace",),
    "vault": ("workspace",),
    "ai_gateway": ("vault",),
    "packages": ("volumes",),
    "sas_programs": ("volumes",),
    "sas7bdat": ("volumes",),
    "source_system": ("workspace",),
}


def _probe_states(config: dict[str, Any]) -> dict[str, str]:
    sources = cast(dict[str, Any], config["sources"])
    return {
        "workspace": str(cast(dict[str, Any], config["workspace"])["state"]),
        "catalog": str(cast(dict[str, Any], config["unity_catalog"])["state"]),
        "volumes": str(cast(dict[str, Any], config["volumes"])["state"]),
        "compute": str(cast(dict[str, Any], config["compute"])["state"]),
        "git": str(cast(dict[str, Any], config["git"])["state"]),
        "vault": str(cast(dict[str, Any], config["vault"])["state"]),
        "ai_gateway": str(cast(dict[str, Any], config["ai_gateway"])["state"]),
        "packages": str(cast(dict[str, Any], config["packages"])["state"]),
        "sas_programs": str(sources["sas_program_state"]),
        "sas7bdat": str(sources["sas7bdat_state"]),
        "source_system": str(sources["source_system_state"]),
    }


def _evaluate_environment_plan_current(request: EnvironmentPlanRequest) -> PreparedEnvironmentPlan:
    """Derive an offline plan. This function performs no provider or network operation."""

    _safe_id(request.run_id, "run_id")
    _safe_id(request.attempt_id, "attempt_id")
    snapshot, config, raw = _load_inputs(request)
    identity = cast(dict[str, str], config["deployment_identity"])
    policy = cast(dict[str, Any], config["probe_policy"])
    blockers: list[dict[str, str]] = []
    probes: list[dict[str, Any]] = []
    mode = str(config["mode"])
    states = _probe_states(config)
    for kind, dependencies in _PROBE_DEPENDENCIES.items():
        item = cast(dict[str, Any], policy[kind])
        state = states[kind]
        required = bool(item["required"])
        write_scope = str(item["write_scope"])
        blocker: str | None = None
        if required and state != "active":
            blocker = (
                "required_reference_denied" if state == "denied" else "required_reference_pending"
            )
        elif mode == "customer_validate" and write_scope == "scoped_internal":
            blocker = "customer_mode_write_scope_forbidden"
        elif state == "active" and any(
            states[dependency] != "active" for dependency in dependencies
        ):
            blocker = "reference_dependency_unresolved"
        if blocker is not None:
            blockers.append({"code": blocker, "reference_id": kind})
        probes.append(
            {
                "probe_id": f"probe-{kind}",
                "kind": kind,
                "reference_id": kind,
                "required": required,
                "timeout_seconds": item["timeout_seconds"],
                "max_retries": item["max_retries"],
                "max_evidence_age_seconds": item["max_evidence_age_seconds"],
                "write_scope": write_scope,
                "dependencies": list(dependencies),
                "disposition": (
                    "blocked"
                    if blocker is not None
                    else ("planned" if state == "active" else "omitted")
                ),
                "remediation": (
                    "remove_customer_write_scope"
                    if blocker == "customer_mode_write_scope_forbidden"
                    else (
                        "resolve_reference_dependencies"
                        if blocker == "reference_dependency_unresolved"
                        else (
                            "resolve_denial"
                            if blocker == "required_reference_denied"
                            else ("supply_reference" if blocker is not None else "none")
                        )
                    )
                ),
                "provider_operation": False,
            }
        )
    blockers.sort(key=lambda item: (item["reference_id"], item["code"]))
    probes.sort(key=lambda item: str(item["probe_id"]))
    status = "blocked" if blockers else "complete"
    environment_configuration_digest = hashlib.sha256(raw).hexdigest()
    policy_digest = _digest(policy)
    implementation_manifest = _implementation_manifest()
    evidence_reference = (
        _plan_path(request, snapshot.environment_id).relative_to(request.output_root).as_posix()
    )
    plan_identity = {
        **identity,
        "mode": mode,
        "factory_configuration_digest": snapshot.configuration_digest,
        "factory_bundle_digest": snapshot.bundle_digest,
        "environment_configuration_digest": environment_configuration_digest,
        "policy_digest": policy_digest,
        "implementation_manifest_digest": _digest(implementation_manifest),
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
    }
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "plan_id": f"DBENVPLAN-{_digest(plan_identity)[:24]}",
        "identity": plan_identity,
        "implementation_manifest": implementation_manifest,
        "policy": policy,
        "planned_probes": probes,
        "blockers": blockers,
        "status": status,
        "terminal_disposition": status,
        "retry": {
            "retryable": status == "blocked",
            "recovery_count": 0,
            "recovery_source": None,
        },
        "canonical_evidence_reference": evidence_reference,
        "claims": _claims(),
        "content_digest": "",
    }
    result["content_digest"] = _digest(result)
    _verify_result_self_consistency(result)
    telemetry = _telemetry_from_verified_result(result)
    return PreparedEnvironmentPlan(result=result, telemetry=telemetry)


def evaluate_environment_plan(request: EnvironmentPlanRequest) -> PreparedEnvironmentPlan:
    """Evaluate current governed inputs without publishing or contacting a provider."""

    return _evaluate_environment_plan_current(request)


def _verify_result_self_consistency(result: dict[str, Any]) -> None:
    _validate("environment-plan-result.schema.json", result)
    supplied = result["content_digest"]
    candidate = {**result, "content_digest": ""}
    if supplied != _digest(candidate):
        raise ValueError("Environment-plan result digest mismatch")
    identity = cast(dict[str, Any], result["identity"])
    expected_id = f"DBENVPLAN-{_digest(identity)[:24]}"
    if result["plan_id"] != expected_id or result["claims"] != _claims():
        raise ValueError("Environment-plan canonical identity or claims are invalid")
    current_manifest = _implementation_manifest()
    if result["implementation_manifest"] != current_manifest or identity[
        "implementation_manifest_digest"
    ] != _digest(current_manifest):
        raise ValueError("Environment-plan implementation manifest is stale or invalid")
    if identity["policy_digest"] != _digest(result["policy"]):
        raise ValueError("Environment-plan policy digest mismatch")
    blockers = cast(list[dict[str, str]], result["blockers"])
    probes = cast(list[dict[str, Any]], result["planned_probes"])
    blocked = bool(blockers)
    expected_status = "blocked" if blocked else "complete"
    retry = cast(dict[str, Any], result["retry"])
    if (
        result["status"] != expected_status
        or result["terminal_disposition"] != expected_status
        or retry
        != {
            "retryable": blocked,
            "recovery_count": 0,
            "recovery_source": None,
        }
    ):
        raise ValueError("Environment-plan disposition or retry metadata is inconsistent")
    probe_ids = [str(item["probe_id"]) for item in probes]
    reference_ids = {str(item["reference_id"]) for item in probes}
    if len(probe_ids) != len(set(probe_ids)) or any(
        item["provider_operation"] is not False for item in probes
    ):
        raise ValueError("Environment-plan probe identity or operation claim is invalid")
    by_reference = {str(item["reference_id"]): item for item in probes}
    if set(by_reference) != set(_PROBE_DEPENDENCIES):
        raise ValueError("Environment-plan probe inventory is incomplete")
    policy = cast(dict[str, Any], result["policy"])
    for kind, dependencies in _PROBE_DEPENDENCIES.items():
        probe = by_reference[kind]
        governed_policy = cast(dict[str, Any], policy[kind])
        if (
            probe["probe_id"] != f"probe-{kind}"
            or probe["kind"] != kind
            or probe["dependencies"] != list(dependencies)
            or any(
                probe[field] != governed_policy[field]
                for field in (
                    "required",
                    "timeout_seconds",
                    "max_retries",
                    "max_evidence_age_seconds",
                    "write_scope",
                )
            )
        ):
            raise ValueError("Environment-plan probe does not replay from governed policy")
    if any(item["reference_id"] not in reference_ids for item in blockers):
        raise ValueError("Environment-plan blocker is not bound to a planned probe")
    blocked_references = {item["reference_id"] for item in blockers}
    if any(
        (item["reference_id"] in blocked_references) != (item["disposition"] == "blocked")
        for item in probes
    ):
        raise ValueError("Environment-plan probe and blocker dispositions disagree")
    if identity["mode"] == "customer_validate" and any(
        item["write_scope"] == "scoped_internal" and item["disposition"] != "blocked"
        for item in probes
    ):
        raise ValueError("Environment-plan customer write scope is not blocked")


def _telemetry_from_verified_result(result: dict[str, Any]) -> dict[str, Any]:
    identity = cast(dict[str, Any], result["identity"])
    payload = {
        "schema_version": "1.0",
        "plan_id": result["plan_id"],
        "client_id": identity["client_id"],
        "deployment_id": identity["deployment_id"],
        "environment_id": identity["environment_id"],
        "run_id": identity["run_id"],
        "attempt_id": identity["attempt_id"],
        "status": result["status"],
        "blocked": result["status"] == "blocked",
        "planned_probe_count": len(result["planned_probes"]),
        "blocker_count": len(result["blockers"]),
        "claims": result["claims"],
        "result_digest": result["content_digest"],
    }
    _validate("environment-plan-telemetry.schema.json", payload)
    return payload


def verify_environment_plan(request: EnvironmentPlanRequest, result: dict[str, Any]) -> None:
    """Verify exact equality with a deterministic re-evaluation of current governed inputs."""

    _verify_result_self_consistency(result)
    expected = _evaluate_environment_plan_current(request)
    if result != expected.result:
        raise ValueError("Environment plan does not match current governed inputs")


def telemetry_from_environment_plan(
    request: EnvironmentPlanRequest, result: dict[str, Any]
) -> dict[str, Any]:
    """Derive telemetry only after request-bound verification against current inputs."""

    verify_environment_plan(request, result)
    return _telemetry_from_verified_result(result)


def _current_input_binding(request: EnvironmentPlanRequest) -> dict[str, Any]:
    snapshot, config, raw = _load_inputs(request)
    manifest = _implementation_manifest()
    return {
        "client_id": snapshot.client_id,
        "deployment_id": snapshot.deployment_id,
        "environment_id": snapshot.environment_id,
        "mode": config["mode"],
        "factory_configuration_digest": snapshot.configuration_digest,
        "factory_bundle_digest": snapshot.bundle_digest,
        "environment_configuration_digest": hashlib.sha256(raw).hexdigest(),
        "policy_digest": _digest(config["probe_policy"]),
        "implementation_manifest_digest": _digest(manifest),
        "implementation_manifest": manifest,
    }


def _binding_from_result(result: dict[str, Any]) -> dict[str, Any]:
    identity = cast(dict[str, Any], result["identity"])
    fields = (
        "client_id",
        "deployment_id",
        "environment_id",
        "mode",
        "factory_configuration_digest",
        "factory_bundle_digest",
        "environment_configuration_digest",
        "policy_digest",
        "implementation_manifest_digest",
    )
    return {
        **{field: identity[field] for field in fields},
        "implementation_manifest": result["implementation_manifest"],
    }


def _directory_descriptor(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise ValueError("Environment-plan attempt directory is unsafe") from exc


def _rename_directory_noreplace(
    parent_descriptor: int, source_name: str, destination_name: str
) -> None:
    """Atomically promote within one directory without replacing any existing entry."""

    for name, label in ((source_name, "source"), (destination_name, "destination")):
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise ValueError(f"Unsafe environment-plan promotion {label}")
    library = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    if sys.platform == "darwin":
        try:
            operation = library.renameatx_np
        except AttributeError as exc:
            raise RuntimeError("Atomic no-replace directory promotion is unavailable") from exc
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        outcome = operation(parent_descriptor, source, parent_descriptor, destination, 0x00000004)
    elif sys.platform.startswith("linux"):
        try:
            operation = library.renameat2
        except AttributeError as exc:
            raise RuntimeError("Atomic no-replace directory promotion is unavailable") from exc
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        outcome = operation(parent_descriptor, source, parent_descriptor, destination, 0x00000001)
    else:
        raise RuntimeError("Atomic no-replace directory promotion is unsupported")
    if outcome == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(
            error,
            "Conflicting canonical environment-plan attempt appeared concurrently",
            destination_name,
        )
    raise OSError(error, os.strerror(error), destination_name)


def _quarantine_attempt(attempts_root: Path, name: str, attempt_id: str) -> Path:
    descriptor = _directory_descriptor(attempts_root)
    try:
        mode = os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_mode
        if not stat.S_ISDIR(mode):
            raise ValueError("Environment-plan attempt is symlinked or not a directory")
        rejected = f".rejected-{_safe_id(attempt_id, 'attempt_id')}-{secrets.token_hex(12)}"
        os.rename(name, rejected, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return attempts_root / rejected


def _recover_staged_attempts(attempts_root: Path, attempt_id: str) -> None:
    descriptor = _directory_descriptor(attempts_root)
    try:
        names = sorted(os.listdir(descriptor))
    finally:
        os.close(descriptor)
    prefix = f".staging-{_safe_id(attempt_id, 'attempt_id')}-"
    for name in names:
        if name.startswith(prefix):
            _quarantine_attempt(attempts_root, name, attempt_id)


def _read_attempt_pair(
    attempt_directory: Path, *, root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    if attempt_directory.is_symlink() or not attempt_directory.is_dir():
        raise ValueError("Canonical environment-plan attempt is unsafe")
    names = {item.name for item in attempt_directory.iterdir()}
    if names != {_RESULT_NAME, _TELEMETRY_NAME}:
        raise ValueError("Canonical environment-plan attempt is incomplete or has extra artifacts")
    result = read_published_json(
        attempt_directory / _RESULT_NAME, root=root, label="environment plan result"
    )
    telemetry = read_published_json(
        attempt_directory / _TELEMETRY_NAME,
        root=root,
        label="environment plan telemetry",
    )
    if not isinstance(result, dict) or not isinstance(telemetry, dict):
        raise ValueError("Canonical environment-plan attempt artifacts must be objects")
    return result, telemetry


def publish_environment_plan(
    request: EnvironmentPlanRequest, prepared: PreparedEnvironmentPlan
) -> tuple[Path, Path]:
    current = _evaluate_environment_plan_current(request)
    if prepared != current:
        raise ValueError("Environment-plan inputs changed after evaluation")
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    identity = cast(dict[str, Any], current.result["identity"])
    result_path = _plan_path(request, str(identity["environment_id"]))
    if not result_path.is_absolute():
        result_path = Path(os.path.abspath(os.fspath(result_path)))
    if not result_path.is_relative_to(root):
        raise ValueError("Environment-plan output escapes the authorized root")
    expected_reference = result_path.relative_to(root).as_posix()
    if current.result["canonical_evidence_reference"] != expected_reference:
        raise ValueError("Environment-plan result is bound to another output path")
    verify_environment_plan(request, current.result)
    canonical_directory = result_path.parent
    attempts_root = canonical_directory.parent
    ensure_directory(attempts_root, root=root)
    _recover_staged_attempts(attempts_root, request.attempt_id)
    telemetry_path = canonical_directory / _TELEMETRY_NAME

    if canonical_directory.exists():
        try:
            canonical, telemetry = _read_attempt_pair(canonical_directory, root=root)
        except ValueError:
            _quarantine_attempt(attempts_root, canonical_directory.name, request.attempt_id)
        else:
            verify_environment_plan(request, canonical)
            if canonical != prepared.result or telemetry != prepared.telemetry:
                raise FileExistsError("Conflicting canonical environment-plan attempt")
            return result_path, telemetry_path

    staging_name = f".staging-{request.attempt_id}-{secrets.token_hex(12)}"
    staging_directory = attempts_root / staging_name
    descriptor = _directory_descriptor(attempts_root)
    try:
        os.mkdir(staging_name, mode=0o700, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    promoted = False
    try:
        staged_result = staging_directory / _RESULT_NAME
        staged_telemetry = staging_directory / _TELEMETRY_NAME
        publish_json(staged_result, prepared.result, "staged environment plan result", root=root)
        publish_json(
            staged_telemetry,
            prepared.telemetry,
            "staged environment plan telemetry",
            root=root,
        )
        staged_pair = _read_attempt_pair(staging_directory, root=root)
        if staged_pair != (prepared.result, prepared.telemetry):
            raise ValueError("Staged environment-plan pair differs from prepared evidence")
        staged_current = _evaluate_environment_plan_current(request)
        if staged_current != prepared:
            raise ValueError("Environment-plan inputs changed after staging")
        verify_environment_plan(request, staged_current.result)
        if _current_input_binding(request) != _binding_from_result(prepared.result):
            raise ValueError("Environment-plan inputs changed before attempt promotion")

        descriptor = _directory_descriptor(attempts_root)
        try:
            _rename_directory_noreplace(
                descriptor,
                staging_name,
                canonical_directory.name,
            )
            promoted = True
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        promoted_current = _evaluate_environment_plan_current(request)
        if promoted_current != prepared or _current_input_binding(request) != _binding_from_result(
            prepared.result
        ):
            _quarantine_attempt(attempts_root, canonical_directory.name, request.attempt_id)
            promoted = False
            raise ValueError("Environment-plan inputs changed after attempt promotion")
        canonical, telemetry = _read_attempt_pair(canonical_directory, root=root)
        verify_environment_plan(request, canonical)
        if (
            canonical != prepared.result
            or telemetry != prepared.telemetry
            or _current_input_binding(request) != _binding_from_result(prepared.result)
        ):
            _quarantine_attempt(attempts_root, canonical_directory.name, request.attempt_id)
            promoted = False
            raise ValueError("Promoted environment-plan pair failed final verification")
        return result_path, telemetry_path
    except Exception:
        try:
            if promoted and os.path.lexists(canonical_directory):
                _quarantine_attempt(attempts_root, canonical_directory.name, request.attempt_id)
            elif not promoted and os.path.lexists(staging_directory):
                _quarantine_attempt(attempts_root, staging_name, request.attempt_id)
        except Exception as quarantine_error:
            raise ValueError(
                "Environment-plan publication failed and its attempt could not be quarantined"
            ) from quarantine_error
        raise


def recover_environment_plan(request: EnvironmentPlanRequest) -> PreparedEnvironmentPlan | None:
    """Recover a missing projection from immutable canonical evidence."""

    root = Path(os.path.abspath(os.fspath(request.output_root)))
    snapshot, _, _ = _load_inputs(request)
    result_path = _plan_path(request, snapshot.environment_id)
    if not result_path.is_absolute():
        result_path = Path(os.path.abspath(os.fspath(result_path)))
    if not result_path.exists():
        return None
    canonical = read_published_json(result_path, root=root, label="environment plan result")
    if not isinstance(canonical, dict):
        raise ValueError("Canonical environment-plan result is not an object")
    verify_environment_plan(request, canonical)
    if canonical["canonical_evidence_reference"] != result_path.relative_to(root).as_posix():
        raise ValueError("Environment-plan evidence is stored at the wrong canonical path")
    expected = _evaluate_environment_plan_current(request)
    if canonical != expected.result:
        raise ValueError("Canonical environment plan does not replay from current governed inputs")
    telemetry_path = result_path.with_name(_TELEMETRY_NAME)
    if telemetry_path.exists():
        stored = read_published_json(telemetry_path, root=root, label="environment plan telemetry")
        if stored != expected.telemetry:
            raise ValueError("Environment-plan telemetry mutation detected")
        return None
    # The result itself is immutable; recovery metadata is telemetry-only and must not rewrite it.
    return PreparedEnvironmentPlan(result=canonical, telemetry=expected.telemetry)
