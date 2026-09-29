"""Offline, governed resolution of logical datasets to environment target namespaces.

BASE-03 deliberately resolves names only.  It does not contact a catalog, authorize a
principal, create a table, or establish customer-environment readiness.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from smf.immutable_files import ensure_directory, publish_json, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.strict_yaml import load_unique_yaml
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LOGICAL_DATASET = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}\.[A-Za-z_][A-Za-z0-9_]{0,127}$")
_NAMESPACE_PART = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RESULT_NAME = "target-resolution.result.json"
_TELEMETRY_NAME = "target-resolution.telemetry.json"


@dataclass(frozen=True)
class TargetResolutionRequest:
    config_root: Path
    config_path: Path
    output_root: Path
    client_id: str
    deployment_id: str
    environment_id: str
    environment_class: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    artifact_id: str
    logical_dataset: str
    access_mode: str
    evaluation_time: str

    def binding(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("config_root")
        payload.pop("config_path")
        root = Path(os.path.abspath(os.fspath(self.config_root)))
        path = Path(os.path.abspath(os.fspath(self.config_path)))
        try:
            reference = path.relative_to(root)
        except ValueError as exc:
            raise ValueError("Target-resolution configuration escapes its authorized root") from exc
        if not reference.parts or ".." in reference.parts:
            raise ValueError("Target-resolution configuration reference is unsafe")
        payload["configuration_reference"] = reference.as_posix()
        payload.pop("output_root")
        return payload


@dataclass(frozen=True)
class PreparedTargetResolution:
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
        raise ValueError(f"Target-resolution schema validation failed: {detail}")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _safe_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or contains_protected_data(value)
    ):
        raise ValueError(f"Unsafe target-resolution {label}")
    return value


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValueError(f"Target-resolution {label} must use canonical UTC RFC3339")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"Target-resolution {label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"Target-resolution {label} must use canonical UTC RFC3339")
    return parsed


def _open_directory(parent_fd: int, component: str, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"{label} contains a symlink or non-directory component") from exc


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _read_regular(root: Path, path: Path, label: str) -> bytes:
    if ".." in root.parts or ".." in path.parts:
        raise ValueError(f"{label} contains traversal")
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    absolute_path = Path(os.path.abspath(os.fspath(path)))
    try:
        relative = absolute_path.relative_to(absolute_root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the authorized configuration root") from exc
    if not relative.parts:
        raise ValueError(f"{label} must be a file below the authorized configuration root")

    directory = os.open(absolute_root.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in (*absolute_root.parts[1:], *relative.parts[:-1]):
            replacement = _open_directory(directory, component, label)
            os.close(directory)
            directory = replacement
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(relative.name, flags, dir_fd=directory)
        except OSError as exc:
            raise ValueError(f"{label} is symlinked, missing, or unsafe") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"{label} is not a regular file")
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            after = os.fstat(descriptor)
            try:
                current = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
            except OSError as exc:
                raise ValueError(f"{label} changed while being acquired") from exc
            if not stat.S_ISREG(current.st_mode) or not (
                _stat_identity(before) == _stat_identity(after) == _stat_identity(current)
            ):
                raise ValueError(f"{label} changed while being acquired")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/target_resolution.py", files("smf").joinpath("target_resolution.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        *(
            (f"smf/schemas/{name}", files("smf.schemas").joinpath(name))
            for name in (
                "target-resolution-config.schema.json",
                "target-resolution-result.schema.json",
                "target-resolution-telemetry.schema.json",
            )
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def load_target_resolution_config(
    path: Path, *, root: Path | None = None
) -> tuple[dict[str, Any], bytes]:
    """Load strict configuration and reject ambiguous or colliding bindings."""

    raw = _read_regular(root or path.parent, path, "Target-resolution configuration")
    try:
        payload = load_unique_yaml(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Target-resolution configuration is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError("Target-resolution configuration must be an object")
    _validate("target-resolution-config.schema.json", payload)
    if contains_protected_data(raw.decode("utf-8")):
        raise ValueError("Target-resolution configuration contains protected material")

    identity = cast(dict[str, Any], payload["deployment_identity"])
    for field in ("client_id", "deployment_id", "environment_id"):
        _safe_id(identity[field], field)
    _safe_id(payload["policy_id"], "policy_id")
    _safe_id(payload["policy_version"], "policy_version")
    authority = cast(dict[str, Any], payload["authority"])
    _safe_id(authority["authority_reference"], "authority_reference")
    qualified_at = _time(authority["qualified_at"], "qualified_at")
    valid_until = _time(authority["valid_until"], "valid_until")
    if valid_until <= qualified_at:
        raise ValueError("Target-resolution authority interval is invalid")

    logical_names: set[str] = set()
    qualified_names: set[str] = set()
    binding_ids: set[str] = set()
    for binding in payload["bindings"]:
        item = cast(dict[str, Any], binding)
        for field in ("binding_id", "binding_version", "authority_reference"):
            _safe_id(item[field], field)
        logical = cast(str, item["logical_dataset"])
        if not _LOGICAL_DATASET.fullmatch(logical):
            raise ValueError("Target-resolution logical dataset is invalid")
        for field in ("catalog", "schema", "table"):
            if not _NAMESPACE_PART.fullmatch(cast(str, item[field])):
                raise ValueError(f"Target-resolution {field} is invalid")
        logical_folded = logical.casefold()
        qualified_folded = ".".join(
            cast(str, item[field]).casefold() for field in ("catalog", "schema", "table")
        )
        binding_folded = cast(str, item["binding_id"]).casefold()
        if logical_folded in logical_names or qualified_folded in qualified_names:
            raise ValueError("Target-resolution configuration contains a case collision")
        if binding_folded in binding_ids:
            raise ValueError("Target-resolution configuration contains a binding-id collision")
        logical_names.add(logical_folded)
        qualified_names.add(qualified_folded)
        binding_ids.add(binding_folded)
        if item["environment_id"] != identity["environment_id"]:
            raise ValueError("Target-resolution binding crosses environment identity")
        if item["environment_class"] != payload["environment_class"]:
            raise ValueError("Target-resolution binding crosses environment class")
    return payload, raw


def _validate_request(request: TargetResolutionRequest) -> dict[str, Any]:
    for field in (
        "client_id",
        "deployment_id",
        "environment_id",
        "workload_id",
        "source_id",
        "run_id",
        "attempt_id",
        "artifact_id",
    ):
        _safe_id(getattr(request, field), field)
    if request.environment_class not in {"evaluation", "production"}:
        raise ValueError("Target-resolution environment_class is invalid")
    if request.access_mode not in {"read", "write"}:
        raise ValueError("Target-resolution access_mode is invalid")
    if not _LOGICAL_DATASET.fullmatch(request.logical_dataset):
        raise ValueError("Target-resolution logical_dataset is invalid")
    _time(request.evaluation_time, "evaluation_time")
    return request.binding()


def evaluate_target_resolution(request: TargetResolutionRequest) -> PreparedTargetResolution:
    binding = _validate_request(request)
    config, raw = load_target_resolution_config(request.config_path, root=request.config_root)
    identity = cast(dict[str, Any], config["deployment_identity"])
    for field in ("client_id", "deployment_id", "environment_id"):
        if binding[field] != identity[field]:
            raise ValueError(f"Target-resolution request {field} does not match configuration")
    if request.environment_class != config["environment_class"]:
        raise ValueError("Target-resolution request crosses environment class")

    blockers: list[dict[str, str]] = []
    authority = cast(dict[str, Any], config["authority"])
    evaluation_time = _time(request.evaluation_time, "evaluation_time")
    qualified_at = _time(authority["qualified_at"], "qualified_at")
    valid_until = _time(authority["valid_until"], "valid_until")
    if authority["state"] != "active":
        blockers.append({"code": "namespace_authority_pending", "state": "pending"})
    if qualified_at > evaluation_time:
        blockers.append({"code": "namespace_authority_not_yet_valid", "state": "blocked"})
    if valid_until <= evaluation_time:
        blockers.append({"code": "namespace_authority_stale", "state": "blocked"})

    candidates = [
        cast(dict[str, Any], item)
        for item in config["bindings"]
        if cast(str, item["logical_dataset"]).casefold() == request.logical_dataset.casefold()
    ]
    resolution: dict[str, Any] | None = None
    if not candidates:
        blockers.append({"code": "logical_dataset_binding_missing", "state": "blocked"})
    elif len(candidates) != 1:
        blockers.append({"code": "logical_dataset_binding_ambiguous", "state": "blocked"})
    else:
        selected = candidates[0]
        if request.logical_dataset != selected["logical_dataset"]:
            blockers.append({"code": "logical_dataset_case_mismatch", "state": "blocked"})
        if request.access_mode not in selected["access_modes"]:
            blockers.append({"code": "target_access_mode_denied", "state": "blocked"})
        if not blockers:
            qualified_name = ".".join(
                cast(str, selected[field]) for field in ("catalog", "schema", "table")
            )
            resolution = {
                "binding_id": selected["binding_id"],
                "binding_version": selected["binding_version"],
                "logical_dataset": selected["logical_dataset"],
                "catalog": selected["catalog"],
                "schema": selected["schema"],
                "table": selected["table"],
                "qualified_name": qualified_name,
                "environment_id": selected["environment_id"],
                "environment_class": selected["environment_class"],
                "namespace_source": selected["namespace_source"],
                "authority_reference": selected["authority_reference"],
                "access_mode": request.access_mode,
            }

    implementation = _implementation_manifest()
    result_identity = {
        **binding,
        "configuration_digest": hashlib.sha256(raw).hexdigest(),
        "implementation_digest": _digest(implementation),
        "policy_id": config["policy_id"],
        "policy_version": config["policy_version"],
    }
    status = "resolved" if resolution is not None else "blocked"
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "base-03.1.0",
        "result_id": "pending",
        "content_digest": "",
        "canonical_evidence_reference": (
            f"runs/{request.run_id}/workloads/{request.workload_id}/"
            f"target-resolution-attempts/{request.attempt_id}/{_RESULT_NAME}"
        ),
        "identity": result_identity,
        "status": status,
        "terminal_disposition": "qualified_offline" if resolution else "blocked",
        "resolution": resolution,
        "blockers": blockers,
        "implementation_manifest": implementation,
        "claims": {
            "live_catalog_contacted": False,
            "target_exists": False,
            "access_authorized": False,
            "write_performed": False,
            "humana_ready": False,
            "production_ready": False,
            "migration_complete": False,
            "semantic_parity": False,
        },
    }
    result["result_id"] = stable_id("B03RES", _decision_identity(result))
    result["content_digest"] = _digest({k: v for k, v in result.items() if k != "content_digest"})
    _validate("target-resolution-result.schema.json", result)
    telemetry = telemetry_from_result(result)
    return PreparedTargetResolution(result=result, telemetry=telemetry)


def telemetry_from_result(result: dict[str, Any]) -> dict[str, Any]:
    telemetry = {
        "schema_version": "1.0",
        "result_id": result["result_id"],
        "status": result["status"],
        "terminal_disposition": result["terminal_disposition"],
        "blocker_codes": [item["code"] for item in result["blockers"]],
        "claims": result["claims"],
    }
    _validate("target-resolution-telemetry.schema.json", telemetry)
    return telemetry


def verify_target_resolution(result: dict[str, Any]) -> None:
    _validate("target-resolution-result.schema.json", result)
    expected = _digest({k: v for k, v in result.items() if k != "content_digest"})
    if result["content_digest"] != expected:
        raise ValueError("Target-resolution content digest is invalid")
    if result["result_id"] != stable_id("B03RES", _decision_identity(result)):
        raise ValueError("Target-resolution governed decision identity is invalid")
    if any(result["claims"].values()):
        raise ValueError("Target-resolution result contains an operational claim")
    if result["implementation_manifest"] != _implementation_manifest():
        raise ValueError("Target-resolution implementation manifest does not match runtime")
    if (result["status"] == "resolved") != (result["resolution"] is not None):
        raise ValueError("Target-resolution status and resolution disagree")


def _decision_identity(result: dict[str, Any]) -> dict[str, Any]:
    """Bind the complete governed decision while avoiding digest/ID recursion."""

    return {
        key: value for key, value in result.items() if key not in {"result_id", "content_digest"}
    }


def publish_target_resolution(
    request: TargetResolutionRequest, prepared: PreparedTargetResolution
) -> tuple[Path, Path]:
    replayed = evaluate_target_resolution(request)
    if replayed != prepared:
        raise ValueError("Prepared target resolution does not match current governed inputs")
    verify_target_resolution(prepared.result)
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    reference = Path(prepared.result["canonical_evidence_reference"])
    if reference.is_absolute() or ".." in reference.parts:
        raise ValueError("Target-resolution evidence reference escapes output root")
    result_path = root / reference
    ensure_directory(result_path.parent, root=root)
    publish_json(result_path, prepared.result, "target-resolution result", root=root)
    canonical = read_published_json(result_path, root=root, label="target-resolution result")
    if not isinstance(canonical, dict):
        raise ValueError("Canonical target-resolution result is not an object")
    verify_target_resolution(canonical)
    telemetry = telemetry_from_result(canonical)
    if telemetry != prepared.telemetry:
        raise ValueError("Target-resolution telemetry is not derived from canonical result")
    telemetry_path = result_path.with_name(_TELEMETRY_NAME)
    publish_json(telemetry_path, telemetry, "target-resolution telemetry", root=root)
    return result_path, telemetry_path


def recover_target_resolution(
    request: TargetResolutionRequest,
) -> PreparedTargetResolution | None:
    """Recover only a missing telemetry projection from current-input replay."""

    replayed = evaluate_target_resolution(request)
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    result_path = root / Path(replayed.result["canonical_evidence_reference"])
    telemetry_path = result_path.with_name(_TELEMETRY_NAME)
    if not result_path.exists() or telemetry_path.exists():
        return None
    payload = read_published_json(result_path, root=root, label="target-resolution result")
    if not isinstance(payload, dict):
        raise ValueError("Canonical target-resolution result is not an object")
    verify_target_resolution(payload)
    if payload != replayed.result:
        raise ValueError("Canonical target resolution does not match current governed inputs")
    return PreparedTargetResolution(payload, telemetry_from_result(payload))
