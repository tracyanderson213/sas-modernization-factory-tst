"""Append-only publication and idempotent telemetry recovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from smf.immutable_files import ensure_directory, publish_bytes, read_published_json
from smf.migration_contract.engine import telemetry_from_result, verify_result
from smf.migration_contract.models import MigrationContractRequest, PreparedMigrationResult
from smf.migration_contract.schema import validate_schema


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _publish_exclusive(path: Path, content: bytes, *, root: Path) -> None:
    try:
        publish_bytes(path, content, "migration contract artifact", root=root)
    except (FileExistsError, ValueError) as exc:
        raise ValueError(f"Conflicting immutable artifact: {path.name}") from exc


def publish_result(
    output_root: Path, result: dict[str, Any], telemetry: dict[str, Any]
) -> tuple[Path, Path]:
    verify_result(result)
    reference = Path(result["canonical_evidence_reference"])
    if reference.is_absolute() or ".." in reference.parts:
        raise ValueError("Canonical evidence reference escapes the output root")
    root = Path(os.path.abspath(os.fspath(output_root)))
    result_path = root / reference
    ensure_directory(result_path.parent, root=root)
    if not result_path.is_relative_to(root):
        raise ValueError("Canonical result path escapes the output root")
    if result_path.name != "migration-cli.result.json":
        raise ValueError("Canonical result filename is invalid")
    _publish_exclusive(result_path, _canonical_bytes(result), root=root)
    canonical = read_published_json(result_path, root=root, label="migration contract result")
    if not isinstance(canonical, dict):
        raise ValueError("Canonical migration result is not an object")
    verify_result(canonical)
    derived = telemetry_from_result(canonical)
    if derived != telemetry:
        raise ValueError("Telemetry was not derived from the canonical result")
    validate_schema("migration-cli-telemetry.schema.json", derived)
    telemetry_path = result_path.with_name("migration-cli.telemetry.json")
    _publish_exclusive(telemetry_path, _canonical_bytes(derived), root=root)
    return result_path, telemetry_path


def recover_missing_telemetry(
    request: MigrationContractRequest,
) -> PreparedMigrationResult | None:
    """Recover a missing projection from a canonical attempt without rereading producer inputs."""

    segments = ["runs", request.run_id]
    if request.workload_id is not None:
        segments.extend(["workloads", request.workload_id])
    root = request.output_root.resolve()
    attempts_root = root / Path(*segments) / "contract-attempts"
    expected = {
        "command": request.command.value,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "workload_id": request.workload_id,
        "action_target": request.action_target,
    }

    if request.attempt_id is not None:
        result_paths = [attempts_root / request.attempt_id / "migration-cli.result.json"]
    else:
        if not attempts_root.exists():
            return None
        if attempts_root.is_symlink() or not attempts_root.is_dir():
            raise ValueError("Canonical recovery path is unsafe")
        result_paths = []
        for child in attempts_root.iterdir():
            if child.is_symlink() or not child.is_dir():
                raise ValueError("Canonical recovery path is unsafe")
            result_paths.append(child / "migration-cli.result.json")
        result_paths.sort(key=lambda path: path.as_posix())

    matches: list[tuple[Path, dict[str, Any]]] = []
    for result_path in result_paths:
        if not result_path.exists():
            continue
        if (
            result_path.is_symlink()
            or not result_path.is_file()
            or not result_path.resolve().is_relative_to(root)
        ):
            raise ValueError("Canonical recovery path is unsafe")
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Canonical migration result is not an object")
        verify_result(payload)
        if payload["canonical_evidence_reference"] != result_path.relative_to(root).as_posix():
            raise ValueError("Canonical result is stored at the wrong evidence reference")
        identity = payload["identity"]
        if all(identity[key] == value for key, value in expected.items()):
            matches.append((result_path, payload))

    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("Multiple canonical results match the recovery request")
    result_path, payload = matches[0]
    telemetry_path = result_path.with_name("migration-cli.telemetry.json")
    if telemetry_path.exists():
        if telemetry_path.is_symlink() or not telemetry_path.is_file():
            raise ValueError("Canonical telemetry path is unsafe")
        return None
    return PreparedMigrationResult(result=payload, telemetry=telemetry_from_result(payload))
