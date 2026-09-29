"""Append-only workload-complexity publication and replay validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from smf.assessment.workload_attestation import workload_result_digest
from smf.assessment.workload_schema import validate_workload_complexity_result

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _component(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}")
    return value


def _safe_source(root: Path, relative: str) -> Path:
    if not relative or urlparse(relative).scheme:
        raise ValueError("Unsafe workload complexity source reference")
    decoded = relative
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    path = Path(decoded)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Unsafe workload complexity source reference")
    resolved_root = root.resolve()
    has_symlink = any(
        root.joinpath(*path.parts[:index]).is_symlink() for index in range(1, len(path.parts) + 1)
    )
    resolved = (root / path).resolve()
    if has_symlink or not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError("Workload complexity source reference escapes or is missing")
    return resolved


def reverify_workload_complexity_sources(payload: dict[str, Any], source_root: Path) -> None:
    for artifact in payload["artifacts"]:
        path = _safe_source(source_root, artifact["source_uri"])
        data = path.read_bytes()
        if (
            len(data) != artifact["size_bytes"]
            or hashlib.sha256(data).hexdigest() != artifact["sha256"]
        ):
            raise ValueError("Qualified workload complexity source bytes changed")


def workload_complexity_path(
    output_root: Path, run_id: str, workload_id: str, attempt_id: str, boundary_id: str
) -> Path:
    return (
        output_root
        / "runs"
        / _component(run_id, "run_id")
        / "workloads"
        / _component(workload_id, "workload_id")
        / "attempts"
        / _component(attempt_id, "attempt_id")
        / "complexity"
        / _component(boundary_id, "boundary_id")
        / "result.json"
    )


def load_workload_complexity_result(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Workload complexity result must be an object")
    validate_workload_complexity_result(raw)
    if raw["result_digest"] != workload_result_digest(raw):
        raise ValueError("Workload complexity result digest mismatch")
    observation_ids = [item["observation_id"] for item in raw["observations"]]
    canonical_ids = [item["canonical_identity"] for item in raw["observations"]]
    if len(observation_ids) != len(set(observation_ids)) or len(canonical_ids) != len(
        set(canonical_ids)
    ):
        raise ValueError("Duplicate workload complexity observation identity")
    return raw


def _publish(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing == payload:
            return
        raise FileExistsError(f"Workload complexity artifact already exists: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".workload-complexity-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if existing != payload:
                raise FileExistsError(
                    f"Workload complexity artifact already exists: {path}"
                ) from None
    finally:
        temporary.unlink(missing_ok=True)


def _explanation(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "assessment_id": payload["assessment_id"],
        "result_digest": payload["result_digest"],
        "policy_digest": payload["policy_digest"],
        "tier": payload["tier"],
        "score": payload["score"],
        "unknowns": payload["unknowns"],
        "blockers": payload["blockers"],
        "sensitivity": payload["sensitivity"],
        "dimensions": [
            {
                key: item[key]
                for key in (
                    "dimension_id",
                    "status",
                    "contribution",
                    "cap",
                    "cap_applied",
                )
            }
            for item in payload["dimensions"]
        ],
    }


def write_workload_complexity_result(
    output_root: Path, payload: dict[str, Any], *, source_root: Path
) -> Path:
    validate_workload_complexity_result(payload)
    if payload["result_digest"] != workload_result_digest(payload):
        raise ValueError("Workload complexity result digest mismatch")
    reverify_workload_complexity_sources(payload, source_root)
    path = workload_complexity_path(
        output_root,
        payload["run_id"],
        payload["workload_id"],
        payload["attempt_id"],
        payload["boundary_id"],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.parent.resolve().is_relative_to(output_root.resolve()):
        raise ValueError("Workload complexity output path escapes root")
    if path.exists():
        canonical = load_workload_complexity_result(path)
        if canonical != payload:
            raise FileExistsError(f"Workload complexity decision already exists: {path}")
    else:
        _publish(path, payload)
        canonical = load_workload_complexity_result(path)
    _publish(path.with_name("explanation.json"), _explanation(canonical))
    return path
