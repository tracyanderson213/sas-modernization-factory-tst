"""Append-only, validated readiness manifest persistence."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from smf.readiness.engine import evaluate_readiness
from smf.readiness.models import ReadinessRequest, ReadinessResult
from smf.readiness.policy import digest_value, readiness_policy_from_dict
from smf.readiness.schema import (
    validate_input_schema,
    validate_policy_schema,
    validate_result_schema,
)
from smf.readiness.telemetry import readiness_event_from_payload

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _component(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}")
    return value


def manifest_path(output_root: Path, run_id: str, workload_id: str, attempt_id: str) -> Path:
    return (
        output_root
        / "runs"
        / _component(run_id, "run_id")
        / "workloads"
        / _component(workload_id, "workload_id")
        / "attempts"
        / _component(attempt_id, "attempt_id")
        / "readiness.manifest.json"
    )


def _validate_digest(payload: dict[str, Any]) -> None:
    expected = payload.get("content_digest")
    unsigned = dict(payload)
    unsigned.pop("content_digest", None)
    if expected != digest_value(unsigned):
        raise ValueError("Readiness manifest content digest mismatch")


def _validate_qualification(payload: dict[str, Any], *, result_root: Path | None = None) -> None:
    qualifying = payload["qualification_input"]
    validate_input_schema(qualifying)
    for field in ("workload_id", "run_id", "attempt_id", "boundary_id"):
        source = (
            qualifying["workload"]["workload_id"] if field == "workload_id" else qualifying[field]
        )
        if payload[field] != source:
            raise ValueError(f"Readiness manifest qualification {field} mismatch")
    if payload["workload_digest"] != digest_value(qualifying["workload"]):
        raise ValueError("Readiness manifest workload digest mismatch")
    validate_policy_schema(payload["policy_snapshot"])
    if payload["policy_digest"] != digest_value(payload["policy_snapshot"]):
        raise ValueError("Readiness manifest policy snapshot digest mismatch")
    if payload["policy_id"] != payload["policy_snapshot"]["policy_id"]:
        raise ValueError("Readiness manifest policy_id mismatch")
    if payload["policy_version"] != payload["policy_snapshot"]["policy_version"]:
        raise ValueError("Readiness manifest policy_version mismatch")
    digest_input = {
        "workload": qualifying["workload"],
        "evidence": qualifying["evidence"],
        "policy_digest": payload["policy_digest"],
    }
    if "result_artifacts" in qualifying:
        digest_input["result_artifacts"] = qualifying["result_artifacts"]
    expected_input_digest = digest_value(digest_input)
    if payload["input_digest"] != expected_input_digest:
        raise ValueError("Readiness manifest input digest mismatch")
    references = {item["evidence_id"]: item for item in payload["evidence_references"]}
    evidence = {item["evidence_id"]: item for item in qualifying["evidence"]}
    if set(references) != set(evidence) or sorted(evidence) != payload["evidence_ids"]:
        raise ValueError("Readiness manifest evidence inventory mismatch")
    if any(
        references[evidence_id]["evidence_digest"] != digest_value(item)
        for evidence_id, item in evidence.items()
    ):
        raise ValueError("Readiness manifest evidence digest mismatch")

    try:
        evaluated_at = datetime.fromisoformat(str(payload["evaluated_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Readiness manifest evaluated_at is invalid") from exc
    if evaluated_at.tzinfo is None:
        raise ValueError("Readiness manifest evaluated_at must be timezone-aware")
    policy = readiness_policy_from_dict(payload["policy_snapshot"])
    replayed = evaluate_readiness(
        ReadinessRequest(
            workload=qualifying["workload"],
            evidence=tuple(qualifying["evidence"]),
            run_id=qualifying["run_id"],
            attempt_id=qualifying["attempt_id"],
            boundary_id=qualifying["boundary_id"],
            result_artifacts=tuple(qualifying.get("result_artifacts", [])),
            result_root=result_root,
        ),
        policy,
        _evaluated_at=evaluated_at,
    ).to_dict()
    decision_fields = (
        "result_id",
        "classification",
        "checks",
        "prerequisite_checklist",
        "blockers",
        "missing_evidence",
        "next_actions",
        "terminal_disposition",
        "valid_until",
        "evidence_references",
        "evidence_ids",
    )
    if any(payload[field] != replayed[field] for field in decision_fields):
        raise ValueError("Readiness manifest decision does not match deterministic qualification")


def load_manifest(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Readiness manifest must be an object")
    validate_result_schema(raw)
    _validate_digest(raw)
    try:
        result_root = path.resolve().parents[6]
    except IndexError as exc:
        raise ValueError("Readiness manifest path is outside the canonical run hierarchy") from exc
    _validate_qualification(raw, result_root=result_root)
    return raw


def telemetry_path(manifest: Path) -> Path:
    return manifest.with_name("readiness.telemetry.json")


def _publish_json(path: Path, payload: dict[str, Any], label: str) -> None:
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing == payload:
            return
        raise FileExistsError(f"Readiness {label} already exists: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".readiness-{label}-", dir=path.parent)
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
                raise FileExistsError(f"Readiness {label} already exists: {path}") from None
    finally:
        if temporary.exists():
            temporary.unlink()


def write_manifest(output_root: Path, result: ReadinessResult) -> Path:
    path = manifest_path(output_root, result.run_id, result.workload_id, result.attempt_id)
    payload = result.to_dict()
    validate_result_schema(payload)
    _validate_digest(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    root = output_root.resolve()
    if not path.parent.resolve().is_relative_to(root):
        raise ValueError("Readiness manifest path escapes output root")
    if path.exists():
        existing = load_manifest(path)
        identity_fields = (
            "result_id",
            "workload_id",
            "boundary_id",
            "run_id",
            "attempt_id",
            "policy_digest",
            "input_digest",
        )
        if any(existing[field] != payload[field] for field in identity_fields):
            raise FileExistsError(f"Readiness attempt already exists: {path}")
        canonical = existing
    else:
        _publish_json(path, payload, "manifest")
        canonical = load_manifest(path)
    # Production persistence always includes the bounded competition projection.
    # A retry can repair a missing event after an interrupted first publication.
    _publish_json(telemetry_path(path), readiness_event_from_payload(canonical), "telemetry event")
    return path
