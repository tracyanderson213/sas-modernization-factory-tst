"""Append-only pilot-selection publication, replay, and recovery."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from smf.pilot.models import PilotSelectionRequest, PilotSelectionResult
from smf.pilot.policy import pilot_policy_from_dict
from smf.pilot.schema import validate_result
from smf.pilot.selection import evaluate_pilot_selection
from smf.pilot.telemetry import selection_telemetry
from smf.readiness.policy import digest_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _component(value: str, label: str) -> str:
    if value in {".", ".."} or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"Unsafe {label}")
    return value


def manifest_path(output_root: Path, run_id: str, selection_id: str, attempt_id: str) -> Path:
    return (
        output_root
        / "runs"
        / _component(run_id, "run_id")
        / "pilot-selections"
        / _component(selection_id, "selection_id")
        / "attempts"
        / _component(attempt_id, "attempt_id")
        / "selection.manifest.json"
    )


def _publish(path: Path, payload: dict[str, Any], label: str) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    if path.exists():
        if path.read_bytes() == encoded:
            return
        raise FileExistsError(
            f"Pilot selection {label} already exists with different bytes: {path}"
        )
    descriptor, name = tempfile.mkstemp(prefix=f".pilot-{label}-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != encoded:
                raise FileExistsError(f"Pilot selection {label} publication collision") from None
    finally:
        temporary.unlink(missing_ok=True)


def _validate_content(payload: dict[str, Any]) -> None:
    unsigned = dict(payload)
    expected = unsigned.pop("content_digest", None)
    if expected != digest_value(unsigned):
        raise ValueError("Pilot selection manifest content digest mismatch")


def load_manifest(path: Path, *, inventory_root: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Pilot selection manifest must be an object")
    validate_result(raw)
    _validate_content(raw)
    for filename, field in (
        ("inventory.snapshot.json", "inventory_snapshot"),
        ("policy.snapshot.json", "policy_snapshot"),
    ):
        snapshot_path = path.with_name(filename)
        if (
            not snapshot_path.is_file()
            or json.loads(snapshot_path.read_text(encoding="utf-8")) != raw[field]
        ):
            raise ValueError(f"Pilot selection {filename} binding mismatch")
    policy = pilot_policy_from_dict(raw["policy_snapshot"])
    replay = evaluate_pilot_selection(
        PilotSelectionRequest(
            inventory=raw["inventory_snapshot"],
            policy=policy,
            inventory_root=inventory_root,
            run_id=raw["run_id"],
            attempt_id=raw["attempt_id"],
        ),
        evaluated_at=datetime.fromisoformat(raw["evaluated_at"]),
    ).to_dict()
    if replay != raw:
        raise ValueError("Pilot selection manifest does not match deterministic replay")
    return raw


def write_manifest(
    output_root: Path, result: PilotSelectionResult, *, inventory_root: Path
) -> Path:
    path = manifest_path(output_root, result.run_id, result.selection_id, result.attempt_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.parent.resolve().is_relative_to(output_root.resolve()):
        raise ValueError("Pilot selection output path escapes output root")
    payload = result.to_dict()
    validate_result(payload)
    _validate_content(payload)
    _publish(
        path.with_name("inventory.snapshot.json"), result.inventory_snapshot, "inventory snapshot"
    )
    _publish(path.with_name("policy.snapshot.json"), result.policy_snapshot, "policy snapshot")
    if path.exists():
        existing = load_manifest(path, inventory_root=inventory_root)
        identity = ("selection_id", "inventory_digest", "policy_digest", "run_id", "attempt_id")
        if any(existing[key] != payload[key] for key in identity):
            raise FileExistsError(f"Pilot selection attempt already exists: {path}")
    else:
        _publish(path, payload, "manifest")
    canonical = load_manifest(path, inventory_root=inventory_root)
    _publish(
        path.with_name("selection.telemetry.json"), selection_telemetry(canonical), "telemetry"
    )
    return path


def verify_selected_workload(
    path: Path,
    *,
    inventory_root: Path,
    workload_id: str,
    boundary_id: str,
    source_closure_digest: str,
    run_id: str,
    attempt_id: str,
) -> dict[str, Any]:
    """Fail-closed downstream admission adapter; selection is not readiness."""
    payload = load_manifest(path, inventory_root=inventory_root)
    if (
        payload["disposition"] != "qualified"
        or payload["run_id"] != run_id
        or payload["attempt_id"] != attempt_id
    ):
        raise ValueError("Pilot selection is not qualified for this run and attempt")
    matches = [
        item
        for item in payload["decisions"]
        if item["workload_id"] == workload_id and item["boundary_id"] == boundary_id
    ]
    if len(matches) != 1:
        raise ValueError("Pilot selection must contain exactly one requested workload identity")
    decision = matches[0]
    if decision["membership"] != "included" or decision["admission_state"] != "eligible":
        raise ValueError("Pilot workload is not included and eligible")
    if decision["source_closure_digest"] != source_closure_digest:
        raise ValueError("Pilot workload source closure changed")
    return cast(dict[str, Any], decision)
