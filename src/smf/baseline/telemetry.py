"""Truthful, bounded baseline acquisition telemetry."""

from __future__ import annotations

from typing import Any

from smf.baseline.schema import validate_telemetry


def baseline_event(result: dict[str, Any]) -> dict[str, Any]:
    acquired = result["disposition"] == "acquired"
    mode = result["acquisition_mode"]
    payload = {
        "schema_version": "1.0",
        "event": "baseline_acquisition_completed",
        "baseline_result_id": result["baseline_result_id"],
        "acquisition_id": result["acquisition_id"],
        "client_id": result["client_id"],
        "workload_id": result["workload_id"],
        "workload_revision_id": result["workload_revision_id"],
        "boundary_id": result["boundary_id"],
        "run_id": result["run_id"],
        "attempt_id": result["attempt_id"],
        "disposition": result["disposition"],
        "baseline_acquired": acquired,
        "acquisition_mode": mode,
        "sas_execution_performed": acquired and mode == "sas_execution",
        "sas_execution_verified": acquired,
        "export_imported": acquired and mode == "approved_export",
        "provenance_verified": acquired,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": result["human_intervention"],
        "blocked": result["disposition"] == "blocked",
        "blocker_reason": result["blockers"][0] if result["blockers"] else None,
    }
    validate_telemetry(payload)
    return payload
