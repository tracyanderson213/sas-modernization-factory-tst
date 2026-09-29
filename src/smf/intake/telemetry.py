"""Truthful projections from authoritative batch-intake decisions."""

from __future__ import annotations

from typing import Any


def intake_telemetry(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event": "batch_intake_evaluated",
        "result_id": payload["result_id"],
        "client_id": payload["client_id"],
        "batch_revision_id": payload["batch_revision_id"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "expected_script_count": payload["expected_script_count"],
        "observed_unique_script_count": payload["observed_unique_script_count"],
        "admitted_count": payload["admitted_count"],
        "blocked_count": payload["blocked_count"],
        "unprocessable_count": payload["unprocessable_count"],
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": False,
        "blocked": payload["disposition"] != "admitted",
    }
