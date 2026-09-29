"""Bounded telemetry derived only from a canonical secret receipt."""

from __future__ import annotations

from typing import Any


def secret_resolution_event(receipt: dict[str, Any]) -> dict[str, Any]:
    request = receipt["request"]
    return {
        "event_type": "secret_resolution_completed",
        "stage": "secret_resolution",
        "resolution_id": receipt["resolution_id"],
        "decision_id": receipt["decision_id"],
        "workload_id": request["workload_id"],
        "run_id": request["run_id"],
        "attempt_id": request["attempt_id"],
        "consumer_id": request["consumer_id"],
        "provider": receipt["provider"],
        "outcome": receipt["state"],
        "reason_code": receipt["reason_code"],
        "transport_attempted": receipt["transport_attempted"],
        "retryable": receipt["retryable"],
        "elapsed_ms": receipt["elapsed_ms"],
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "blocked": receipt["state"] != "resolved",
    }
