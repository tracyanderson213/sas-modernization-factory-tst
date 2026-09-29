"""Sanitized lifecycle projection; readiness never asserts downstream success."""

from __future__ import annotations

from typing import Any

from smf.readiness.models import ReadinessResult


def readiness_event_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Project bounded telemetry from a validated canonical manifest payload."""

    human_assisted = any(
        item["check_id"] == "human-approval"
        and item["status"] == "pass"
        and bool(item["evidence_ids"])
        for item in payload["checks"]
    )
    return {
        "event_type": "workload_readiness_completed",
        "stage": "readiness",
        "outcome": str(payload["classification"]).lower(),
        "workload_id": payload["workload_id"],
        "boundary_id": payload["boundary_id"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "readiness_result_id": payload["result_id"],
        "policy_version": payload["policy_version"],
        "policy_digest": payload["policy_digest"],
        "elapsed_ms": payload["elapsed_ms"],
        "blockers": [
            {"category": item["category"], "owner": item["owner"]} for item in payload["blockers"]
        ],
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": human_assisted,
        "blocked": payload["classification"] != "READY",
        "prerequisite_states": {
            item["prerequisite_id"]: item["state"] for item in payload["prerequisite_checklist"]
        },
    }


def readiness_event(result: ReadinessResult) -> dict[str, Any]:
    return readiness_event_from_payload(result.to_dict())
