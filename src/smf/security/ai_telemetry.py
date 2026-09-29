"""Telemetry derived only from canonical AI-context admission evidence."""

from __future__ import annotations

from typing import Any


def ai_context_event(result: dict[str, Any]) -> dict[str, Any]:
    request = result["request"]
    blocked = result["state"] != "qualified_offline"
    return {
        "event_type": "ai_context_admission_completed",
        "stage": "ai_context_admission",
        "decision_id": result["decision_id"],
        "client_id": request["client_id"],
        "workload_id": request["workload_id"],
        "run_id": request["run_id"],
        "attempt_id": request["attempt_id"],
        "provider_id": request["provider_id"],
        "model_id": request["model_id"],
        "outcome": result["state"],
        "blocker_codes": result["blocker_codes"],
        "context_qualified": result["context_qualified"],
        "submission_authorized": False,
        "transport_attempted": False,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": False,
        "blocked": blocked,
    }
