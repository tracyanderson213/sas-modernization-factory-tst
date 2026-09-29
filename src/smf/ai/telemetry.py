"""Safe telemetry projection from canonical provider results."""

from __future__ import annotations

from typing import Any


def ai_provider_event(result: dict[str, Any]) -> dict[str, Any]:
    request = result["request"]
    return {
        "event_type": "ai_provider_completed",
        "stage": "ai_provider",
        "decision_id": result["decision_id"],
        "client_id": request["client_id"],
        "workload_id": request["workload_id"],
        "run_id": request["run_id"],
        "attempt_id": request["workflow_attempt_id"],
        "provider_request_id": request["provider_request_id"],
        "provider_attempt_id": request["provider_attempt_id"],
        "retry_ordinal": request["retry_ordinal"],
        "provider_id": request["provider_id"],
        "model_id": request["model_id"],
        "target": request["target"],
        "outcome": result["state"],
        "blocker_codes": result["blocker_codes"],
        "evidence_class": result["evidence_class"],
        "elapsed_ms": result["elapsed_ms"],
        "provider_invoked": result["provider_invoked"],
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
        "human_assisted": result["human_assisted"],
        "blocked": result["state"] != "succeeded",
    }
