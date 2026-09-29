"""Safe telemetry derived from canonical AI transport results."""

from __future__ import annotations

from typing import Any


def ai_transport_event(result: dict[str, Any]) -> dict[str, Any]:
    request = result["request"]
    return {
        "event_type": "ai_transport_completed",
        "stage": "ai_transport",
        "decision_id": result["decision_id"],
        "client_id": request["client_id"],
        "workload_id": request["workload_id"],
        "run_id": request["run_id"],
        "attempt_id": request["workflow_attempt_id"],
        "provider_request_id": request["provider_request_id"],
        "transport_attempt_id": request["transport_attempt_id"],
        "retry_ordinal": request["retry_ordinal"],
        "provider_id": request["provider_id"],
        "model_id": request["model_id"],
        "endpoint_binding_id": request["endpoint_binding_id"],
        "transport_policy_digest": request["transport_policy_digest"],
        "endpoint_binding_digest": request["endpoint_binding_digest"],
        "outcome": result["state"],
        "blocker_codes": result["blocker_codes"],
        "elapsed_ms": result["elapsed_ms"],
        "context_qualified": result["context_qualified"],
        "submission_authorized": result["submission_authorized"],
        "transport_attempted": result["transport_attempted"],
        "response_received": result["response_received"],
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": result["human_assisted"],
        "blocked": result["state"] != "response_received",
    }
