"""Bounded projections derived only from a canonical selection manifest."""

from __future__ import annotations

from typing import Any


def selection_telemetry(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_type": "pilot_selection_completed",
        "stage": "pilot_selection",
        "selection_id": payload["selection_id"],
        "client_id": payload["client_id"],
        "inventory_id": payload["inventory_id"],
        "inventory_digest": payload["inventory_digest"],
        "policy_id": payload["policy_id"],
        "policy_digest": payload["policy_digest"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "full_inventory_denominator": payload["full_inventory_denominator"],
        "outcome": payload["disposition"],
        "blocked": payload["disposition"] != "qualified",
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
        "human_assisted": False,
        "candidates": [
            {
                "workload_id": item["workload_id"],
                "boundary_id": item["boundary_id"],
                "source_closure_digest": item["source_closure_digest"],
                "membership": item["membership"],
                "admission_state": item["admission_state"],
                "reasons": item["reasons"],
                "owners": item["owners"],
            }
            for item in payload["decisions"]
        ],
    }
