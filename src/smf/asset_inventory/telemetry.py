"""Truthful telemetry projection for BASE-07 inventory attempts."""

from __future__ import annotations

from typing import Any


def asset_inventory_event(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event": "asset_inventory_evaluated",
        "inventory_result_id": result["inventory_result_id"],
        "client_id": result["client_id"],
        "workload_id": result["workload_id"],
        "run_id": result["run_id"],
        "attempt_id": result["attempt_id"],
        "inventory_generated": result["claims"]["inventory_generated"],
        "production_inventory": False,
        "complete": False,
        "blocked": bool(result["blockers"]),
        "blocker_count": len(result["blockers"]),
        "item_count": len(result["items"]),
        "human_assisted": False,
    }
