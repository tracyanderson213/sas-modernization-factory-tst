"""Target-state workload manifest assembly.

MOD-09 assembles the canonical modernization planning records already produced by
prior stages into a portable workload-level target-state manifest. It does not
confirm unresolved dispositions, choose among Databricks pattern candidates, assign
calendar waves, or manufacture rationale.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    DispositionDecisionStatus,
    TargetStateBoundaryPlan,
    TargetStateWorkloadManifest,
    Workload,
)


def derive_target_state_manifest(workload: Workload) -> Workload:
    """Assemble a deterministic target-state manifest from canonical planning state."""

    dispositions = {item.boundary_id: item for item in workload.disposition_inputs}
    target_inputs = {item.boundary_id: item for item in workload.target_state_pattern_inputs}
    wave_by_boundary = {
        boundary_id: group.wave_group_id
        for group in workload.migration_wave_groups
        for boundary_id in group.boundary_ids
    }

    mappings: dict[str, list[str]] = {}
    mapping_blockers: dict[str, set[str]] = {}
    for pattern_mapping in workload.databricks_pattern_mappings:
        mappings.setdefault(pattern_mapping.boundary_id, []).append(pattern_mapping.mapping_id)
        mapping_blockers.setdefault(pattern_mapping.boundary_id, set()).update(
            pattern_mapping.blocker_ids
        )

    incremental: dict[str, list[str]] = {}
    incremental_blockers: dict[str, set[str]] = {}
    for incremental_opportunity in workload.batch_incremental_opportunities:
        incremental.setdefault(incremental_opportunity.boundary_id, []).append(
            incremental_opportunity.opportunity_id
        )
        incremental_blockers.setdefault(incremental_opportunity.boundary_id, set()).update(
            incremental_opportunity.blocker_ids
        )

    intermediate: dict[str, list[str]] = {}
    intermediate_blockers: dict[str, set[str]] = {}
    for elimination_opportunity in workload.intermediate_artifact_elimination_opportunities:
        intermediate.setdefault(elimination_opportunity.boundary_id, []).append(
            elimination_opportunity.opportunity_id
        )
        intermediate_blockers.setdefault(elimination_opportunity.boundary_id, set()).update(
            elimination_opportunity.blocker_ids
        )

    plans: list[TargetStateBoundaryPlan] = []
    manifest_unresolved: set[str] = set()
    for boundary in sorted(workload.boundaries, key=lambda item: item.boundary_id):
        disposition = dispositions.get(boundary.boundary_id)
        target_input = target_inputs.get(boundary.boundary_id)
        unresolved = set(target_input.unresolved_items if target_input else ())
        if (
            disposition is None
            or disposition.decision_status is not DispositionDecisionStatus.CONFIRMED
        ):
            unresolved.add(f"disposition:{boundary.boundary_id}")
        if target_input is None:
            unresolved.add(f"target_state_input:{boundary.boundary_id}")

        blockers = set(mapping_blockers.get(boundary.boundary_id, set()))
        blockers.update(incremental_blockers.get(boundary.boundary_id, set()))
        blockers.update(intermediate_blockers.get(boundary.boundary_id, set()))
        manifest_unresolved.update(unresolved)

        plans.append(
            TargetStateBoundaryPlan(
                boundary_id=boundary.boundary_id,
                disposition=disposition.selected_disposition if disposition else None,
                disposition_status=(
                    disposition.decision_status
                    if disposition
                    else DispositionDecisionStatus.UNRESOLVED
                ),
                databricks_pattern_mapping_ids=tuple(
                    sorted(mappings.get(boundary.boundary_id, ()))
                ),
                migration_wave_group_id=wave_by_boundary.get(boundary.boundary_id),
                incremental_opportunity_ids=tuple(
                    sorted(incremental.get(boundary.boundary_id, ()))
                ),
                intermediate_elimination_opportunity_ids=tuple(
                    sorted(intermediate.get(boundary.boundary_id, ()))
                ),
                unresolved_items=tuple(sorted(unresolved)),
                blocker_ids=tuple(sorted(blockers)),
                metadata={
                    "basis": "canonical_modernization_planning_state",
                    "architecture_selected": False,
                    "calendar_wave_assigned": False,
                    "rationale_generated": False,
                },
            )
        )

    manifest = TargetStateWorkloadManifest(
        manifest_id=stable_id("TSM", {"workload": workload.workload_id}),
        workload_id=workload.workload_id,
        boundary_plans=tuple(plans),
        unresolved_items=tuple(sorted(manifest_unresolved)),
        metadata={
            "basis": "canonical_modernization_planning_state",
            "portable_planning_contract": True,
            "automatic_decision": False,
            "architecture_selected": False,
            "calendar_waves_assigned": False,
            "rationale_stage": "MOD-10",
        },
    )
    metadata = {
        **workload.metadata,
        "target_state_workload_manifest": {
            "manifest_id": manifest.manifest_id,
            "boundary_plan_count": len(plans),
            "unresolved_item_count": len(manifest.unresolved_items),
            "automatic_decision": False,
        },
    }
    return replace(workload, target_state_manifest=manifest, metadata=metadata)
