from smf.modernization.manifest import derive_target_state_manifest
from smf.workload.models import (
    BatchIncrementalOpportunity,
    Confidence,
    DatabricksPatternMapping,
    DatabricksTargetPattern,
    DispositionDecisionStatus,
    IntermediateArtifactEliminationOpportunity,
    MigrationWaveGroup,
    ModernizationDisposition,
    ModernizationDispositionInput,
    TargetStatePatternInput,
    Workload,
    WorkloadBoundary,
)


def _workload(*, confirmed: bool = True) -> Workload:
    boundary = WorkloadBoundary(boundary_id="b-1", name="one")
    disposition = ModernizationDispositionInput(
        disposition_input_id="di-1",
        boundary_id="b-1",
        selected_disposition=ModernizationDisposition.CONVERT if confirmed else None,
        decision_status=(
            DispositionDecisionStatus.CONFIRMED
            if confirmed
            else DispositionDecisionStatus.UNRESOLVED
        ),
    )
    target = TargetStatePatternInput(
        pattern_input_id="tpi-1",
        boundary_id="b-1",
        disposition_input_id="di-1",
        selected_disposition=disposition.selected_disposition,
        disposition_status=disposition.decision_status,
        unresolved_items=() if confirmed else ("boundary_confirmation:b-1",),
    )
    return Workload(
        workload_id="w-1",
        name="w",
        boundaries=(boundary,),
        disposition_inputs=(disposition,),
        target_state_pattern_inputs=(target,),
        migration_wave_groups=(MigrationWaveGroup(wave_group_id="wg-1", boundary_ids=("b-1",)),),
        databricks_pattern_mappings=(
            DatabricksPatternMapping(
                mapping_id="map-1",
                boundary_id="b-1",
                pattern=DatabricksTargetPattern.BATCH_SPARK,
                blocker_ids=("DBX-BLOCKER-X",),
            ),
        ),
        batch_incremental_opportunities=(
            BatchIncrementalOpportunity(
                opportunity_id="inc-1",
                boundary_id="b-1",
                blocker_ids=("INC-BLOCKER-X",),
            ),
        ),
        intermediate_artifact_elimination_opportunities=(
            IntermediateArtifactEliminationOpportunity(
                opportunity_id="int-1",
                boundary_id="b-1",
                dataset_id="d-1",
                confidence=Confidence.LOW,
                blocker_ids=("INT-BLOCKER-X",),
            ),
        ),
    )


def test_builds_one_plan_per_boundary():
    result = derive_target_state_manifest(_workload())
    assert result.target_state_manifest is not None
    assert [x.boundary_id for x in result.target_state_manifest.boundary_plans] == ["b-1"]


def test_preserves_confirmed_disposition_without_selecting_new_one():
    plan = derive_target_state_manifest(_workload()).target_state_manifest.boundary_plans[0]
    assert plan.disposition is ModernizationDisposition.CONVERT
    assert plan.disposition_status is DispositionDecisionStatus.CONFIRMED


def test_unresolved_disposition_remains_unresolved():
    plan = derive_target_state_manifest(
        _workload(confirmed=False)
    ).target_state_manifest.boundary_plans[0]
    assert plan.disposition is None
    assert "disposition:b-1" in plan.unresolved_items


def test_references_databricks_candidates_by_stable_id():
    plan = derive_target_state_manifest(_workload()).target_state_manifest.boundary_plans[0]
    assert plan.databricks_pattern_mapping_ids == ("map-1",)
    assert plan.metadata["architecture_selected"] is False


def test_references_relative_wave_group_without_calendar_assignment():
    plan = derive_target_state_manifest(_workload()).target_state_manifest.boundary_plans[0]
    assert plan.migration_wave_group_id == "wg-1"
    assert plan.metadata["calendar_wave_assigned"] is False


def test_references_modernization_opportunities():
    plan = derive_target_state_manifest(_workload()).target_state_manifest.boundary_plans[0]
    assert plan.incremental_opportunity_ids == ("inc-1",)
    assert plan.intermediate_elimination_opportunity_ids == ("int-1",)


def test_aggregates_candidate_and_opportunity_blockers():
    plan = derive_target_state_manifest(_workload()).target_state_manifest.boundary_plans[0]
    assert set(plan.blocker_ids) == {"DBX-BLOCKER-X", "INC-BLOCKER-X", "INT-BLOCKER-X"}


def test_missing_target_input_is_explicit_gap():
    w = _workload()
    w = Workload(
        workload_id=w.workload_id,
        name=w.name,
        boundaries=w.boundaries,
        disposition_inputs=w.disposition_inputs,
    )
    plan = derive_target_state_manifest(w).target_state_manifest.boundary_plans[0]
    assert "target_state_input:b-1" in plan.unresolved_items


def test_identity_and_output_are_deterministic_on_rerun():
    first = derive_target_state_manifest(_workload())
    second = derive_target_state_manifest(first)
    assert first.target_state_manifest == second.target_state_manifest


def test_empty_workload_produces_empty_portable_manifest_without_invention():
    result = derive_target_state_manifest(Workload(workload_id="w", name="w"))
    manifest = result.target_state_manifest
    assert manifest is not None
    assert manifest.boundary_plans == ()
    assert manifest.metadata["automatic_decision"] is False
    assert manifest.metadata["rationale_stage"] == "MOD-10"
