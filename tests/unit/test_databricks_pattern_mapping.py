from dataclasses import replace

from smf.modernization.databricks_patterns import derive_databricks_pattern_mappings
from smf.workload.models import (
    BatchIncrementalOpportunity,
    Confidence,
    DatabricksTargetPattern,
    DispositionDecisionStatus,
    ModernizationDisposition,
    TargetDataBehavior,
    TargetExecutionBehavior,
    TargetStatePatternInput,
    Workload,
)


def _workload(*, confirmed=False, incremental=False):
    item = TargetStatePatternInput(
        pattern_input_id="tpi-1",
        boundary_id="b-1",
        execution_behaviors=(TargetExecutionBehavior.SCHEDULED,),
        data_behaviors=(
            TargetDataBehavior.READS_DATA,
            TargetDataBehavior.WRITES_DATA,
            TargetDataBehavior.PRODUCES_OUTPUT,
        ),
        selected_disposition=ModernizationDisposition.CONVERT if confirmed else None,
        disposition_status=DispositionDecisionStatus.CONFIRMED
        if confirmed
        else DispositionDecisionStatus.UNRESOLVED,
        unresolved_items=() if confirmed else ("boundary_confirmation:b-1",),
    )
    opportunities = ()
    if incremental:
        opportunities = (
            BatchIncrementalOpportunity(
                opportunity_id="bio-1",
                boundary_id="b-1",
                confidence=Confidence.LOW,
                signal_ids=("INCREMENTAL-SCHEDULED-BATCH",),
                blocker_ids=("INCREMENTAL-BLOCKER-CHANGE-CAPTURE-NOT-ESTABLISHED",),
            ),
        )
    return Workload(
        workload_id="w-1",
        name="w",
        target_state_pattern_inputs=(item,),
        batch_incremental_opportunities=opportunities,
    )


def test_maps_scheduled_execution_to_workflow_job_candidate():
    result = derive_databricks_pattern_mappings(_workload())
    assert DatabricksTargetPattern.WORKFLOW_JOB in {
        x.pattern for x in result.databricks_pattern_mappings
    }


def test_maps_read_write_transformation_to_batch_spark_candidate():
    result = derive_databricks_pattern_mappings(_workload())
    assert DatabricksTargetPattern.BATCH_SPARK in {
        x.pattern for x in result.databricks_pattern_mappings
    }


def test_maps_persisted_output_to_delta_table_candidate():
    result = derive_databricks_pattern_mappings(_workload())
    assert DatabricksTargetPattern.DELTA_TABLE in {
        x.pattern for x in result.databricks_pattern_mappings
    }


def test_incremental_opportunity_adds_incremental_pipeline_candidate():
    result = derive_databricks_pattern_mappings(_workload(incremental=True))
    item = next(
        x
        for x in result.databricks_pattern_mappings
        if x.pattern is DatabricksTargetPattern.INCREMENTAL_PIPELINE
    )
    assert "INCREMENTAL-BLOCKER-CHANGE-CAPTURE-NOT-ESTABLISHED" in item.blocker_ids
    assert item.confidence is Confidence.LOW


def test_unconfirmed_disposition_is_preserved_as_blocker():
    result = derive_databricks_pattern_mappings(_workload())
    assert all(
        "DBX-BLOCKER-DISPOSITION-NOT-CONFIRMED" in x.blocker_ids
        for x in result.databricks_pattern_mappings
    )


def test_confirmed_convert_removes_disposition_blocker():
    result = derive_databricks_pattern_mappings(_workload(confirmed=True))
    assert all(
        "DBX-BLOCKER-DISPOSITION-NOT-CONFIRMED" not in x.blocker_ids
        for x in result.databricks_pattern_mappings
    )


def test_non_databricks_disposition_blocks_implementation_mapping():
    w = _workload(confirmed=True)
    item = replace(
        w.target_state_pattern_inputs[0], selected_disposition=ModernizationDisposition.RETIRE
    )
    w = replace(w, target_state_pattern_inputs=(item,))
    result = derive_databricks_pattern_mappings(w)
    assert all(
        "DBX-BLOCKER-DISPOSITION-NOT-DATABRICKS-IMPLEMENTATION" in x.blocker_ids
        for x in result.databricks_pattern_mappings
    )


def test_mapping_never_claims_feasibility_or_semantic_equivalence():
    result = derive_databricks_pattern_mappings(_workload(confirmed=True))
    assert all(
        x.metadata["target_feasibility_established"] is False
        for x in result.databricks_pattern_mappings
    )
    assert all(
        x.metadata["semantic_equivalence_established"] is False
        for x in result.databricks_pattern_mappings
    )


def test_identity_is_stable_and_rerun_replaces_results():
    first = derive_databricks_pattern_mappings(_workload())
    second = derive_databricks_pattern_mappings(first)
    assert [x.mapping_id for x in first.databricks_pattern_mappings] == [
        x.mapping_id for x in second.databricks_pattern_mappings
    ]


def test_empty_pattern_inputs_produce_no_invented_mapping():
    result = derive_databricks_pattern_mappings(Workload(workload_id="w", name="w"))
    assert result.databricks_pattern_mappings == ()
    assert result.metadata["databricks_target_pattern_mapping"]["automatic_selection"] is False
