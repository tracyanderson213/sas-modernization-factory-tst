from dataclasses import replace

from smf.discovery.boundaries import derive_workload_boundaries
from smf.discovery.downstream import derive_downstream_outputs
from smf.discovery.lineage import derive_data_lineage
from smf.modernization.disposition import derive_modernization_disposition_inputs
from smf.modernization.target_state import derive_target_state_pattern_inputs
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DatasetKind,
    DispositionDecisionStatus,
    EvidenceMethod,
    ModernizationDisposition,
    RelationshipKind,
    TargetDataBehavior,
    TargetExecutionBehavior,
)


def _workload():
    builder = WorkloadBuilder(name="claims")
    evidence = builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS, source="claims.sas", confidence=Confidence.HIGH
    )
    program = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM, name="claims.sas", evidence=(evidence,)
    )
    shell = builder.add_artifact(
        kind=ArtifactKind.SHELL_SCRIPT, name="run.sh", evidence=(evidence,)
    )
    dataset = builder.add_dataset(
        name="CLAIMS.OUT", kind=DatasetKind.INTERMEDIATE, evidence=(evidence,)
    )
    builder.add_relationship(
        source_id=shell.artifact_id,
        kind=RelationshipKind.TRIGGERS,
        target_id=program.artifact_id,
        evidence=(evidence,),
    )
    builder.add_relationship(
        source_id=program.artifact_id,
        kind=RelationshipKind.READS,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
    )
    builder.add_relationship(
        source_id=program.artifact_id,
        kind=RelationshipKind.WRITES,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
    )
    workload = derive_data_lineage(builder.build())
    workload = derive_downstream_outputs(workload)
    workload = derive_workload_boundaries(workload)
    return derive_modernization_disposition_inputs(workload)


def test_creates_one_pattern_input_per_boundary_without_selecting_target_pattern():
    workload = derive_target_state_pattern_inputs(_workload())
    assert len(workload.target_state_pattern_inputs) == len(workload.boundaries) == 1
    item = workload.target_state_pattern_inputs[0]
    assert item.metadata["target_pattern_selected"] is False
    assert workload.metadata["target_state_pattern_inputs"]["target_pattern_selected_count"] == 0
    assert (
        workload.metadata["target_state_pattern_inputs"]["recommendation_engine_required"] is True
    )


def test_pattern_input_identity_is_stable():
    workload = _workload()
    first = derive_target_state_pattern_inputs(workload)
    second = derive_target_state_pattern_inputs(workload)
    assert (
        first.target_state_pattern_inputs[0].pattern_input_id
        == second.target_state_pattern_inputs[0].pattern_input_id
    )


def test_carries_disposition_contract_without_inventing_selection():
    workload = derive_target_state_pattern_inputs(_workload())
    item = workload.target_state_pattern_inputs[0]
    disposition = workload.disposition_inputs[0]
    assert item.disposition_input_id == disposition.disposition_input_id
    assert item.selected_disposition is None
    assert item.disposition_status is DispositionDecisionStatus.UNRESOLVED


def test_explicit_governed_disposition_flows_into_pattern_input():
    workload = _workload()
    confirmed = replace(
        workload.disposition_inputs[0],
        selected_disposition=ModernizationDisposition.CONVERT,
        decision_status=DispositionDecisionStatus.CONFIRMED,
    )
    workload = replace(workload, disposition_inputs=(confirmed,))
    item = derive_target_state_pattern_inputs(workload).target_state_pattern_inputs[0]
    assert item.selected_disposition is ModernizationDisposition.CONVERT
    assert item.disposition_status is DispositionDecisionStatus.CONFIRMED


def test_normalizes_execution_and_data_characteristics_from_canonical_facts():
    item = derive_target_state_pattern_inputs(_workload()).target_state_pattern_inputs[0]
    assert TargetExecutionBehavior.SCRIPT_DRIVEN in item.execution_behaviors
    assert TargetDataBehavior.READS_DATA in item.data_behaviors
    assert TargetDataBehavior.WRITES_DATA in item.data_behaviors
    assert TargetDataBehavior.PRODUCES_OUTPUT not in item.data_behaviors
    assert TargetDataBehavior.USES_INTERMEDIATE in item.data_behaviors


def test_unknown_execution_behavior_remains_unknown():
    workload = _workload()
    boundary = workload.boundaries[0]
    sas_only = tuple(a for a in workload.artifacts if a.kind is ArtifactKind.SAS_PROGRAM)
    workload = replace(
        workload,
        artifacts=sas_only,
        boundaries=(replace(boundary, artifact_ids=(sas_only[0].artifact_id,)),),
    )
    item = derive_target_state_pattern_inputs(workload).target_state_pattern_inputs[0]
    assert item.execution_behaviors == (TargetExecutionBehavior.UNKNOWN,)


def test_unconfirmed_consumer_and_boundary_are_preserved_as_unresolved():
    item = derive_target_state_pattern_inputs(_workload()).target_state_pattern_inputs[0]
    assert not any(value.startswith("output_consumer:") for value in item.unresolved_items)
    assert any(value.startswith("boundary_confirmation:") for value in item.unresolved_items)
    assert item.metadata["consumer_resolution_complete"] is True


def test_relationship_kinds_are_normalized_for_later_recommendation_logic():
    item = derive_target_state_pattern_inputs(_workload()).target_state_pattern_inputs[0]
    assert RelationshipKind.TRIGGERS in item.relationship_kinds
    assert RelationshipKind.READS in item.relationship_kinds
    assert RelationshipKind.WRITES in item.relationship_kinds


def test_serialization_includes_pattern_inputs_without_target_recommendation():
    workload = derive_target_state_pattern_inputs(_workload())
    payload = workload.to_dict()
    assert len(payload["target_state_pattern_inputs"]) == 1
    assert payload["target_state_pattern_inputs"][0]["metadata"]["target_pattern_selected"] is False
