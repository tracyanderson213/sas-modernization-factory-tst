from dataclasses import replace

import pytest

from smf.discovery.boundaries import derive_workload_boundaries
from smf.discovery.downstream import derive_downstream_outputs
from smf.discovery.lineage import derive_data_lineage
from smf.modernization.disposition import derive_modernization_disposition_inputs
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DatasetKind,
    DispositionCandidate,
    DispositionDecisionStatus,
    DispositionInputSource,
    EvidenceMethod,
    ModernizationDisposition,
    ModernizationDispositionInput,
    RelationshipKind,
)


def _workload_with_boundary():
    builder = WorkloadBuilder(name="claims")
    evidence = builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="claims.sas",
        confidence=Confidence.HIGH,
        locator="claims.sas",
    )
    program = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM,
        name="claims.sas",
        logical_path="claims.sas",
        evidence=(evidence,),
    )
    dataset = builder.add_dataset(
        name="CLAIMS.OUT", kind=DatasetKind.SAS_DATASET, evidence=(evidence,)
    )
    builder.add_relationship(
        source_id=program.artifact_id,
        kind=RelationshipKind.WRITES,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
    )
    workload = derive_data_lineage(builder.build())
    workload = derive_downstream_outputs(workload)
    return derive_workload_boundaries(workload)


def test_discovery_creates_unresolved_input_without_autonomous_disposition():
    workload = derive_modernization_disposition_inputs(_workload_with_boundary())

    assert len(workload.disposition_inputs) == 1
    item = workload.disposition_inputs[0]
    assert item.boundary_id == workload.boundaries[0].boundary_id
    assert item.decision_status is DispositionDecisionStatus.UNRESOLVED
    assert item.selected_disposition is None
    assert item.candidates == ()
    assert item.metadata["selected_by_discovery"] is False
    assert item.metadata["output_count"] == 0
    assert item.metadata["unresolved_output_consumer_count"] == 0
    assert workload.metadata["modernization_disposition"]["governed_selection_required"] is True


def test_disposition_input_identity_is_stable():
    workload = _workload_with_boundary()
    first = derive_modernization_disposition_inputs(workload)
    second = derive_modernization_disposition_inputs(workload)
    assert (
        first.disposition_inputs[0].disposition_input_id
        == second.disposition_inputs[0].disposition_input_id
    )


@pytest.mark.parametrize("disposition", list(ModernizationDisposition))
def test_model_accepts_every_governed_disposition(disposition):
    candidate = DispositionCandidate(
        candidate_id=f"candidate-{disposition.value}",
        disposition=disposition,
        rationale="Explicit assessment or governed decision rationale.",
        confidence=Confidence.MEDIUM,
        source=DispositionInputSource.ASSESSMENT,
    )
    item = ModernizationDispositionInput(
        disposition_input_id="MDI-test",
        boundary_id="BND-test",
        candidates=(candidate,),
    )
    assert item.candidates[0].disposition is disposition


def test_selection_is_explicit_and_can_be_confirmed_without_rewriting_discovery():
    workload = derive_modernization_disposition_inputs(_workload_with_boundary())
    original = workload.disposition_inputs[0]
    confirmed = replace(
        original,
        selected_disposition=ModernizationDisposition.CONSOLIDATE,
        decision_status=DispositionDecisionStatus.CONFIRMED,
        rationale="Architecture review confirmed duplicate business capability.",
    )
    assert original.selected_disposition is None
    assert original.decision_status is DispositionDecisionStatus.UNRESOLVED
    assert confirmed.selected_disposition is ModernizationDisposition.CONSOLIDATE
    assert confirmed.decision_status is DispositionDecisionStatus.CONFIRMED
