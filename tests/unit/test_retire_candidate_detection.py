from dataclasses import replace

from smf.modernization.disposition import derive_modernization_disposition_inputs
from smf.modernization.retire import derive_retire_candidates
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    ConsumerResolution,
    DatasetKind,
    DispositionDecisionStatus,
    DispositionInputSource,
    EvidenceMethod,
    ExternalDependencyKind,
    ModernizationDisposition,
    Output,
    Relationship,
    RelationshipKind,
    WorkloadBoundary,
)


def _workload(*, resolution=ConsumerResolution.UNRESOLVED, consumers=(), confirm_boundary=False):
    builder = WorkloadBuilder(name="estate", namespace="test")
    evidence = builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="estate",
        confidence=Confidence.HIGH,
    )
    program = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM, name="a.sas", evidence=(evidence,)
    )
    dataset = builder.add_dataset(name="OUT", kind=DatasetKind.SAS_DATASET, evidence=(evidence,))
    workload = builder.build()
    output = Output(
        output_id="OUT-1",
        dataset_id=dataset.dataset_id,
        producer_ids=(program.artifact_id,),
        consumer_ids=consumers,
        consumer_resolution=resolution,
        evidence=(evidence,),
    )
    boundary = WorkloadBoundary(
        boundary_id="BND-A",
        name="A",
        artifact_ids=(program.artifact_id,),
        dataset_ids=(dataset.dataset_id,),
        output_ids=(output.output_id,),
        confidence=Confidence.HIGH,
        evidence=(evidence,),
        metadata={"requires_confirmation": not confirm_boundary},
    )
    workload = replace(workload, outputs=(output,), boundaries=(boundary,))
    return derive_modernization_disposition_inputs(workload), program.artifact_id, evidence


def _candidate(workload):
    return derive_retire_candidates(workload).disposition_inputs[0].candidates[0]


def test_adds_retire_candidate_without_selecting_or_confirming_it():
    workload, *_ = _workload()
    result = derive_retire_candidates(workload)
    item = result.disposition_inputs[0]
    candidate = item.candidates[0]
    assert candidate.disposition is ModernizationDisposition.RETIRE
    assert candidate.source is DispositionInputSource.ASSESSMENT
    assert item.selected_disposition is None
    assert item.decision_status is DispositionDecisionStatus.UNRESOLVED
    assert candidate.metadata["selected"] is False
    assert candidate.metadata["requires_confirmation"] is True


def test_unresolved_consumer_is_not_treated_as_proof_of_no_consumer():
    workload, *_ = _workload(resolution=ConsumerResolution.UNRESOLVED)
    candidate = _candidate(workload)
    assert "RETIRE-NO-OBSERVED-CONSUMERS" in candidate.metadata["supporting_rule_ids"]
    assert "RETIRE-BLOCKER-UNRESOLVED-CONSUMER" in candidate.blocker_ids
    assert candidate.confidence is Confidence.LOW


def test_partial_consumer_coverage_remains_a_blocker():
    workload, *_ = _workload(resolution=ConsumerResolution.PARTIAL)
    candidate = _candidate(workload)
    assert "RETIRE-BLOCKER-PARTIAL-CONSUMER" in candidate.blocker_ids
    assert candidate.confidence is Confidence.LOW


def test_confirmed_no_consumers_can_raise_confidence_without_auto_selection():
    workload, *_ = _workload(
        resolution=ConsumerResolution.CONFIRMED,
        confirm_boundary=True,
    )
    candidate = _candidate(workload)
    assert "RETIRE-CONFIRMED-NO-CONSUMERS" in candidate.metadata["supporting_rule_ids"]
    assert candidate.blocker_ids == ()
    assert candidate.confidence is Confidence.HIGH
    assert workload.disposition_inputs[0].selected_disposition is None


def test_observed_consumer_is_preserved_as_counter_evidence():
    workload, *_ = _workload(
        resolution=ConsumerResolution.CONFIRMED,
        consumers=("consumer-1",),
        confirm_boundary=True,
    )
    candidate = _candidate(workload)
    assert "RETIRE-COUNTER-OBSERVED-CONSUMER" in candidate.metadata["counter_evidence_rule_ids"]
    assert candidate.confidence is Confidence.LOW


def test_observed_trigger_is_counter_evidence():
    workload, program_id, evidence = _workload(confirm_boundary=True)
    launcher = replace(workload.artifacts[0], artifact_id="ART-LAUNCH", name="launcher.sh")
    relationship = Relationship(
        relationship_id="REL-TRIGGER",
        source_id=launcher.artifact_id,
        kind=RelationshipKind.TRIGGERS,
        target_id=program_id,
        evidence=(evidence,),
    )
    workload = replace(
        workload, artifacts=(*workload.artifacts, launcher), relationships=(relationship,)
    )
    candidate = _candidate(workload)
    assert "RETIRE-COUNTER-OBSERVED-EXECUTION" in candidate.metadata["counter_evidence_rule_ids"]


def test_cross_boundary_dependency_is_counter_evidence():
    workload, program_id, evidence = _workload(confirm_boundary=True)
    other = replace(workload.artifacts[0], artifact_id="ART-B", name="b.sas")
    other_boundary = WorkloadBoundary(
        boundary_id="BND-B",
        name="B",
        artifact_ids=(other.artifact_id,),
        confidence=Confidence.HIGH,
        evidence=(evidence,),
        metadata={"requires_confirmation": False},
    )
    relationship = Relationship(
        relationship_id="REL-PRECEDES",
        source_id=program_id,
        kind=RelationshipKind.PRECEDES,
        target_id=other.artifact_id,
        evidence=(evidence,),
    )
    workload = replace(
        workload,
        artifacts=(*workload.artifacts, other),
        boundaries=(*workload.boundaries, other_boundary),
        relationships=(relationship,),
    )
    candidate = _candidate(workload)
    assert (
        "RETIRE-COUNTER-CROSS-BOUNDARY-DEPENDENCY"
        in candidate.metadata["counter_evidence_rule_ids"]
    )


def test_unresolved_connection_is_a_blocker():
    workload, *_ = _workload(confirm_boundary=True)
    builder = WorkloadBuilder(name="dep")
    evidence = workload.boundaries[0].evidence
    dependency = builder.add_external_dependency(
        kind=ExternalDependencyKind.UNRESOLVED_CONNECTION,
        name="MYSTERY",
        evidence=evidence,
    )
    boundary = replace(workload.boundaries[0], external_dependency_ids=(dependency.dependency_id,))
    workload = replace(workload, external_dependencies=(dependency,), boundaries=(boundary,))
    candidate = _candidate(workload)
    assert "RETIRE-BLOCKER-UNRESOLVED-CONNECTION" in candidate.blocker_ids


def test_candidate_identity_is_stable_and_rederivation_is_idempotent():
    workload, *_ = _workload()
    first = derive_retire_candidates(workload)
    second = derive_retire_candidates(first)
    assert len(second.disposition_inputs[0].candidates) == 1
    assert (
        first.disposition_inputs[0].candidates[0].candidate_id
        == second.disposition_inputs[0].candidates[0].candidate_id
    )


def test_existing_non_retire_candidate_is_preserved():
    workload, *_ = _workload()
    existing = replace(
        _candidate(workload),
        candidate_id="MDC-CONSOLIDATE",
        disposition=ModernizationDisposition.CONSOLIDATE,
    )
    item = replace(workload.disposition_inputs[0], candidates=(existing,))
    result = derive_retire_candidates(replace(workload, disposition_inputs=(item,)))
    assert {candidate.disposition for candidate in result.disposition_inputs[0].candidates} == {
        ModernizationDisposition.CONSOLIDATE,
        ModernizationDisposition.RETIRE,
    }
