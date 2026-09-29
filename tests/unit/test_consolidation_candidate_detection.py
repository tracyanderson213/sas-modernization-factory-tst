from smf.modernization.consolidate import derive_consolidation_candidates
from smf.modernization.disposition import derive_modernization_disposition_inputs
from smf.workload.models import (
    Confidence,
    ConsumerResolution,
    ModernizationDisposition,
    Output,
    Workload,
    WorkloadBoundary,
)


def boundary(name: str, *, datasets=(), deps=(), outputs=(), metadata=None):
    return WorkloadBoundary(
        boundary_id=name,
        name=name,
        dataset_ids=tuple(datasets),
        external_dependency_ids=tuple(deps),
        output_ids=tuple(outputs),
        confidence=Confidence.HIGH,
        metadata=metadata or {"requires_confirmation": False},
    )


def prepared(*boundaries, outputs=()):
    workload = Workload(
        workload_id="WL-1", name="estate", boundaries=tuple(boundaries), outputs=tuple(outputs)
    )
    return derive_modernization_disposition_inputs(workload)


def consolidate(workload, boundary_id):
    item = next(x for x in workload.disposition_inputs if x.boundary_id == boundary_id)
    return [x for x in item.candidates if x.disposition is ModernizationDisposition.CONSOLIDATE]


def test_no_affinity_produces_no_candidate():
    result = derive_consolidation_candidates(prepared(boundary("A"), boundary("B")))
    assert not consolidate(result, "A")


def test_shared_dataset_produces_low_confidence_candidate():
    result = derive_consolidation_candidates(
        prepared(boundary("A", datasets=("D",)), boundary("B", datasets=("D",)))
    )
    candidate = consolidate(result, "A")[0]
    assert candidate.confidence is Confidence.LOW
    assert candidate.metadata["peer_boundary_ids"] == ("B",)


def test_shared_external_dependency_is_weak_affinity():
    result = derive_consolidation_candidates(
        prepared(boundary("A", deps=("X",)), boundary("B", deps=("X",)))
    )
    assert consolidate(result, "A")[0].confidence is Confidence.LOW


def test_shared_consumer_and_data_raise_confidence_only_to_medium():
    outputs = (
        Output("OA", "DA", ("a",), ("consumer",), ConsumerResolution.PARTIAL),
        Output("OB", "DB", ("b",), ("consumer",), ConsumerResolution.PARTIAL),
    )
    result = derive_consolidation_candidates(
        prepared(
            boundary("A", datasets=("D",), outputs=("OA",)),
            boundary("B", datasets=("D",), outputs=("OB",)),
            outputs=outputs,
        )
    )
    assert consolidate(result, "A")[0].confidence is Confidence.MEDIUM


def test_candidate_never_establishes_behavior_equivalence():
    result = derive_consolidation_candidates(
        prepared(boundary("A", datasets=("D",)), boundary("B", datasets=("D",)))
    )
    candidate = consolidate(result, "A")[0]
    assert candidate.metadata["behavior_equivalence_established"] is False
    assert "CONSOLIDATE-BLOCKER-BEHAVIOR-EQUIVALENCE-NOT-ESTABLISHED" in candidate.blocker_ids


def test_candidate_never_selects_disposition():
    result = derive_consolidation_candidates(
        prepared(boundary("A", datasets=("D",)), boundary("B", datasets=("D",)))
    )
    item = next(x for x in result.disposition_inputs if x.boundary_id == "A")
    assert item.selected_disposition is None


def test_candidates_are_symmetric():
    result = derive_consolidation_candidates(
        prepared(boundary("A", datasets=("D",)), boundary("B", datasets=("D",)))
    )
    assert consolidate(result, "A")[0].metadata["peer_boundary_ids"] == ("B",)
    assert consolidate(result, "B")[0].metadata["peer_boundary_ids"] == ("A",)


def test_unresolved_adjacent_artifacts_are_preserved_as_blocker():
    meta = {"requires_confirmation": True, "unresolved_adjacent_artifact_ids": ("EXT",)}
    result = derive_consolidation_candidates(
        prepared(boundary("A", datasets=("D",), metadata=meta), boundary("B", datasets=("D",)))
    )
    assert "CONSOLIDATE-BLOCKER-UNRESOLVED-ADJACENT" in consolidate(result, "A")[0].blocker_ids


def test_existing_retire_candidate_is_preserved():
    workload = prepared(boundary("A", datasets=("D",)), boundary("B", datasets=("D",)))
    from smf.modernization.retire import derive_retire_candidates

    workload = derive_retire_candidates(workload)
    result = derive_consolidation_candidates(workload)
    dispositions = {
        x.disposition
        for x in next(i for i in result.disposition_inputs if i.boundary_id == "A").candidates
    }
    assert ModernizationDisposition.RETIRE in dispositions
    assert ModernizationDisposition.CONSOLIDATE in dispositions


def test_rerun_replaces_consolidate_candidates_instead_of_duplicating():
    workload = prepared(boundary("A", datasets=("D",)), boundary("B", datasets=("D",)))
    once = derive_consolidation_candidates(workload)
    twice = derive_consolidation_candidates(once)
    assert len(consolidate(twice, "A")) == 1
