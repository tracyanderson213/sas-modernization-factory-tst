from dataclasses import replace

from smf.modernization.intermediate import derive_intermediate_artifact_elimination_opportunities
from smf.workload.models import (
    Confidence,
    ConsumerResolution,
    Dataset,
    DatasetKind,
    Output,
    Relationship,
    RelationshipKind,
    Workload,
    WorkloadBoundary,
)


def _workload(*, external_reader: bool = False, exposed_output: bool = False) -> Workload:
    dataset = Dataset(dataset_id="D1", kind=DatasetKind.INTERMEDIATE, name="work.stage")
    artifact_ids = ("A1", "A2")
    relationships = [
        Relationship("R1", "A1", RelationshipKind.WRITES, "D1"),
        Relationship("R2", "A2", RelationshipKind.READS, "D1"),
    ]
    if external_reader:
        relationships.append(Relationship("R3", "A3", RelationshipKind.READS, "D1"))
    outputs = (
        (
            Output(
                output_id="O1",
                dataset_id="D1",
                producer_ids=("A1",),
                consumer_resolution=ConsumerResolution.PARTIAL,
            ),
        )
        if exposed_output
        else ()
    )
    return Workload(
        workload_id="W1",
        name="test",
        datasets=(dataset,),
        relationships=tuple(relationships),
        outputs=outputs,
        boundaries=(
            WorkloadBoundary(
                boundary_id="B1",
                name="boundary",
                artifact_ids=artifact_ids,
                dataset_ids=("D1",),
                metadata={"requires_confirmation": False},
            ),
        ),
    )


def test_internal_intermediate_becomes_candidate() -> None:
    result = derive_intermediate_artifact_elimination_opportunities(_workload())
    assert len(result.intermediate_artifact_elimination_opportunities) == 1


def test_candidate_is_medium_at_most() -> None:
    item = derive_intermediate_artifact_elimination_opportunities(
        _workload()
    ).intermediate_artifact_elimination_opportunities[0]
    assert item.confidence is Confidence.MEDIUM


def test_absent_output_does_not_prove_absent_downstream_consumer() -> None:
    item = derive_intermediate_artifact_elimination_opportunities(
        _workload()
    ).intermediate_artifact_elimination_opportunities[0]
    assert "INTERMEDIATE-BLOCKER-DOWNSTREAM-COVERAGE-NOT-ESTABLISHED" in item.blocker_ids
    assert item.metadata["downstream_absence_proven"] is False


def test_semantic_necessity_remains_blocked() -> None:
    item = derive_intermediate_artifact_elimination_opportunities(
        _workload()
    ).intermediate_artifact_elimination_opportunities[0]
    assert "INTERMEDIATE-BLOCKER-SEMANTIC-NECESSITY-NOT-ESTABLISHED" in item.blocker_ids
    assert item.metadata["semantic_equivalence_established"] is False


def test_cross_boundary_reader_blocks_elimination() -> None:
    item = derive_intermediate_artifact_elimination_opportunities(
        _workload(external_reader=True)
    ).intermediate_artifact_elimination_opportunities[0]
    assert "INTERMEDIATE-BLOCKER-CROSS-BOUNDARY-CONSUMER" in item.blocker_ids
    assert item.confidence is Confidence.LOW


def test_exposed_output_blocks_elimination() -> None:
    item = derive_intermediate_artifact_elimination_opportunities(
        _workload(exposed_output=True)
    ).intermediate_artifact_elimination_opportunities[0]
    assert "INTERMEDIATE-BLOCKER-EXPOSED-AS-OUTPUT" in item.blocker_ids


def test_partial_output_coverage_is_preserved_as_blocker() -> None:
    item = derive_intermediate_artifact_elimination_opportunities(
        _workload(exposed_output=True)
    ).intermediate_artifact_elimination_opportunities[0]
    assert "INTERMEDIATE-BLOCKER-DOWNSTREAM-COVERAGE-INCOMPLETE" in item.blocker_ids


def test_non_intermediate_dataset_is_not_candidate() -> None:
    workload = _workload()
    workload = replace(
        workload, datasets=(replace(workload.datasets[0], kind=DatasetKind.SAS_DATASET),)
    )
    result = derive_intermediate_artifact_elimination_opportunities(workload)
    assert result.intermediate_artifact_elimination_opportunities == ()


def test_unconsumed_intermediate_is_not_candidate() -> None:
    workload = _workload()
    workload = replace(workload, relationships=(workload.relationships[0],))
    result = derive_intermediate_artifact_elimination_opportunities(workload)
    assert result.intermediate_artifact_elimination_opportunities == ()


def test_analysis_is_deterministic_and_replaces_prior_results() -> None:
    first = derive_intermediate_artifact_elimination_opportunities(_workload())
    second = derive_intermediate_artifact_elimination_opportunities(first)
    assert (
        second.intermediate_artifact_elimination_opportunities
        == first.intermediate_artifact_elimination_opportunities
    )
    assert (
        second.metadata["intermediate_artifact_elimination_analysis"]["automatic_elimination"]
        is False
    )
