from smf.discovery.boundaries import derive_workload_boundaries
from smf.discovery.downstream import derive_downstream_outputs
from smf.discovery.lineage import derive_data_lineage
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DatasetKind,
    EvidenceMethod,
    ExternalDependencyKind,
    RelationshipKind,
    WorkloadStatus,
)


def _evidence(builder: WorkloadBuilder):
    return builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="test.sas",
        confidence=Confidence.HIGH,
    )


def test_boundary_groups_connected_artifacts_and_preserves_supporting_context() -> None:
    builder = WorkloadBuilder(name="estate", namespace="test")
    evidence = _evidence(builder)
    producer = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM,
        name="extract.sas",
        evidence=(evidence,),
    )
    consumer = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM,
        name="publish.sas",
        evidence=(evidence,),
    )
    unrelated = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM,
        name="other.sas",
        evidence=(evidence,),
    )
    dataset = builder.add_dataset(kind=DatasetKind.SAS_DATASET, name="work.claims")
    dependency = builder.add_external_dependency(
        kind=ExternalDependencyKind.DATABASE_CONNECTION,
        name="libref:src",
        evidence=(evidence,),
    )
    builder.add_relationship(
        source_id=producer.artifact_id,
        kind=RelationshipKind.WRITES,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
    )
    builder.add_relationship(
        source_id=consumer.artifact_id,
        kind=RelationshipKind.READS,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
    )
    builder.add_relationship(
        source_id=producer.artifact_id,
        kind=RelationshipKind.DEPENDS_ON,
        target_id=dependency.dependency_id,
        evidence=(evidence,),
    )

    workload = derive_data_lineage(builder.build())
    workload = derive_downstream_outputs(workload)
    workload = derive_workload_boundaries(workload)

    assert workload.status is WorkloadStatus.BOUNDARY_PROPOSED
    assert len(workload.boundaries) == 3
    connected = next(
        item for item in workload.boundaries if producer.artifact_id in item.artifact_ids
    )
    singleton = next(
        item for item in workload.boundaries if unrelated.artifact_id in item.artifact_ids
    )

    assert connected.artifact_ids == (producer.artifact_id,)
    assert connected.dataset_ids == (dataset.dataset_id,)
    assert connected.external_dependency_ids == (dependency.dependency_id,)
    assert connected.output_ids == ()
    assert connected.confidence is Confidence.MEDIUM
    assert connected.metadata["reason_counts"] == {}
    assert connected.metadata["requires_confirmation"] is True
    assert singleton.artifact_ids == (unrelated.artifact_id,)
    assert singleton.metadata["requires_confirmation"] is True


def test_referenced_only_scheduler_dependency_does_not_merge_boundary() -> None:
    builder = WorkloadBuilder(name="estate", namespace="test")
    evidence = _evidence(builder)
    job = builder.add_artifact(kind=ArtifactKind.SCHEDULER_JOB, name="LOCAL", evidence=(evidence,))
    external = builder.add_artifact(
        kind=ArtifactKind.SCHEDULER_JOB,
        name="EXTERNAL",
        evidence=(evidence,),
        metadata={"definition_status": "referenced_only"},
    )
    builder.add_relationship(
        source_id=job.artifact_id,
        kind=RelationshipKind.DEPENDS_ON,
        target_id=external.artifact_id,
        evidence=(evidence,),
    )

    workload = derive_workload_boundaries(builder.build())

    assert len(workload.boundaries) == 1
    boundary = workload.boundaries[0]
    assert boundary.artifact_ids == (job.artifact_id,)
    assert boundary.metadata["unresolved_adjacent_artifact_ids"] == (external.artifact_id,)
