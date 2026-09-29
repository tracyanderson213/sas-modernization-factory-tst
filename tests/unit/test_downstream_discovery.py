from smf.discovery.downstream import derive_downstream_outputs
from smf.discovery.lineage import derive_data_lineage
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DatasetKind,
    EvidenceMethod,
    RelationshipKind,
)


def _evidence(builder: WorkloadBuilder):
    return builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="test.sas",
        confidence=Confidence.HIGH,
    )


def test_output_records_observed_in_estate_consumer_without_claiming_completeness() -> None:
    builder = WorkloadBuilder(name="claims", namespace="test")
    producer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="producer.sas")
    consumer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="consumer.sas")
    evidence = _evidence(builder)
    dataset = builder.add_dataset(kind=DatasetKind.SAS_DATASET, name="curated.claims")
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

    workload = derive_downstream_outputs(derive_data_lineage(builder.build()))

    assert workload.outputs == ()
    assert workload.data_lineage_analysis is not None
    assert workload.data_lineage_analysis.complete is False


def test_output_without_observed_consumer_remains_unresolved() -> None:
    builder = WorkloadBuilder(name="report", namespace="test")
    producer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="publish.sas")
    evidence = _evidence(builder)
    dataset = builder.add_dataset(
        kind=DatasetKind.FILE,
        name="claims_report.csv",
        location="output/claims_report.csv",
    )
    builder.add_relationship(
        source_id=producer.artifact_id,
        kind=RelationshipKind.WRITES,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
    )

    workload = derive_downstream_outputs(derive_data_lineage(builder.build()))

    assert workload.outputs == ()
