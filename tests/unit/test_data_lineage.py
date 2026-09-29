from pathlib import Path

from smf.discovery import discover_source
from smf.discovery.dependency_graph import derive_dependency_graph
from smf.discovery.lineage import derive_data_lineage
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DatasetKind,
    EvidenceMethod,
    RelationshipKind,
)


def test_lineage_derives_producer_consumer_and_artifact_dependency() -> None:
    builder = WorkloadBuilder(name="claims", namespace="test")
    producer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="extract.sas")
    consumer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="report.sas")
    evidence = builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="test",
        confidence=Confidence.HIGH,
    )
    dataset = builder.add_dataset(
        kind=DatasetKind.INTERMEDIATE,
        name="work.claims",
        system="work",
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

    workload = derive_data_lineage(builder.build())
    edges = {(item.source_id, item.kind, item.target_id): item for item in workload.relationships}

    assert (producer.artifact_id, RelationshipKind.PRODUCES, dataset.dataset_id) not in edges
    assert (dataset.dataset_id, RelationshipKind.CONSUMED_BY, consumer.artifact_id) not in edges
    assert (producer.artifact_id, RelationshipKind.PRECEDES, consumer.artifact_id) not in edges
    assert (consumer.artifact_id, RelationshipKind.DEPENDS_ON, producer.artifact_id) not in edges
    assert workload.data_lineage_analysis is not None
    assert workload.data_lineage_analysis.complete is False


def test_lineage_does_not_invent_dependency_without_shared_dataset() -> None:
    builder = WorkloadBuilder(name="isolated", namespace="test")
    left = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="left.sas")
    right = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="right.sas")
    left_data = builder.add_dataset(kind=DatasetKind.INTERMEDIATE, name="work.left", system="work")
    right_data = builder.add_dataset(
        kind=DatasetKind.INTERMEDIATE, name="work.right", system="work"
    )
    builder.add_relationship(
        source_id=left.artifact_id,
        kind=RelationshipKind.WRITES,
        target_id=left_data.dataset_id,
    )
    builder.add_relationship(
        source_id=right.artifact_id,
        kind=RelationshipKind.READS,
        target_id=right_data.dataset_id,
    )

    workload = derive_data_lineage(builder.build())

    assert not any(
        item.kind in {RelationshipKind.PRECEDES, RelationshipKind.DEPENDS_ON}
        for item in workload.relationships
    )


def test_filesystem_discovery_builds_cross_program_lineage(tmp_path: Path) -> None:
    (tmp_path / "01_extract.sas").write_text(
        "data work.claims; set source.claims; run;\n",
        encoding="utf-8",
    )
    (tmp_path / "02_report.sas").write_text(
        "data work.report; set work.claims; run;\n",
        encoding="utf-8",
    )

    result = discover_source(tmp_path, provider="filesystem", namespace="test")
    workload = result.workloads[0]
    artifacts = {item.name: item for item in workload.artifacts}
    lineage = [item for item in workload.relationships if item.kind is RelationshipKind.PRECEDES]

    assert len(lineage) == 1
    assert lineage[0].source_id == artifacts["01_extract.sas"].artifact_id
    assert lineage[0].target_id == artifacts["02_report.sas"].artifact_id
    assert lineage[0].metadata["via_dataset_name"] == "work.claims"
    assert lineage[0].evidence


def test_lineage_does_not_select_from_multiple_producers() -> None:
    builder = WorkloadBuilder(name="multi", namespace="test")
    first = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="first.sas")
    second = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="second.sas")
    consumer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="consumer.sas")
    datasets = [
        builder.add_dataset(kind=DatasetKind.INTERMEDIATE, name=name, system="work")
        for name in ("work.one", "work.two")
    ]
    for index, dataset in enumerate(datasets):
        evidence = builder.evidence(
            method=EvidenceMethod.STATIC_ANALYSIS,
            source="test",
            confidence=Confidence.HIGH,
            locator=f"line:{index}",
        )
        builder.add_relationship(
            source_id=first.artifact_id,
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
        source_id=second.artifact_id,
        kind=RelationshipKind.WRITES,
        target_id=datasets[0].dataset_id,
    )

    workload = derive_data_lineage(builder.build())
    assert not any(
        item.kind in {RelationshipKind.DEPENDS_ON, RelationshipKind.PRECEDES}
        and item.metadata.get("dependency_domain") == "data"
        for item in workload.relationships
    )
    assert workload.data_lineage_analysis is not None
    conflicted = next(
        item
        for item in workload.data_lineage_analysis.dataset_resolutions
        if item.dataset_id == datasets[0].dataset_id
    )
    assert conflicted.producer_resolution.value == "unresolved"
    assert not any(
        item.kind is RelationshipKind.DEPENDS_ON
        and item.metadata.get("via_dataset_id") == datasets[0].dataset_id
        for item in workload.relationships
    )
    assert derive_data_lineage(workload).relationships == workload.relationships


def test_data_and_scheduler_dependencies_for_same_pair_remain_distinct() -> None:
    builder = WorkloadBuilder(name="mixed-domain", namespace="test")
    producer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="producer.sas")
    consumer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="consumer.sas")
    dataset = builder.add_dataset(kind=DatasetKind.INTERMEDIATE, name="work.shared", system="work")
    evidence = builder.evidence(
        method=EvidenceMethod.SCHEDULER_METADATA,
        source="schedule.jil",
        confidence=Confidence.HIGH,
    )
    builder.add_relationship(
        source_id=consumer.artifact_id,
        kind=RelationshipKind.DEPENDS_ON,
        target_id=producer.artifact_id,
        evidence=(evidence,),
        metadata={"dependency_domain": "scheduler"},
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

    workload = derive_dependency_graph(derive_data_lineage(builder.build()))
    relationships = [
        item
        for item in workload.relationships
        if item.source_id == consumer.artifact_id
        and item.kind is RelationshipKind.DEPENDS_ON
        and item.target_id == producer.artifact_id
    ]
    edges = [
        item
        for item in workload.dependency_graph.edges
        if item.source_id == consumer.artifact_id
        and item.kind is RelationshipKind.DEPENDS_ON
        and item.target_id == producer.artifact_id
    ]

    assert {item.metadata["dependency_domain"] for item in relationships} == {"scheduler"}
    assert len({item.relationship_id for item in relationships}) == 1
    assert {item.metadata["dependency_domain"] for item in edges} == {"scheduler"}
    assert len({item.edge_id for item in edges}) == 1
