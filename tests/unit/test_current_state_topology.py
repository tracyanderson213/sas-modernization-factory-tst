from smf.discovery.boundaries import derive_workload_boundaries
from smf.discovery.lineage import derive_data_lineage
from smf.discovery.topology import derive_current_state_topology
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DatasetKind,
    EvidenceMethod,
    ExternalDependencyKind,
    RelationshipKind,
    TopologyNodeKind,
)


def test_topology_projects_boundaries_data_and_external_dependencies() -> None:
    builder = WorkloadBuilder(name="estate", namespace="test")
    evidence = builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="test.sas",
        confidence=Confidence.HIGH,
    )
    producer = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM, name="extract.sas", evidence=(evidence,)
    )
    dataset = builder.add_dataset(
        kind=DatasetKind.DATABASE_TABLE, name="claims.monthly", evidence=(evidence,)
    )
    dependency = builder.add_external_dependency(
        kind=ExternalDependencyKind.DATABASE_CONNECTION,
        name="libref:claims",
        evidence=(evidence,),
    )
    builder.add_relationship(
        source_id=producer.artifact_id,
        kind=RelationshipKind.WRITES,
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
    workload = derive_workload_boundaries(workload)
    workload = derive_current_state_topology(workload)

    assert workload.topology is not None
    kinds = {node.kind for node in workload.topology.nodes}
    assert TopologyNodeKind.WORKLOAD_BOUNDARY in kinds
    assert TopologyNodeKind.DATASET in kinds
    assert TopologyNodeKind.EXTERNAL_DEPENDENCY in kinds
    boundary = workload.boundaries[0]
    edges = {(edge.source_id, edge.kind, edge.target_id) for edge in workload.topology.edges}
    assert (boundary.boundary_id, RelationshipKind.WRITES, dataset.dataset_id) in edges
    assert (boundary.boundary_id, RelationshipKind.DEPENDS_ON, dependency.dependency_id) in edges
    assert workload.topology.metadata["complete_enterprise_topology"] is False


def test_topology_keeps_referenced_only_scheduler_visible_and_does_not_invent_edges() -> None:
    builder = WorkloadBuilder(name="estate", namespace="test")
    evidence = builder.evidence(
        method=EvidenceMethod.SCHEDULER_METADATA,
        source="jobs.jil",
        confidence=Confidence.HIGH,
    )
    local = builder.add_artifact(
        kind=ArtifactKind.SCHEDULER_JOB, name="LOCAL", evidence=(evidence,)
    )
    external = builder.add_artifact(
        kind=ArtifactKind.SCHEDULER_JOB,
        name="UPSTREAM_EXTERNAL",
        evidence=(evidence,),
        metadata={"definition_status": "referenced_only"},
    )
    builder.add_relationship(
        source_id=local.artifact_id,
        kind=RelationshipKind.DEPENDS_ON,
        target_id=external.artifact_id,
        evidence=(evidence,),
    )

    workload = derive_workload_boundaries(builder.build())
    workload = derive_current_state_topology(workload)

    assert workload.topology is not None
    external_node = next(
        node for node in workload.topology.nodes if node.entity_id == external.artifact_id
    )
    assert external_node.kind is TopologyNodeKind.EXTERNAL_ARTIFACT
    assert len(workload.topology.edges) == 1
    assert workload.topology.edges[0].target_id == external.artifact_id
