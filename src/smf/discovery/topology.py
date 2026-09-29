"""Current-state topology projection for discovered workload systems.

WLD-10 projects the canonical discovery graph into a navigable topology without
inventing relationships. Boundary membership is preserved, external and
referenced-only dependencies remain visible, and every topology edge retains
its source relationship evidence.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Confidence,
    DiscoveryEvidence,
    TopologyEdge,
    TopologyNode,
    TopologyNodeKind,
    Workload,
    WorkloadTopology,
)


def _merge_evidence(*groups: tuple[DiscoveryEvidence, ...]) -> tuple[DiscoveryEvidence, ...]:
    merged: dict[str, DiscoveryEvidence] = {}
    for group in groups:
        for evidence in group:
            merged[evidence.evidence_id] = evidence
    return tuple(merged.values())


def derive_current_state_topology(workload: Workload) -> Workload:
    """Create an evidence-preserving topology projection from canonical discovery facts."""

    boundary_by_artifact = {
        artifact_id: boundary.boundary_id
        for boundary in workload.boundaries
        for artifact_id in boundary.artifact_ids
    }
    nodes: dict[str, TopologyNode] = {}

    for boundary in workload.boundaries:
        nodes[boundary.boundary_id] = TopologyNode(
            node_id=boundary.boundary_id,
            kind=TopologyNodeKind.WORKLOAD_BOUNDARY,
            entity_id=boundary.boundary_id,
            label=boundary.name,
            boundary_id=boundary.boundary_id,
            confidence=boundary.confidence,
            evidence=boundary.evidence,
            metadata={
                "requires_confirmation": boundary.metadata.get("requires_confirmation", True)
            },
        )

    for dataset in workload.datasets:
        nodes[dataset.dataset_id] = TopologyNode(
            node_id=dataset.dataset_id,
            kind=TopologyNodeKind.DATASET,
            entity_id=dataset.dataset_id,
            label=dataset.name,
            confidence=Confidence.HIGH if dataset.evidence else Confidence.UNKNOWN,
            evidence=dataset.evidence,
            metadata={"dataset_kind": dataset.kind.value, "system": dataset.system},
        )

    for dependency in workload.external_dependencies:
        nodes[dependency.dependency_id] = TopologyNode(
            node_id=dependency.dependency_id,
            kind=TopologyNodeKind.EXTERNAL_DEPENDENCY,
            entity_id=dependency.dependency_id,
            label=dependency.name,
            confidence=Confidence.HIGH if dependency.evidence else Confidence.UNKNOWN,
            evidence=dependency.evidence,
            metadata={"dependency_kind": dependency.kind.value, "system": dependency.system},
        )

    referenced_only_ids: set[str] = set()
    for artifact in workload.artifacts:
        if artifact.metadata.get("definition_status") != "referenced_only":
            continue
        referenced_only_ids.add(artifact.artifact_id)
        nodes[artifact.artifact_id] = TopologyNode(
            node_id=artifact.artifact_id,
            kind=TopologyNodeKind.EXTERNAL_ARTIFACT,
            entity_id=artifact.artifact_id,
            label=artifact.name,
            confidence=Confidence.MEDIUM if artifact.evidence else Confidence.UNKNOWN,
            evidence=artifact.evidence,
            metadata={"artifact_kind": artifact.kind.value, "definition_status": "referenced_only"},
        )

    edges: dict[str, TopologyEdge] = {}
    unresolved_relationship_ids: list[str] = []
    for relationship in workload.relationships:
        source = boundary_by_artifact.get(relationship.source_id, relationship.source_id)
        target = boundary_by_artifact.get(relationship.target_id, relationship.target_id)
        if source == target:
            continue
        if source not in nodes or target not in nodes:
            unresolved_relationship_ids.append(relationship.relationship_id)
            continue
        edge_id = stable_id(
            "TOPEDGE",
            {"source": source, "kind": relationship.kind.value, "target": target},
        )
        existing = edges.get(edge_id)
        evidence = relationship.evidence
        relationship_ids = [relationship.relationship_id]
        if existing is not None:
            evidence = _merge_evidence(existing.evidence, relationship.evidence)
            relationship_ids = [
                *existing.metadata.get("relationship_ids", ()),
                relationship.relationship_id,
            ]
        edges[edge_id] = TopologyEdge(
            edge_id=edge_id,
            source_id=source,
            kind=relationship.kind,
            target_id=target,
            evidence=evidence,
            metadata={"relationship_ids": tuple(sorted(set(relationship_ids)))},
        )

    topology = WorkloadTopology(
        topology_id=stable_id("TOPO", {"workload": workload.workload_id}),
        nodes=tuple(sorted(nodes.values(), key=lambda item: item.node_id)),
        edges=tuple(sorted(edges.values(), key=lambda item: item.edge_id)),
        evidence=_merge_evidence(*(edge.evidence for edge in edges.values())),
        metadata={
            "basis": "canonical_discovery_graph_projection",
            "boundary_count": len(workload.boundaries),
            "referenced_only_external_artifact_count": len(referenced_only_ids),
            "unresolved_relationship_ids": tuple(sorted(unresolved_relationship_ids)),
            "complete_enterprise_topology": False,
        },
    )
    metadata = {
        **workload.metadata,
        "current_state_topology": {
            "node_count": len(topology.nodes),
            "edge_count": len(topology.edges),
            "complete_enterprise_topology": False,
        },
    }
    return replace(workload, topology=topology, metadata=metadata)
