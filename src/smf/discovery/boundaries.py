"""Evidence-backed workload grouping and boundary proposal derivation.

WLD-09 groups discovered artifacts using deterministic graph connectivity. It
proposes workload-system boundaries without pretending that filesystem layout
or missing evidence proves a business boundary. Every proposal preserves the
relationships and evidence that caused artifacts to be grouped.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    Confidence,
    DiscoveryEvidence,
    Relationship,
    RelationshipKind,
    Workload,
    WorkloadBoundary,
    WorkloadStatus,
)

_CONNECTING_KINDS = {
    RelationshipKind.INCLUDES,
    RelationshipKind.CALLS,
    RelationshipKind.TRIGGERS,
    RelationshipKind.PRECEDES,
    RelationshipKind.DEPENDS_ON,
}

_EXCLUDED_ARTIFACT_KINDS = {ArtifactKind.OTHER}


def _merge_evidence(*groups: tuple[DiscoveryEvidence, ...]) -> tuple[DiscoveryEvidence, ...]:
    merged: dict[str, DiscoveryEvidence] = {}
    for group in groups:
        for item in group:
            merged[item.evidence_id] = item
    return tuple(merged.values())


def _eligible_artifact(artifact: Artifact) -> bool:
    if artifact.kind in _EXCLUDED_ARTIFACT_KINDS:
        return False
    return artifact.metadata.get("definition_status") != "referenced_only"


def _component_ids(
    artifact_ids: set[str], relationships: tuple[Relationship, ...]
) -> tuple[tuple[str, ...], ...]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for relationship in relationships:
        if relationship.kind not in _CONNECTING_KINDS:
            continue
        if (
            relationship.kind is RelationshipKind.INCLUDES
            and relationship.metadata.get("include_resolution") != "resolved"
        ):
            continue
        if relationship.source_id not in artifact_ids or relationship.target_id not in artifact_ids:
            continue
        adjacency[relationship.source_id].add(relationship.target_id)
        adjacency[relationship.target_id].add(relationship.source_id)

    components: list[tuple[str, ...]] = []
    remaining = set(artifact_ids)
    while remaining:
        start = min(remaining)
        queue = deque([start])
        component: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in component:
                continue
            component.add(current)
            remaining.discard(current)
            queue.extend(sorted(adjacency.get(current, set()) - component))
        components.append(tuple(sorted(component)))
    return tuple(sorted(components, key=lambda item: item[0]))


def _boundary_name(artifacts: list[Artifact]) -> str:
    scheduler = sorted(
        (
            item
            for item in artifacts
            if item.kind is ArtifactKind.SCHEDULER_JOB
            and item.metadata.get("definition_status") != "referenced_only"
        ),
        key=lambda item: (item.logical_path or "", item.name),
    )
    if scheduler:
        return scheduler[0].name

    programs = sorted(
        (item for item in artifacts if item.kind is ArtifactKind.SAS_PROGRAM),
        key=lambda item: (item.logical_path or "", item.name),
    )
    if programs:
        return programs[0].name.rsplit(".", 1)[0]

    first = sorted(artifacts, key=lambda item: (item.logical_path or "", item.name))[0]
    return first.name.rsplit(".", 1)[0]


def _confidence(component: tuple[str, ...], evidence: tuple[DiscoveryEvidence, ...]) -> Confidence:
    if len(component) > 1 and evidence:
        return Confidence.HIGH
    if evidence:
        return Confidence.MEDIUM
    return Confidence.LOW


def derive_workload_boundaries(workload: Workload) -> Workload:
    """Propose explainable workload boundaries from deterministic graph evidence."""

    artifacts = {item.artifact_id: item for item in workload.artifacts}
    eligible_ids = {item.artifact_id for item in workload.artifacts if _eligible_artifact(item)}
    components = _component_ids(eligible_ids, workload.relationships)
    dependency_ids = {item.dependency_id for item in workload.external_dependencies}
    output_by_dataset = {item.dataset_id: item for item in workload.outputs}

    boundaries: list[WorkloadBoundary] = []
    for component in components:
        member_ids = set(component)
        member_artifacts = [artifacts[item_id] for item_id in component]
        connecting_edges = [
            relationship
            for relationship in workload.relationships
            if relationship.kind in _CONNECTING_KINDS
            and relationship.source_id in member_ids
            and relationship.target_id in member_ids
        ]
        related_edges = [
            relationship
            for relationship in workload.relationships
            if relationship.source_id in member_ids or relationship.target_id in member_ids
        ]

        dataset_ids: set[str] = set()
        external_dependency_ids: set[str] = set()
        unresolved_artifact_ids: set[str] = set()
        for relationship in related_edges:
            other_id = (
                relationship.target_id
                if relationship.source_id in member_ids
                else relationship.source_id
            )
            if other_id in dependency_ids:
                external_dependency_ids.add(other_id)
            if (
                other_id in artifacts
                and artifacts[other_id].metadata.get("definition_status") == "referenced_only"
            ):
                unresolved_artifact_ids.add(other_id)
            if relationship.kind in {
                RelationshipKind.READS,
                RelationshipKind.WRITES,
                RelationshipKind.PRODUCES,
                RelationshipKind.CONSUMED_BY,
            }:
                if relationship.source_id in member_ids:
                    dataset_ids.add(relationship.target_id)
                elif relationship.target_id in member_ids:
                    dataset_ids.add(relationship.source_id)

        valid_dataset_ids = {item.dataset_id for item in workload.datasets}
        dataset_ids &= valid_dataset_ids
        output_ids = {
            output_by_dataset[dataset_id].output_id
            for dataset_id in dataset_ids
            if dataset_id in output_by_dataset
        }
        unresolved_dependency_ids = tuple(
            sorted(
                item.unresolved_id
                for item in (
                    workload.dependency_graph.unresolved if workload.dependency_graph else ()
                )
                if item.source_id in member_ids
            )
        )
        evidence = _merge_evidence(
            *(edge.evidence for edge in connecting_edges),
            *(artifact.evidence for artifact in member_artifacts),
        )
        reason_counts: dict[str, int] = defaultdict(int)
        for edge in connecting_edges:
            reason_counts[edge.kind.value] += 1

        boundary_id = stable_id(
            "BND",
            {"workload": workload.workload_id, "artifacts": list(component)},
        )
        boundaries.append(
            WorkloadBoundary(
                boundary_id=boundary_id,
                name=_boundary_name(member_artifacts),
                artifact_ids=component,
                dataset_ids=tuple(sorted(dataset_ids)),
                external_dependency_ids=tuple(sorted(external_dependency_ids)),
                output_ids=tuple(sorted(output_ids)),
                confidence=_confidence(component, evidence),
                evidence=evidence,
                metadata={
                    "basis": "deterministic_graph_connectivity",
                    "reason_counts": dict(sorted(reason_counts.items())),
                    "artifact_count": len(component),
                    "unresolved_adjacent_artifact_ids": tuple(sorted(unresolved_artifact_ids)),
                    "unresolved_dependency_ids": unresolved_dependency_ids,
                    "requires_confirmation": True,
                },
            )
        )

    metadata = {
        **workload.metadata,
        "boundary_detection": {
            "strategy": "deterministic_graph_connectivity",
            "candidate_count": len(boundaries),
            "excluded_other_artifact_count": sum(
                1 for item in workload.artifacts if item.kind in _EXCLUDED_ARTIFACT_KINDS
            ),
            "confirmation_required": True,
        },
    }
    status = WorkloadStatus.BOUNDARY_PROPOSED if boundaries else workload.status
    return replace(workload, boundaries=tuple(boundaries), status=status, metadata=metadata)
