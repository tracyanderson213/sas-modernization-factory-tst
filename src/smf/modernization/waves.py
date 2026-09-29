"""Dependency-aware migration wave grouping foundation.

WLD-13 derives evidence-backed migration cohorts and relative dependency order
from canonical workload facts. The result is a planning proposal, not a calendar
schedule or autonomous migration commitment.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import DiscoveryEvidence, MigrationWaveGroup, RelationshipKind, Workload


def _merge_evidence(*groups: tuple[DiscoveryEvidence, ...]) -> tuple[DiscoveryEvidence, ...]:
    merged: dict[str, DiscoveryEvidence] = {}
    for group in groups:
        for item in group:
            merged[item.evidence_id] = item
    return tuple(merged.values())


def _boundary_by_artifact(workload: Workload) -> dict[str, str]:
    return {
        artifact_id: boundary.boundary_id
        for boundary in workload.boundaries
        for artifact_id in boundary.artifact_ids
    }


def _directed_dependencies(
    workload: Workload,
) -> dict[tuple[str, str], tuple[DiscoveryEvidence, ...]]:
    """Return predecessor -> successor boundary dependencies supported by evidence."""

    by_artifact = _boundary_by_artifact(workload)
    evidence_by_pair: dict[tuple[str, str], list[DiscoveryEvidence]] = defaultdict(list)
    for relationship in workload.relationships:
        source = by_artifact.get(relationship.source_id)
        target = by_artifact.get(relationship.target_id)
        if source is None or target is None or source == target:
            continue
        pair: tuple[str, str] | None = None
        if relationship.kind in {RelationshipKind.PRECEDES, RelationshipKind.TRIGGERS}:
            pair = (source, target)
        elif relationship.kind is RelationshipKind.DEPENDS_ON:
            pair = (target, source)
        if pair is not None:
            evidence_by_pair[pair].extend(relationship.evidence)
    return {pair: _merge_evidence(tuple(items)) for pair, items in evidence_by_pair.items()}


def _affinity_pairs(workload: Workload) -> dict[tuple[str, str], set[str]]:
    """Find boundaries sharing migration-relevant dependencies or datasets."""

    pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    boundaries = list(workload.boundaries)
    for index, left in enumerate(boundaries):
        for right in boundaries[index + 1 :]:
            first, second = sorted((left.boundary_id, right.boundary_id))
            key: tuple[str, str] = (first, second)
            if set(left.dataset_ids) & set(right.dataset_ids):
                pairs[key].add("shared_dataset")
            if set(left.external_dependency_ids) & set(right.external_dependency_ids):
                pairs[key].add("shared_external_dependency")
    return pairs


def _affinity_components(
    workload: Workload, affinity: dict[tuple[str, str], set[str]]
) -> list[set[str]]:
    parent = {item.boundary_id: item.boundary_id for item in workload.boundaries}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for left, right in affinity:
        union(left, right)
    groups: dict[str, set[str]] = defaultdict(set)
    for boundary_id in parent:
        groups[find(boundary_id)].add(boundary_id)
    return list(groups.values())


def _strongly_connected_components(nodes: set[str], edges: set[tuple[str, str]]) -> list[set[str]]:
    """Tarjan SCC so circular dependencies stay in the same migration cohort."""

    adjacency: dict[str, set[str]] = defaultdict(set)
    for source, target in edges:
        adjacency[source].add(target)
    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[set[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlink[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(adjacency.get(node, set())):
            if target not in indices:
                visit(target)
                lowlink[node] = min(lowlink[node], lowlink[target])
            elif target in on_stack:
                lowlink[node] = min(lowlink[node], indices[target])
        if lowlink[node] == indices[node]:
            component: set[str] = set()
            while True:
                item = stack.pop()
                on_stack.remove(item)
                component.add(item)
                if item == node:
                    break
            components.append(component)

    for node in sorted(nodes):
        if node not in indices:
            visit(node)
    return components


def derive_migration_wave_groups(workload: Workload) -> Workload:
    """Propose dependency-aware migration groups without assigning calendar waves."""

    affinity = _affinity_pairs(workload)
    directed = _directed_dependencies(workload)
    affinity_components = _affinity_components(workload, affinity)
    affinity_id_by_boundary: dict[str, str] = {}
    boundaries_by_affinity: dict[str, set[str]] = {}
    for component in affinity_components:
        affinity_id = min(component)
        boundaries_by_affinity[affinity_id] = component
        for boundary_id in component:
            affinity_id_by_boundary[boundary_id] = affinity_id

    affinity_edges = {
        (affinity_id_by_boundary[source], affinity_id_by_boundary[target])
        for source, target in directed
        if affinity_id_by_boundary[source] != affinity_id_by_boundary[target]
    }
    sccs = _strongly_connected_components(set(boundaries_by_affinity), affinity_edges)

    group_boundaries: dict[str, tuple[str, ...]] = {}
    group_by_affinity: dict[str, str] = {}
    for scc in sccs:
        boundary_ids = tuple(
            sorted(
                boundary_id
                for affinity_id in scc
                for boundary_id in boundaries_by_affinity[affinity_id]
            )
        )
        group_id = stable_id("MWG", {"workload": workload.workload_id, "boundaries": boundary_ids})
        group_boundaries[group_id] = boundary_ids
        for affinity_id in scc:
            group_by_affinity[affinity_id] = group_id

    predecessor_groups: dict[str, set[str]] = defaultdict(set)
    for source, target in affinity_edges:
        source_group = group_by_affinity[source]
        target_group = group_by_affinity[target]
        if source_group != target_group:
            predecessor_groups[target_group].add(source_group)

    ranks = {group_id: 0 for group_id in group_boundaries}
    for _ in range(len(ranks)):
        changed = False
        for group_id, predecessors in predecessor_groups.items():
            candidate = max(ranks[item] + 1 for item in predecessors)
            if candidate > ranks[group_id]:
                ranks[group_id] = candidate
                changed = True
        if not changed:
            break

    boundary_by_id = {item.boundary_id: item for item in workload.boundaries}
    pattern_by_boundary = {item.boundary_id: item for item in workload.target_state_pattern_inputs}
    groups: list[MigrationWaveGroup] = []
    for group_id, boundary_ids in group_boundaries.items():
        boundary_set = set(boundary_ids)
        reasons: set[str] = set()
        unresolved: set[str] = set()
        evidence_groups: list[tuple[DiscoveryEvidence, ...]] = []
        for boundary_id in boundary_ids:
            boundary = boundary_by_id[boundary_id]
            evidence_groups.append(boundary.evidence)
            pattern = pattern_by_boundary.get(boundary_id)
            if pattern is not None:
                unresolved.update(pattern.unresolved_items)
        for (left, right), pair_reasons in affinity.items():
            if left in boundary_set and right in boundary_set:
                reasons.update(pair_reasons)
        for (source, target), edge_evidence in directed.items():
            if source in boundary_set and target in boundary_set:
                reasons.add(
                    "dependency_cycle" if (target, source) in directed else "dependency_coupling"
                )
                evidence_groups.append(edge_evidence)

        groups.append(
            MigrationWaveGroup(
                wave_group_id=group_id,
                boundary_ids=boundary_ids,
                predecessor_group_ids=tuple(sorted(predecessor_groups[group_id])),
                sequence_rank=ranks[group_id],
                coupling_reasons=tuple(sorted(reasons or {"independent_boundary"})),
                unresolved_items=tuple(sorted(unresolved)),
                evidence=_merge_evidence(*evidence_groups),
                metadata={
                    "basis": "canonical_dependency_and_affinity_evidence",
                    "calendar_wave_assigned": False,
                    "requires_planning_confirmation": True,
                    "boundary_count": len(boundary_ids),
                },
            )
        )

    groups.sort(key=lambda item: (item.sequence_rank, item.wave_group_id))
    metadata = {
        **workload.metadata,
        "migration_wave_grouping": {
            "group_count": len(groups),
            "basis": "canonical_dependency_and_affinity_evidence",
            "calendar_wave_assigned": False,
            "governed_planning_required": True,
        },
    }
    return replace(workload, migration_wave_groups=tuple(groups), metadata=metadata)
