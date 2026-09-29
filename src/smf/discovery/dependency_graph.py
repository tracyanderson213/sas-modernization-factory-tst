"""Stable dependency-graph projection from canonical workload relationships."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    Confidence,
    DependencyDomain,
    DependencyEdge,
    DependencyGraph,
    DependencyNode,
    DependencyNodeKind,
    DependencyResolutionReason,
    DiscoveryEvidence,
    EvidenceMethod,
    ExternalDependencyKind,
    IncludeResolutionKind,
    RelationshipKind,
    UnresolvedDependency,
    Workload,
)


def _merge_evidence(
    *groups: tuple[DiscoveryEvidence, ...],
) -> tuple[DiscoveryEvidence, ...]:
    merged = {item.evidence_id: item for group in groups for item in group}
    return tuple(merged[key] for key in sorted(merged))


def _metadata_evidence(
    artifact: Artifact,
    reference: str,
    line: int,
    *,
    method: EvidenceMethod = EvidenceMethod.STATIC_ANALYSIS,
    source: str | None = None,
    observed_value: str | None = None,
) -> DiscoveryEvidence:
    source = source or artifact.logical_path or artifact.name
    locator = f"{source}:{line}"
    return DiscoveryEvidence(
        evidence_id=stable_id(
            "EV",
            {
                "method": method.value,
                "source": source,
                "locator": locator,
                "observed_value": observed_value or reference,
            },
        ),
        method=method,
        source=source,
        confidence=Confidence.HIGH,
        locator=locator,
        observed_value=observed_value or reference,
        metadata={"line": line, "observation": "unresolved_dependency"},
    )


def _reason(value: str) -> DependencyResolutionReason:
    aliases = {
        "external": DependencyResolutionReason.EXTERNAL,
        "referenced_only": DependencyResolutionReason.EXTERNAL,
        "unresolved_connection": DependencyResolutionReason.EXTERNAL,
        "unresolved": DependencyResolutionReason.MISSING,
    }
    if value in aliases:
        return aliases[value]
    try:
        return DependencyResolutionReason(value)
    except ValueError as exc:
        raise ValueError(f"Unsupported dependency resolution reason: {value}") from exc


def _relationship_domain(
    relationship_kind: RelationshipKind,
    metadata: dict[str, Any],
    *,
    target_is_external: bool,
) -> str:
    declared = metadata.get("dependency_domain")
    if isinstance(declared, str):
        return declared
    if target_is_external or metadata.get("dependency_scope") == "external":
        return DependencyDomain.EXTERNAL.value
    if relationship_kind in {RelationshipKind.INCLUDES, RelationshipKind.CALLS}:
        return DependencyDomain.CODE.value
    if relationship_kind in {
        RelationshipKind.READS,
        RelationshipKind.WRITES,
        RelationshipKind.PRODUCES,
        RelationshipKind.CONSUMES,
        RelationshipKind.CONSUMED_BY,
    }:
        return DependencyDomain.DATA.value
    if relationship_kind is RelationshipKind.TRIGGERS:
        return DependencyDomain.RUNTIME_LAUNCH.value
    return DependencyDomain.SCHEDULER.value


def _add_unresolved(
    unresolved: dict[str, UnresolvedDependency],
    *,
    workload: Workload,
    source_id: str,
    domain: DependencyDomain,
    reference: str,
    reason: DependencyResolutionReason,
    evidence: tuple[DiscoveryEvidence, ...],
    metadata: dict[str, Any] | None = None,
) -> None:
    identity = {
        "workload": workload.workload_id,
        "source": source_id,
        "domain": domain.value,
        "reference": reference,
        "reason": reason.value,
    }
    relationship_kind = (metadata or {}).get("relationship_kind")
    if relationship_kind is not None:
        identity["relationship_kind"] = relationship_kind
    macro_resolution_id = (metadata or {}).get("macro_resolution_id")
    if macro_resolution_id is not None:
        identity["macro_resolution_id"] = macro_resolution_id
    unresolved_id = stable_id("UNRES", identity)
    existing = unresolved.get(unresolved_id)
    unresolved[unresolved_id] = UnresolvedDependency(
        unresolved_id=unresolved_id,
        source_id=source_id,
        domain=domain,
        reference=reference,
        reason=reason,
        evidence=_merge_evidence(existing.evidence if existing else (), evidence),
        metadata={**(existing.metadata if existing else {}), **(metadata or {})},
    )


def _artifact_metadata_unresolved(
    workload: Workload,
    artifact: Artifact,
    unresolved: dict[str, UnresolvedDependency],
) -> None:
    for raw in artifact.metadata.get("macro_call_findings", ()):
        if not isinstance(raw, dict) or raw.get("resolution") == "resolved":
            continue
        reference = raw.get("reference")
        line = raw.get("line")
        resolution = raw.get("resolution")
        if not isinstance(reference, str) or not isinstance(line, int):
            continue
        occurrence = {
            key: raw[key]
            for key in (
                "macro_resolution_id",
                "macro_observation_id",
                "macro_strategy_digest",
                "column",
                "byte_start",
                "byte_end",
                "source_checksum",
                "span_digest",
            )
            if key in raw
        }
        evidence = _metadata_evidence(artifact, reference, line)
        if isinstance(raw.get("macro_resolution_id"), str):
            evidence = replace(
                evidence,
                evidence_id=stable_id("EV", {"macro_resolution_id": raw["macro_resolution_id"]}),
                metadata={**evidence.metadata, **occurrence},
            )
        _add_unresolved(
            unresolved,
            workload=workload,
            source_id=artifact.artifact_id,
            domain=DependencyDomain.CODE,
            reference=reference,
            reason=_reason(str(resolution)),
            evidence=(evidence,),
            metadata={
                "candidate_artifact_ids": tuple(raw.get("candidate_artifact_ids", ())),
                "candidate_definition_ids": tuple(raw.get("candidate_definition_ids", ())),
                **occurrence,
            },
        )

    static = artifact.metadata.get("sas_static")
    if isinstance(static, dict):
        for raw in static.get("dynamic_dataset_reference_details", ()):
            if not isinstance(raw, dict):
                continue
            reference = raw.get("value")
            line = raw.get("line")
            if isinstance(reference, str) and isinstance(line, int):
                relationship_kind = raw.get("relationship_kind")
                _add_unresolved(
                    unresolved,
                    workload=workload,
                    source_id=artifact.artifact_id,
                    domain=DependencyDomain.DATA,
                    reference=reference,
                    reason=DependencyResolutionReason.DYNAMIC,
                    evidence=(_metadata_evidence(artifact, reference, line),),
                    metadata={"relationship_kind": relationship_kind}
                    if relationship_kind
                    in {
                        RelationshipKind.READS.value,
                        RelationshipKind.WRITES.value,
                    }
                    else None,
                )

    for raw in artifact.metadata.get("runtime_invocations", ()):
        if not isinstance(raw, dict) or str(raw.get("resolution", "")).startswith("resolved"):
            continue
        reference = raw.get("target")
        line = raw.get("line")
        if isinstance(reference, str) and isinstance(line, int):
            try:
                method = EvidenceMethod(str(raw.get("evidence_method", "static_analysis")))
            except ValueError:
                method = EvidenceMethod.STATIC_ANALYSIS
            source = raw.get("source")
            observed_value = raw.get("observed_value")
            _add_unresolved(
                unresolved,
                workload=workload,
                source_id=artifact.artifact_id,
                domain=DependencyDomain.RUNTIME_LAUNCH,
                reference=reference,
                reason=_reason(str(raw.get("resolution"))),
                evidence=(
                    _metadata_evidence(
                        artifact,
                        reference,
                        line,
                        method=method,
                        source=source if isinstance(source, str) else None,
                        observed_value=(
                            observed_value if isinstance(observed_value, str) else None
                        ),
                    ),
                ),
                metadata={"invocation_kind": raw.get("kind")},
            )


def derive_dependency_graph(workload: Workload) -> Workload:
    """Project canonical entities and direct relationships without transitive inference."""

    nodes: dict[str, DependencyNode] = {}
    for artifact in workload.artifacts:
        nodes[artifact.artifact_id] = DependencyNode(
            node_id=artifact.artifact_id,
            kind=DependencyNodeKind.ARTIFACT,
            entity_id=artifact.artifact_id,
            label=artifact.name,
            evidence=artifact.evidence,
            metadata={
                "artifact_kind": artifact.kind.value,
                "logical_path": artifact.logical_path,
                "definition_status": artifact.metadata.get("definition_status"),
                "placeholder": bool(artifact.metadata.get("placeholder")),
            },
        )
    for dataset in workload.datasets:
        nodes[dataset.dataset_id] = DependencyNode(
            node_id=dataset.dataset_id,
            kind=DependencyNodeKind.DATASET,
            entity_id=dataset.dataset_id,
            label=dataset.name,
            evidence=dataset.evidence,
            metadata={"dataset_kind": dataset.kind.value, "system": dataset.system},
        )
    for dependency in workload.external_dependencies:
        nodes[dependency.dependency_id] = DependencyNode(
            node_id=dependency.dependency_id,
            kind=DependencyNodeKind.EXTERNAL_DEPENDENCY,
            entity_id=dependency.dependency_id,
            label=dependency.name,
            evidence=dependency.evidence,
            metadata={"dependency_kind": dependency.kind.value, "system": dependency.system},
        )

    unresolved: dict[str, UnresolvedDependency] = {}
    artifacts = {item.artifact_id: item for item in workload.artifacts}
    dependencies = {item.dependency_id: item for item in workload.external_dependencies}
    for artifact in workload.artifacts:
        _artifact_metadata_unresolved(workload, artifact, unresolved)

    edges: dict[str, DependencyEdge] = {}
    skipped_relationship_ids: list[str] = []
    canonical_access_relationship_ids = {
        item.relationship_id
        for item in (
            workload.data_lineage_analysis.accesses
            if workload.data_lineage_analysis is not None
            else ()
        )
    }
    for relationship in workload.relationships:
        if (
            workload.data_lineage_analysis is not None
            and relationship.kind in {RelationshipKind.READS, RelationshipKind.WRITES}
            and relationship.relationship_id not in canonical_access_relationship_ids
        ):
            skipped_relationship_ids.append(relationship.relationship_id)
            continue
        source_artifact = artifacts.get(relationship.source_id)
        target_artifact = artifacts.get(relationship.target_id)
        include_resolution = relationship.metadata.get("include_resolution")
        if relationship.kind is RelationshipKind.INCLUDES:
            try:
                include_state = IncludeResolutionKind(str(include_resolution))
            except ValueError as exc:
                raise ValueError(f"Unsupported include resolution: {include_resolution!r}") from exc
        else:
            include_state = None
        if (
            relationship.kind is RelationshipKind.INCLUDES
            and include_state is not IncludeResolutionKind.RESOLVED
        ):
            reference = target_artifact.logical_path if target_artifact else relationship.target_id
            assert reference is not None
            assert include_state is not None
            reason = (
                DependencyResolutionReason.UNSUPPORTED
                if include_state is IncludeResolutionKind.BOUNDARY_ESCAPE
                else _reason(include_state.value)
            )
            _add_unresolved(
                unresolved,
                workload=workload,
                source_id=relationship.source_id,
                domain=DependencyDomain.CODE,
                reference=reference,
                reason=reason,
                evidence=relationship.evidence,
                metadata={
                    "relationship_id": relationship.relationship_id,
                    "dependency_kind": RelationshipKind.INCLUDES.value,
                    "candidate_artifact_ids": relationship.metadata.get(
                        "candidate_artifact_ids", ()
                    ),
                    "include_resolution_id": relationship.metadata.get("include_resolution_id"),
                    "include_policy_digest": relationship.metadata.get("include_policy_digest"),
                },
            )
            skipped_relationship_ids.append(relationship.relationship_id)
            continue

        if (
            target_artifact is not None
            and target_artifact.metadata.get("definition_status") == "referenced_only"
        ):
            _add_unresolved(
                unresolved,
                workload=workload,
                source_id=relationship.source_id,
                domain=DependencyDomain.SCHEDULER,
                reference=target_artifact.name,
                reason=DependencyResolutionReason.EXTERNAL,
                evidence=relationship.evidence,
                metadata={"relationship_id": relationship.relationship_id},
            )
            skipped_relationship_ids.append(relationship.relationship_id)
            continue

        # Scheduler reconciliation emits the inverse PRECEDES fact alongside
        # DEPENDS_ON.  Do not project that inverse as resolved when its source
        # is the same referenced-only placeholder; the DEPENDS_ON relationship
        # above carries the unresolved observation from the real dependent.
        if (
            source_artifact is not None
            and source_artifact.metadata.get("definition_status") == "referenced_only"
        ):
            skipped_relationship_ids.append(relationship.relationship_id)
            continue

        external = dependencies.get(relationship.target_id)
        if external is not None and (
            external.kind is ExternalDependencyKind.UNRESOLVED_CONNECTION
            or external.metadata.get("resolution") == "unresolved"
        ):
            _add_unresolved(
                unresolved,
                workload=workload,
                source_id=relationship.source_id,
                domain=DependencyDomain.EXTERNAL,
                reference=external.name,
                reason=DependencyResolutionReason.EXTERNAL,
                evidence=relationship.evidence,
                metadata={"external_dependency_id": external.dependency_id},
            )
            skipped_relationship_ids.append(relationship.relationship_id)
            continue

        if relationship.source_id not in nodes or relationship.target_id not in nodes:
            skipped_relationship_ids.append(relationship.relationship_id)
            continue
        dependency_domain = _relationship_domain(
            relationship.kind,
            relationship.metadata,
            target_is_external=external is not None,
        )
        edge_id = stable_id(
            "DEPEDGE",
            {
                "workload": workload.workload_id,
                "source": relationship.source_id,
                "kind": relationship.kind.value,
                "target": relationship.target_id,
                "dependency_domain": dependency_domain,
            },
        )
        dataset_ids = relationship.metadata.get("via_dataset_ids", ())
        dataset_names = relationship.metadata.get("via_dataset_names", ())
        existing_edge = edges.get(edge_id)
        source_access_ids = tuple(
            sorted(
                {
                    *(existing_edge.metadata.get("source_access_ids", ()) if existing_edge else ()),
                    *(
                        (relationship.metadata["source_access_id"],)
                        if isinstance(relationship.metadata.get("source_access_id"), str)
                        else ()
                    ),
                }
            )
        )
        consumer_access_ids = tuple(
            sorted(
                {
                    *(
                        existing_edge.metadata.get("consumer_access_ids", ())
                        if existing_edge
                        else ()
                    ),
                    *(
                        (relationship.metadata["consumer_access_id"],)
                        if isinstance(relationship.metadata.get("consumer_access_id"), str)
                        else ()
                    ),
                }
            )
        )
        edges[edge_id] = DependencyEdge(
            edge_id=edge_id,
            source_id=relationship.source_id,
            kind=relationship.kind,
            target_id=relationship.target_id,
            relationship_ids=tuple(
                sorted(
                    {
                        relationship.relationship_id,
                        *(existing_edge.relationship_ids if existing_edge else ()),
                    }
                )
            ),
            evidence=_merge_evidence(
                existing_edge.evidence if existing_edge else (), relationship.evidence
            ),
            dataset_ids=tuple(
                sorted(
                    {
                        *(existing_edge.dataset_ids if existing_edge else ()),
                        *(str(item) for item in dataset_ids),
                    }
                )
            ),
            dataset_names=tuple(
                sorted(
                    {
                        *(existing_edge.dataset_names if existing_edge else ()),
                        *(str(item) for item in dataset_names),
                    }
                )
            ),
            metadata={
                **(existing_edge.metadata if existing_edge else {}),
                "dependency_domain": dependency_domain,
                "resolution": relationship.metadata.get("resolution"),
                "producer_resolution": relationship.metadata.get("producer_resolution"),
                "source_access_ids": source_access_ids,
                "consumer_access_ids": consumer_access_ids,
                "lineage_policy_digest": relationship.metadata.get("lineage_policy_digest"),
                "candidate_producer_access_ids": relationship.metadata.get(
                    "candidate_producer_access_ids", ()
                ),
            },
        )

    code_analysis = workload.code_dependency_analysis
    graph_identity = {
        "workload": workload.workload_id,
        "source_closure": (
            code_analysis.source_closure_digest if code_analysis is not None else None
        ),
        "code_analysis": code_analysis.analysis_id if code_analysis is not None else None,
        "edges": tuple(sorted(edges)),
        "unresolved": tuple(sorted(unresolved)),
    }
    graph = DependencyGraph(
        graph_id=stable_id("DEPGRAPH", graph_identity),
        nodes=tuple(sorted(nodes.values(), key=lambda item: item.node_id)),
        edges=tuple(sorted(edges.values(), key=lambda item: item.edge_id)),
        unresolved=tuple(sorted(unresolved.values(), key=lambda item: item.unresolved_id)),
        evidence=_merge_evidence(
            *(item.evidence for item in edges.values()),
            *(item.evidence for item in unresolved.values()),
        ),
        metadata={
            "basis": "canonical_relationship_projection",
            "scope": "observed_discovered_estate",
            "complete_enterprise_graph": False,
            "transitive_edges_inferred": False,
            "code_analysis_id": code_analysis.analysis_id if code_analysis is not None else None,
            "source_closure_digest": (
                code_analysis.source_closure_digest if code_analysis is not None else None
            ),
            "direction_semantics": {
                "calls": "caller_to_definition",
                "includes": "including_artifact_to_included_artifact",
                "reads": "artifact_to_dataset",
                "writes": "artifact_to_dataset",
                "produces": "producer_to_dataset",
                "consumed_by": "dataset_to_consumer",
                "triggers": "launcher_to_launched_artifact",
                "depends_on": "dependent_to_prerequisite",
                "precedes": "prerequisite_to_dependent",
            },
            "skipped_relationship_ids": tuple(sorted(skipped_relationship_ids)),
        },
    )
    return replace(workload, dependency_graph=graph)
