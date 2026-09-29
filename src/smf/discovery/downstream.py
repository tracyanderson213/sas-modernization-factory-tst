"""Deterministic downstream-consumer and output characterization.

WLD-08 turns produced canonical datasets/files into first-class output records.
Observed in-estate consumers are attached from CONSUMED_BY lineage edges. The
absence of an observed consumer is preserved as unresolved, never interpreted
as proof that no downstream consumer exists.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    ConsumerResolution,
    DiscoveryEvidence,
    Output,
    Relationship,
    RelationshipKind,
    Workload,
)


def _merge_evidence(*groups: tuple[DiscoveryEvidence, ...]) -> tuple[DiscoveryEvidence, ...]:
    merged: dict[str, DiscoveryEvidence] = {}
    for group in groups:
        for item in group:
            merged[item.evidence_id] = item
    return tuple(merged.values())


def derive_downstream_outputs(workload: Workload) -> Workload:
    """Build canonical output records from deterministic lineage evidence."""

    datasets = {item.dataset_id: item for item in workload.datasets}
    producers: dict[str, list[Relationship]] = {}
    consumers: dict[str, list[Relationship]] = {}
    lineage_resolutions = {
        item.dataset_id: item
        for item in (
            workload.data_lineage_analysis.dataset_resolutions
            if workload.data_lineage_analysis is not None
            else ()
        )
    }

    for relationship in workload.relationships:
        if relationship.kind is RelationshipKind.PRODUCES:
            producers.setdefault(relationship.target_id, []).append(relationship)
        elif relationship.kind is RelationshipKind.CONSUMED_BY:
            consumers.setdefault(relationship.source_id, []).append(relationship)

    outputs: list[Output] = []
    for dataset_id, producer_edges in producers.items():
        dataset = datasets.get(dataset_id)
        if dataset is None:
            continue

        consumer_edges = consumers.get(dataset_id, [])
        producer_ids = tuple(sorted({edge.source_id for edge in producer_edges}))
        consumer_ids = tuple(sorted({edge.target_id for edge in consumer_edges}))
        evidence = _merge_evidence(*(edge.evidence for edge in [*producer_edges, *consumer_edges]))
        resolution = ConsumerResolution.PARTIAL if consumer_ids else ConsumerResolution.UNRESOLVED
        lineage_resolution = lineage_resolutions.get(dataset_id)
        outputs.append(
            Output(
                output_id=stable_id(
                    "OUT",
                    {"workload": workload.workload_id, "dataset": dataset_id},
                ),
                dataset_id=dataset_id,
                producer_ids=producer_ids,
                consumer_ids=consumer_ids,
                consumer_resolution=resolution,
                evidence=evidence,
                metadata={
                    "dataset_name": dataset.name,
                    "dataset_kind": dataset.kind.value,
                    "consumer_count": len(consumer_ids),
                    "consumer_scope": "discovered_estate",
                    "producer_relationship_ids": tuple(
                        sorted(edge.relationship_id for edge in producer_edges)
                    ),
                    "consumer_relationship_ids": tuple(
                        sorted(edge.relationship_id for edge in consumer_edges)
                    ),
                    "producer_access_ids": tuple(
                        sorted(
                            str(edge.metadata["source_access_id"])
                            for edge in producer_edges
                            if isinstance(edge.metadata.get("source_access_id"), str)
                        )
                    ),
                    "consumer_access_ids": tuple(
                        sorted(
                            str(edge.metadata["consumer_access_id"])
                            for edge in consumer_edges
                            if isinstance(edge.metadata.get("consumer_access_id"), str)
                        )
                    ),
                    "producer_resolution": (
                        lineage_resolution.producer_resolution.value
                        if lineage_resolution is not None
                        else "unresolved"
                    ),
                    "candidate_producer_artifact_ids": (
                        lineage_resolution.candidate_producer_artifact_ids
                        if lineage_resolution is not None
                        else producer_ids
                    ),
                },
            )
        )

    return replace(workload, outputs=tuple(outputs))
