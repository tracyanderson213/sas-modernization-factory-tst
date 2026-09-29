"""Intermediate artifact elimination opportunity analysis.

MOD-07 identifies intermediate datasets whose current-state materialization may be
worth eliminating in a target design. It preserves lineage and downstream-coverage
uncertainty and never treats an internal-looking WORK dataset as proof that the
materialization is semantically unnecessary.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Confidence,
    ConsumerResolution,
    Dataset,
    DatasetKind,
    IntermediateArtifactEliminationOpportunity,
    RelationshipKind,
    Workload,
    WorkloadBoundary,
)


def _boundary_for_dataset(workload: Workload, dataset_id: str) -> WorkloadBoundary | None:
    matches = [b for b in workload.boundaries if dataset_id in b.dataset_ids]
    return sorted(matches, key=lambda item: item.boundary_id)[0] if matches else None


def _opportunity(
    workload: Workload,
    dataset: Dataset,
) -> IntermediateArtifactEliminationOpportunity | None:
    if dataset.kind is not DatasetKind.INTERMEDIATE:
        return None

    writes = tuple(
        sorted(
            {
                r.source_id
                for r in workload.relationships
                if r.kind is RelationshipKind.WRITES and r.target_id == dataset.dataset_id
            }
        )
    )
    reads = tuple(
        sorted(
            {
                r.source_id
                for r in workload.relationships
                if r.kind is RelationshipKind.READS and r.target_id == dataset.dataset_id
            }
        )
    )
    if not writes or not reads:
        return None

    boundary = _boundary_for_dataset(workload, dataset.dataset_id)
    if boundary is None:
        return None

    boundary_artifacts = set(boundary.artifact_ids)
    external_readers = tuple(item for item in reads if item not in boundary_artifacts)
    outputs = tuple(item for item in workload.outputs if item.dataset_id == dataset.dataset_id)

    signals = {"INTERMEDIATE-PRODUCED-AND-CONSUMED"}
    if not external_readers:
        signals.add("INTERMEDIATE-OBSERVED-READERS-WITHIN-BOUNDARY")
    if len(writes) == 1:
        signals.add("INTERMEDIATE-SINGLE-OBSERVED-PRODUCER")

    blockers = {"INTERMEDIATE-BLOCKER-SEMANTIC-NECESSITY-NOT-ESTABLISHED"}
    if boundary.metadata.get("requires_confirmation", True):
        blockers.add("INTERMEDIATE-BLOCKER-BOUNDARY-CONFIRMATION")
    if external_readers:
        blockers.add("INTERMEDIATE-BLOCKER-CROSS-BOUNDARY-CONSUMER")
    if outputs:
        blockers.add("INTERMEDIATE-BLOCKER-EXPOSED-AS-OUTPUT")
        if any(item.consumer_resolution is not ConsumerResolution.CONFIRMED for item in outputs):
            blockers.add("INTERMEDIATE-BLOCKER-DOWNSTREAM-COVERAGE-INCOMPLETE")
    else:
        blockers.add("INTERMEDIATE-BLOCKER-DOWNSTREAM-COVERAGE-NOT-ESTABLISHED")

    confidence = (
        Confidence.MEDIUM
        if not external_readers and not outputs and len(writes) == 1
        else Confidence.LOW
    )
    return IntermediateArtifactEliminationOpportunity(
        opportunity_id=stable_id(
            "IAE",
            {
                "workload": workload.workload_id,
                "boundary": boundary.boundary_id,
                "dataset": dataset.dataset_id,
            },
        ),
        boundary_id=boundary.boundary_id,
        dataset_id=dataset.dataset_id,
        producer_ids=writes,
        consumer_ids=reads,
        confidence=confidence,
        signal_ids=tuple(sorted(signals)),
        blocker_ids=tuple(sorted(blockers)),
        evidence=dataset.evidence,
        metadata={
            "basis": "intermediate_artifact_elimination_rules",
            "candidate_only": True,
            "elimination_feasibility_established": False,
            "semantic_equivalence_established": False,
            "downstream_absence_proven": False,
            "requires_confirmation": True,
        },
    )


def derive_intermediate_artifact_elimination_opportunities(workload: Workload) -> Workload:
    """Derive conservative target-design opportunities for intermediate datasets."""

    opportunities = tuple(
        item
        for dataset in sorted(workload.datasets, key=lambda item: item.dataset_id)
        if (item := _opportunity(workload, dataset)) is not None
    )
    metadata = {
        **workload.metadata,
        "intermediate_artifact_elimination_analysis": {
            "opportunity_count": len(opportunities),
            "basis": "intermediate_artifact_elimination_rules",
            "automatic_elimination": False,
            "semantic_equivalence_established": False,
            "governed_confirmation_required": True,
        },
    }
    return replace(
        workload,
        intermediate_artifact_elimination_opportunities=opportunities,
        metadata=metadata,
    )
