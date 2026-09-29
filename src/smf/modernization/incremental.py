"""Batch-to-incremental modernization opportunity analysis.

MOD-06 identifies evidence that a currently scheduled/batch-oriented workload may
be worth evaluating for incremental execution. It does not claim that change data
capture exists, that incremental semantics are safe, or that a target streaming
architecture has been selected.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    BatchIncrementalOpportunity,
    Confidence,
    DatasetKind,
    RelationshipKind,
    Workload,
    WorkloadBoundary,
)


def _artifacts(workload: Workload, boundary: WorkloadBoundary) -> tuple[Artifact, ...]:
    by_id = {item.artifact_id: item for item in workload.artifacts}
    return tuple(by_id[item_id] for item_id in boundary.artifact_ids if item_id in by_id)


def _scheduler_signals(artifacts: tuple[Artifact, ...]) -> tuple[str, ...]:
    signals: set[str] = set()
    for artifact in artifacts:
        if artifact.kind is not ArtifactKind.SCHEDULER_JOB:
            continue
        signals.add("INCREMENTAL-SCHEDULED-BATCH")
        if artifact.metadata.get("schedule"):
            signals.add("INCREMENTAL-CRON-SCHEDULE")
        if artifact.metadata.get("start_times"):
            signals.add("INCREMENTAL-FIXED-START-TIME")
        if artifact.metadata.get("days_of_week"):
            signals.add("INCREMENTAL-CALENDAR-SCHEDULE")
    return tuple(sorted(signals))


def _data_signals(workload: Workload, boundary: WorkloadBoundary) -> tuple[str, ...]:
    artifact_ids = set(boundary.artifact_ids)
    dataset_ids = set(boundary.dataset_ids)
    kinds = {
        rel.kind
        for rel in workload.relationships
        if (rel.source_id in artifact_ids and rel.target_id in dataset_ids)
        or (rel.source_id in dataset_ids and rel.target_id in artifact_ids)
    }
    signals: set[str] = set()
    if RelationshipKind.READS in kinds or RelationshipKind.CONSUMES in kinds:
        signals.add("INCREMENTAL-READS-DATA")
    if RelationshipKind.WRITES in kinds or boundary.output_ids:
        signals.add("INCREMENTAL-WRITES-OR-PRODUCES-DATA")
    return tuple(sorted(signals))


def _blockers(workload: Workload, boundary: WorkloadBoundary) -> tuple[str, ...]:
    blockers: set[str] = {
        "INCREMENTAL-BLOCKER-CHANGE-CAPTURE-NOT-ESTABLISHED",
        "INCREMENTAL-BLOCKER-INCREMENTAL-SEMANTICS-NOT-ESTABLISHED",
    }
    if boundary.metadata.get("requires_confirmation", True):
        blockers.add("INCREMENTAL-BLOCKER-BOUNDARY-CONFIRMATION")
    if boundary.metadata.get("unresolved_adjacent_artifact_ids"):
        blockers.add("INCREMENTAL-BLOCKER-UNRESOLVED-ADJACENT")
    datasets = {item.dataset_id: item for item in workload.datasets}
    if any(
        item_id in datasets and datasets[item_id].kind is DatasetKind.UNKNOWN
        for item_id in boundary.dataset_ids
    ):
        blockers.add("INCREMENTAL-BLOCKER-UNKNOWN-DATASET")
    return tuple(sorted(blockers))


def _opportunity(
    workload: Workload,
    boundary: WorkloadBoundary,
) -> BatchIncrementalOpportunity | None:
    artifacts = _artifacts(workload, boundary)
    schedule_signals = _scheduler_signals(artifacts)
    data_signals = _data_signals(workload, boundary)

    if "INCREMENTAL-SCHEDULED-BATCH" not in schedule_signals:
        return None
    if not data_signals:
        return None

    blockers = _blockers(workload, boundary)
    confidence = (
        Confidence.MEDIUM if len(schedule_signals) > 1 and len(data_signals) > 1 else Confidence.LOW
    )
    return BatchIncrementalOpportunity(
        opportunity_id=stable_id(
            "BIO", {"workload": workload.workload_id, "boundary": boundary.boundary_id}
        ),
        boundary_id=boundary.boundary_id,
        confidence=confidence,
        signal_ids=tuple(sorted((*schedule_signals, *data_signals))),
        blocker_ids=blockers,
        evidence=boundary.evidence,
        metadata={
            "basis": "batch_to_incremental_opportunity_rules",
            "candidate_only": True,
            "incremental_feasibility_established": False,
            "change_capture_established": False,
            "target_pattern_selected": False,
            "requires_confirmation": True,
        },
    )


def derive_batch_incremental_opportunities(workload: Workload) -> Workload:
    """Identify conservative batch-to-incremental assessment opportunities."""

    opportunities = tuple(
        item
        for boundary in sorted(workload.boundaries, key=lambda item: item.boundary_id)
        if (item := _opportunity(workload, boundary)) is not None
    )
    metadata = {
        **workload.metadata,
        "batch_to_incremental_opportunity_analysis": {
            "opportunity_count": len(opportunities),
            "basis": "batch_to_incremental_opportunity_rules",
            "automatic_target_selection": False,
            "incremental_feasibility_established": False,
            "governed_confirmation_required": True,
        },
    }
    return replace(workload, batch_incremental_opportunities=opportunities, metadata=metadata)
