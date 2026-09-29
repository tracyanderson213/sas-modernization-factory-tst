"""Evidence-based CONSOLIDATE candidate detection.

MOD-03 identifies workload boundaries with evidence-backed consolidation affinity.
It does not merge workload boundaries or select a modernization disposition.
Shared infrastructure alone is treated as weak affinity, not proof of redundant
business behavior.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Confidence,
    DispositionCandidate,
    DispositionInputSource,
    ModernizationDisposition,
    ModernizationDispositionInput,
    Workload,
    WorkloadBoundary,
)

_SIGNAL_SHARED_DATASET = "CONSOLIDATE-SHARED-DATASET"
_SIGNAL_SHARED_OUTPUT_CONSUMER = "CONSOLIDATE-SHARED-OUTPUT-CONSUMER"
_SIGNAL_SHARED_EXTERNAL_DEPENDENCY = "CONSOLIDATE-SHARED-EXTERNAL-DEPENDENCY"
_BLOCKER_BOUNDARY_CONFIRMATION = "CONSOLIDATE-BLOCKER-BOUNDARY-CONFIRMATION"
_BLOCKER_UNRESOLVED_ADJACENT = "CONSOLIDATE-BLOCKER-UNRESOLVED-ADJACENT"
_BLOCKER_BEHAVIOR_EQUIVALENCE = "CONSOLIDATE-BLOCKER-BEHAVIOR-EQUIVALENCE-NOT-ESTABLISHED"


def _disposition_inputs(workload: Workload) -> dict[str, ModernizationDispositionInput]:
    return {item.boundary_id: item for item in workload.disposition_inputs}


def _consumer_ids(workload: Workload, boundary: WorkloadBoundary) -> set[str]:
    outputs = {item.output_id: item for item in workload.outputs}
    return {
        consumer_id
        for output_id in boundary.output_ids
        if output_id in outputs
        for consumer_id in outputs[output_id].consumer_ids
    }


def _pair_signals(
    workload: Workload, left: WorkloadBoundary, right: WorkloadBoundary
) -> tuple[str, ...]:
    signals: set[str] = set()
    if set(left.dataset_ids) & set(right.dataset_ids):
        signals.add(_SIGNAL_SHARED_DATASET)
    if _consumer_ids(workload, left) & _consumer_ids(workload, right):
        signals.add(_SIGNAL_SHARED_OUTPUT_CONSUMER)
    if set(left.external_dependency_ids) & set(right.external_dependency_ids):
        signals.add(_SIGNAL_SHARED_EXTERNAL_DEPENDENCY)
    return tuple(sorted(signals))


def _confidence(signals: tuple[str, ...]) -> Confidence:
    # Shared consumers plus shared data is stronger structural evidence, but even
    # this does not prove equivalent business logic. MOD-08 supplies that later.
    if _SIGNAL_SHARED_OUTPUT_CONSUMER in signals and _SIGNAL_SHARED_DATASET in signals:
        return Confidence.MEDIUM
    return Confidence.LOW


def _blockers(left: WorkloadBoundary, right: WorkloadBoundary) -> tuple[str, ...]:
    blockers = {_BLOCKER_BEHAVIOR_EQUIVALENCE}
    if left.metadata.get("requires_confirmation", True) or right.metadata.get(
        "requires_confirmation", True
    ):
        blockers.add(_BLOCKER_BOUNDARY_CONFIRMATION)
    if left.metadata.get("unresolved_adjacent_artifact_ids") or right.metadata.get(
        "unresolved_adjacent_artifact_ids"
    ):
        blockers.add(_BLOCKER_UNRESOLVED_ADJACENT)
    return tuple(sorted(blockers))


def derive_consolidation_candidates(workload: Workload) -> Workload:
    """Add evidence-backed CONSOLIDATE candidates without merging workloads.

    Candidates are attached to each participating boundary and identify peer
    boundaries plus the structural signals that caused the hypothesis. No
    candidate is selected or confirmed automatically.
    """

    inputs = _disposition_inputs(workload)
    boundaries = sorted(workload.boundaries, key=lambda item: item.boundary_id)
    peers: dict[str, list[tuple[str, tuple[str, ...], tuple[str, ...], Confidence]]] = defaultdict(
        list
    )
    for index, left in enumerate(boundaries):
        for right in boundaries[index + 1 :]:
            signals = _pair_signals(workload, left, right)
            if not signals:
                continue
            blockers = _blockers(left, right)
            confidence = _confidence(signals)
            peers[left.boundary_id].append((right.boundary_id, signals, blockers, confidence))
            peers[right.boundary_id].append((left.boundary_id, signals, blockers, confidence))

    updated: list[ModernizationDispositionInput] = []
    candidate_count = 0
    for boundary in boundaries:
        disposition_input = inputs.get(boundary.boundary_id)
        if disposition_input is None:
            continue
        retained = tuple(
            item
            for item in disposition_input.candidates
            if item.disposition is not ModernizationDisposition.CONSOLIDATE
        )
        candidates: list[DispositionCandidate] = []
        for peer_id, signals, blockers, confidence in sorted(peers.get(boundary.boundary_id, [])):
            candidates.append(
                DispositionCandidate(
                    candidate_id=stable_id(
                        "MDC",
                        {
                            "input": disposition_input.disposition_input_id,
                            "disposition": ModernizationDisposition.CONSOLIDATE.value,
                            "peer": peer_id,
                        },
                    ),
                    disposition=ModernizationDisposition.CONSOLIDATE,
                    rationale=(
                        "CONSOLIDATE is an assessment hypothesis based on structural "
                        "affinity. Equivalent or redundant business behavior has not "
                        "been established and requires later analysis and governance."
                    ),
                    confidence=confidence,
                    source=DispositionInputSource.ASSESSMENT,
                    evidence=boundary.evidence,
                    blocker_ids=blockers,
                    metadata={
                        "basis": "deterministic_consolidation_affinity_rules",
                        "peer_boundary_ids": (peer_id,),
                        "supporting_signal_ids": signals,
                        "behavior_equivalence_established": False,
                        "requires_confirmation": True,
                        "selected": False,
                    },
                )
            )
        candidate_count += len(candidates)
        updated.append(replace(disposition_input, candidates=(*retained, *candidates)))

    updated_ids = {item.disposition_input_id for item in updated}
    updated.extend(
        item for item in workload.disposition_inputs if item.disposition_input_id not in updated_ids
    )
    metadata = {
        **workload.metadata,
        "consolidation_candidate_detection": {
            "candidate_count": candidate_count,
            "basis": "deterministic_consolidation_affinity_rules",
            "behavior_equivalence_established": False,
            "automatic_selection": False,
            "governed_confirmation_required": True,
        },
    }
    return replace(workload, disposition_inputs=tuple(updated), metadata=metadata)
