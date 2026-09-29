"""Canonical delivery-path candidate assessment for modernization dispositions.

MOD-04 evaluates evidence for CONVERT, RE_ENGINEER, REPLACE, and PRESERVE using
WLD-11's canonical disposition contract. ``refactor`` is intentionally not a
separate disposition: refactoring that changes the implementation approach is
represented as RE_ENGINEER; bounded source translation remains CONVERT.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    Confidence,
    ConsumerResolution,
    DispositionCandidate,
    DispositionInputSource,
    ModernizationDisposition,
    ModernizationDispositionInput,
    Workload,
    WorkloadBoundary,
)

_PATH_DISPOSITIONS = {
    ModernizationDisposition.CONVERT,
    ModernizationDisposition.RE_ENGINEER,
    ModernizationDisposition.REPLACE,
    ModernizationDisposition.PRESERVE,
}


def _input_by_boundary(workload: Workload) -> dict[str, ModernizationDispositionInput]:
    return {item.boundary_id: item for item in workload.disposition_inputs}


def _artifacts(workload: Workload, boundary: WorkloadBoundary) -> tuple[Artifact, ...]:
    by_id = {item.artifact_id: item for item in workload.artifacts}
    return tuple(by_id[item_id] for item_id in boundary.artifact_ids if item_id in by_id)


def _common_blockers(workload: Workload, boundary: WorkloadBoundary) -> tuple[str, ...]:
    blockers: set[str] = set()
    if boundary.metadata.get("requires_confirmation", True):
        blockers.add("PATH-BLOCKER-BOUNDARY-CONFIRMATION")
    if boundary.metadata.get("unresolved_adjacent_artifact_ids"):
        blockers.add("PATH-BLOCKER-UNRESOLVED-ADJACENT")
    outputs = {item.output_id: item for item in workload.outputs}
    if any(
        output_id in outputs
        and outputs[output_id].consumer_resolution is not ConsumerResolution.CONFIRMED
        for output_id in boundary.output_ids
    ):
        blockers.add("PATH-BLOCKER-CONSUMER-COVERAGE")
    return tuple(sorted(blockers))


def _candidate(
    disposition_input: ModernizationDispositionInput,
    boundary: WorkloadBoundary,
    disposition: ModernizationDisposition,
    *,
    rationale: str,
    confidence: Confidence,
    signals: tuple[str, ...],
    blockers: tuple[str, ...],
) -> DispositionCandidate:
    return DispositionCandidate(
        candidate_id=stable_id(
            "MDC",
            {"input": disposition_input.disposition_input_id, "disposition": disposition.value},
        ),
        disposition=disposition,
        rationale=rationale,
        confidence=confidence,
        source=DispositionInputSource.ASSESSMENT,
        evidence=boundary.evidence,
        blocker_ids=blockers,
        metadata={
            "basis": "canonical_delivery_path_rules",
            "supporting_signal_ids": signals,
            "requires_confirmation": True,
            "selected": False,
            "refactor_is_canonical_disposition": False,
        },
    )


def _path_candidates(
    workload: Workload,
    boundary: WorkloadBoundary,
    disposition_input: ModernizationDispositionInput,
) -> tuple[DispositionCandidate, ...]:
    artifacts = _artifacts(workload, boundary)
    kinds = {item.kind for item in artifacts}
    blockers = _common_blockers(workload, boundary)
    candidates: list[DispositionCandidate] = []

    sas_kinds = {ArtifactKind.SAS_PROGRAM, ArtifactKind.SAS_MACRO, ArtifactKind.SAS_INCLUDE}
    if kinds & sas_kinds:
        candidates.append(
            _candidate(
                disposition_input,
                boundary,
                ModernizationDisposition.CONVERT,
                rationale=(
                    "CONVERT is a candidate because executable SAS source is present. "
                    "This indicates translation applicability, not semantic parity or "
                    "automatic suitability for direct conversion."
                ),
                confidence=Confidence.MEDIUM if not blockers else Confidence.LOW,
                signals=("PATH-CONVERT-SAS-SOURCE",),
                blockers=blockers,
            )
        )

    reengineer_signals: set[str] = set()
    if ArtifactKind.SCHEDULER_JOB in kinds or ArtifactKind.SHELL_SCRIPT in kinds:
        reengineer_signals.add("PATH-REENGINEER-ORCHESTRATION")
    if any(
        item.metadata.get("sas_static", {}).get("dynamic_dataset_references") for item in artifacts
    ):
        reengineer_signals.add("PATH-REENGINEER-DYNAMIC-DATA-REFERENCE")
    if boundary.external_dependency_ids:
        reengineer_signals.add("PATH-REENGINEER-EXTERNAL-DEPENDENCY")
    if reengineer_signals:
        candidates.append(
            _candidate(
                disposition_input,
                boundary,
                ModernizationDisposition.RE_ENGINEER,
                rationale=(
                    "RE_ENGINEER is a candidate because the workload includes structural "
                    "or operational behavior that may warrant redesign rather than bounded "
                    "source translation. The evidence does not itself require redesign."
                ),
                confidence=Confidence.LOW,
                signals=tuple(sorted(reengineer_signals)),
                blockers=blockers,
            )
        )

    replacement_target = boundary.metadata.get("replacement_target")
    if isinstance(replacement_target, str) and replacement_target.strip():
        candidates.append(
            _candidate(
                disposition_input,
                boundary,
                ModernizationDisposition.REPLACE,
                rationale=(
                    "REPLACE is a candidate because an explicit replacement target was "
                    "supplied by governed assessment evidence. Discovery does not infer "
                    "commercial or platform replacement products."
                ),
                confidence=Confidence.MEDIUM,
                signals=("PATH-REPLACE-EXPLICIT-TARGET",),
                blockers=blockers,
            )
        )

    if boundary.metadata.get("preserve_required") is True:
        candidates.append(
            _candidate(
                disposition_input,
                boundary,
                ModernizationDisposition.PRESERVE,
                rationale=(
                    "PRESERVE is a candidate because an explicit preservation constraint "
                    "is present. The constraint remains subject to governed confirmation."
                ),
                confidence=Confidence.MEDIUM,
                signals=("PATH-PRESERVE-EXPLICIT-CONSTRAINT",),
                blockers=blockers,
            )
        )
    return tuple(candidates)


def derive_delivery_path_candidates(workload: Workload) -> Workload:
    """Add canonical delivery-path candidates without selecting a disposition."""

    inputs = _input_by_boundary(workload)
    updated: list[ModernizationDispositionInput] = []
    candidate_count = 0
    for boundary in sorted(workload.boundaries, key=lambda item: item.boundary_id):
        disposition_input = inputs.get(boundary.boundary_id)
        if disposition_input is None:
            continue
        retained = tuple(
            item
            for item in disposition_input.candidates
            if item.disposition not in _PATH_DISPOSITIONS
        )
        candidates = _path_candidates(workload, boundary, disposition_input)
        candidate_count += len(candidates)
        updated.append(replace(disposition_input, candidates=(*retained, *candidates)))

    updated_ids = {item.disposition_input_id for item in updated}
    updated.extend(
        item for item in workload.disposition_inputs if item.disposition_input_id not in updated_ids
    )
    metadata = {
        **workload.metadata,
        "delivery_path_candidate_assessment": {
            "candidate_count": candidate_count,
            "basis": "canonical_delivery_path_rules",
            "canonical_dispositions": tuple(sorted(item.value for item in _PATH_DISPOSITIONS)),
            "refactor_is_canonical_disposition": False,
            "automatic_selection": False,
            "governed_confirmation_required": True,
        },
    }
    return replace(workload, disposition_inputs=tuple(updated), metadata=metadata)
