"""Evidence-based RETIRE candidate detection.

MOD-02 adds deterministic assessment candidates to the WLD-11 disposition input
contract. It never selects or confirms RETIRE. Missing observations remain
coverage gaps rather than proof that a workload is unused.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Confidence,
    ConsumerResolution,
    DispositionCandidate,
    DispositionInputSource,
    ExternalDependencyKind,
    ModernizationDisposition,
    ModernizationDispositionInput,
    RelationshipKind,
    Workload,
    WorkloadBoundary,
)

_RULE_CONFIRMED_NO_CONSUMERS = "RETIRE-CONFIRMED-NO-CONSUMERS"
_RULE_NO_OBSERVED_CONSUMERS = "RETIRE-NO-OBSERVED-CONSUMERS"
_RULE_OBSERVED_CONSUMER = "RETIRE-COUNTER-OBSERVED-CONSUMER"
_RULE_OBSERVED_EXECUTION = "RETIRE-COUNTER-OBSERVED-EXECUTION"
_RULE_CROSS_BOUNDARY_DEPENDENCY = "RETIRE-COUNTER-CROSS-BOUNDARY-DEPENDENCY"
_RULE_UNRESOLVED_CONSUMER = "RETIRE-BLOCKER-UNRESOLVED-CONSUMER"
_RULE_PARTIAL_CONSUMER = "RETIRE-BLOCKER-PARTIAL-CONSUMER"
_RULE_UNRESOLVED_ADJACENT = "RETIRE-BLOCKER-UNRESOLVED-ADJACENT"
_RULE_UNRESOLVED_CONNECTION = "RETIRE-BLOCKER-UNRESOLVED-CONNECTION"
_RULE_BOUNDARY_CONFIRMATION = "RETIRE-BLOCKER-BOUNDARY-CONFIRMATION"


def _disposition_input(
    workload: Workload, boundary_id: str
) -> ModernizationDispositionInput | None:
    return next(
        (item for item in workload.disposition_inputs if item.boundary_id == boundary_id), None
    )


def _boundary_by_artifact(workload: Workload) -> dict[str, str]:
    return {
        artifact_id: boundary.boundary_id
        for boundary in workload.boundaries
        for artifact_id in boundary.artifact_ids
    }


def _rules_for_boundary(
    workload: Workload, boundary: WorkloadBoundary
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    supporting: set[str] = set()
    counter: set[str] = set()
    blockers: set[str] = set()

    outputs = {item.output_id: item for item in workload.outputs}
    boundary_outputs = [outputs[item_id] for item_id in boundary.output_ids if item_id in outputs]
    observed_consumers = {
        consumer_id for output in boundary_outputs for consumer_id in output.consumer_ids
    }
    if observed_consumers:
        counter.add(_RULE_OBSERVED_CONSUMER)
    elif boundary_outputs and all(
        output.consumer_resolution is ConsumerResolution.CONFIRMED for output in boundary_outputs
    ):
        supporting.add(_RULE_CONFIRMED_NO_CONSUMERS)
    else:
        # This is intentionally weak evidence. Absence of an observed consumer is
        # not proof that no consumer exists and therefore always requires a blocker.
        supporting.add(_RULE_NO_OBSERVED_CONSUMERS)

    for output in boundary_outputs:
        if output.consumer_resolution is ConsumerResolution.UNRESOLVED:
            blockers.add(_RULE_UNRESOLVED_CONSUMER)
        elif output.consumer_resolution is ConsumerResolution.PARTIAL:
            blockers.add(_RULE_PARTIAL_CONSUMER)

    by_artifact = _boundary_by_artifact(workload)
    boundary_artifacts = set(boundary.artifact_ids)
    for relationship in workload.relationships:
        source_boundary = by_artifact.get(relationship.source_id)
        target_boundary = by_artifact.get(relationship.target_id)
        if relationship.kind in {
            RelationshipKind.TRIGGERS,
            RelationshipKind.CALLS,
        } and (
            relationship.target_id in boundary_artifacts or target_boundary == boundary.boundary_id
        ):
            counter.add(_RULE_OBSERVED_EXECUTION)
        if (
            source_boundary == boundary.boundary_id
            and target_boundary
            not in {
                None,
                boundary.boundary_id,
            }
            and relationship.kind in {RelationshipKind.PRECEDES, RelationshipKind.TRIGGERS}
        ):
            counter.add(_RULE_CROSS_BOUNDARY_DEPENDENCY)
        if (
            target_boundary == boundary.boundary_id
            and source_boundary
            not in {
                None,
                boundary.boundary_id,
            }
            and relationship.kind is RelationshipKind.DEPENDS_ON
        ):
            counter.add(_RULE_CROSS_BOUNDARY_DEPENDENCY)

    if boundary.metadata.get("unresolved_adjacent_artifact_ids"):
        blockers.add(_RULE_UNRESOLVED_ADJACENT)
    if boundary.metadata.get("requires_confirmation", True):
        blockers.add(_RULE_BOUNDARY_CONFIRMATION)

    dependencies = {item.dependency_id: item for item in workload.external_dependencies}
    if any(
        dependencies[item_id].kind is ExternalDependencyKind.UNRESOLVED_CONNECTION
        for item_id in boundary.external_dependency_ids
        if item_id in dependencies
    ):
        blockers.add(_RULE_UNRESOLVED_CONNECTION)

    return tuple(sorted(supporting)), tuple(sorted(counter)), tuple(sorted(blockers))


def _candidate_confidence(
    supporting: tuple[str, ...], counter: tuple[str, ...], blockers: tuple[str, ...]
) -> Confidence:
    if counter:
        return Confidence.LOW
    if _RULE_CONFIRMED_NO_CONSUMERS in supporting and not blockers:
        return Confidence.HIGH
    if _RULE_CONFIRMED_NO_CONSUMERS in supporting:
        return Confidence.MEDIUM
    return Confidence.LOW


def derive_retire_candidates(workload: Workload) -> Workload:
    """Add deterministic RETIRE candidates without selecting a disposition.

    A candidate is an assessment hypothesis. Counter-evidence and unresolved
    coverage are preserved on the candidate so downstream governance can reject,
    investigate, or confirm it explicitly.
    """

    updated_inputs: list[ModernizationDispositionInput] = []
    candidate_count = 0
    for boundary in workload.boundaries:
        disposition_input = _disposition_input(workload, boundary.boundary_id)
        if disposition_input is None:
            continue
        supporting, counter, blockers = _rules_for_boundary(workload, boundary)
        confidence = _candidate_confidence(supporting, counter, blockers)
        candidate = DispositionCandidate(
            candidate_id=stable_id(
                "MDC",
                {
                    "input": disposition_input.disposition_input_id,
                    "disposition": ModernizationDisposition.RETIRE.value,
                },
            ),
            disposition=ModernizationDisposition.RETIRE,
            rationale=(
                "RETIRE is an assessment candidate only. Supporting, contradictory, "
                "and unresolved evidence must be reviewed before any governed selection."
            ),
            confidence=confidence,
            source=DispositionInputSource.ASSESSMENT,
            evidence=boundary.evidence,
            blocker_ids=blockers,
            metadata={
                "basis": "deterministic_retire_candidate_rules",
                "supporting_rule_ids": supporting,
                "counter_evidence_rule_ids": counter,
                "requires_confirmation": True,
                "selected": False,
            },
        )
        retained = tuple(
            item
            for item in disposition_input.candidates
            if item.disposition is not ModernizationDisposition.RETIRE
        )
        updated_inputs.append(replace(disposition_input, candidates=(*retained, candidate)))
        candidate_count += 1

    # Preserve inputs for any boundary not present in the current boundary set.
    updated_ids = {item.disposition_input_id for item in updated_inputs}
    updated_inputs.extend(
        item for item in workload.disposition_inputs if item.disposition_input_id not in updated_ids
    )
    metadata = {
        **workload.metadata,
        "retire_candidate_detection": {
            "candidate_count": candidate_count,
            "basis": "deterministic_retire_candidate_rules",
            "automatic_selection": False,
            "governed_confirmation_required": True,
        },
    }
    return replace(workload, disposition_inputs=tuple(updated_inputs), metadata=metadata)
