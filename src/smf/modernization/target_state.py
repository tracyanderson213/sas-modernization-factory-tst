"""Target-state pattern recommendation input derivation.

WLD-12 normalizes canonical current-state facts into a stable input contract for
later target-pattern recommendation. It does not recommend or select a target
architecture pattern.
"""

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    ArtifactKind,
    ConsumerResolution,
    DatasetKind,
    DispositionDecisionStatus,
    ModernizationDispositionInput,
    RelationshipKind,
    TargetDataBehavior,
    TargetExecutionBehavior,
    TargetStatePatternInput,
    Workload,
    WorkloadBoundary,
)


def _disposition_input(
    workload: Workload, boundary_id: str
) -> ModernizationDispositionInput | None:
    return next(
        (item for item in workload.disposition_inputs if item.boundary_id == boundary_id), None
    )


def _execution_behaviors(
    workload: Workload, boundary: WorkloadBoundary
) -> tuple[TargetExecutionBehavior, ...]:
    artifacts = {item.artifact_id: item for item in workload.artifacts}
    kinds = {artifacts[item_id].kind for item_id in boundary.artifact_ids if item_id in artifacts}
    values: list[TargetExecutionBehavior] = []
    if ArtifactKind.SCHEDULER_JOB in kinds:
        values.append(TargetExecutionBehavior.SCHEDULED)
    if ArtifactKind.SHELL_SCRIPT in kinds:
        values.append(TargetExecutionBehavior.SCRIPT_DRIVEN)
    return tuple(values or [TargetExecutionBehavior.UNKNOWN])


def _data_behaviors(
    workload: Workload, boundary: WorkloadBoundary
) -> tuple[TargetDataBehavior, ...]:
    member_ids = set(boundary.artifact_ids)
    dataset_ids = set(boundary.dataset_ids)
    kinds = {
        rel.kind
        for rel in workload.relationships
        if (rel.source_id in member_ids and rel.target_id in dataset_ids)
        or (rel.source_id in dataset_ids and rel.target_id in member_ids)
    }
    datasets = {item.dataset_id: item for item in workload.datasets}
    values: list[TargetDataBehavior] = []
    if RelationshipKind.READS in kinds or RelationshipKind.CONSUMES in kinds:
        values.append(TargetDataBehavior.READS_DATA)
    if RelationshipKind.WRITES in kinds:
        values.append(TargetDataBehavior.WRITES_DATA)
    if boundary.output_ids:
        values.append(TargetDataBehavior.PRODUCES_OUTPUT)
    if any(
        datasets[item_id].kind is DatasetKind.INTERMEDIATE
        for item_id in dataset_ids
        if item_id in datasets
    ):
        values.append(TargetDataBehavior.USES_INTERMEDIATE)
    return tuple(values)


def _unresolved_items(workload: Workload, boundary: WorkloadBoundary) -> tuple[str, ...]:
    outputs = {item.output_id: item for item in workload.outputs}
    unresolved = [
        f"output_consumer:{item_id}"
        for item_id in boundary.output_ids
        if item_id in outputs
        and outputs[item_id].consumer_resolution is not ConsumerResolution.CONFIRMED
    ]
    unresolved.extend(
        f"adjacent_artifact:{item_id}"
        for item_id in sorted(boundary.metadata.get("unresolved_adjacent_artifact_ids", ()))
    )
    if boundary.metadata.get("requires_confirmation", True):
        unresolved.append(f"boundary_confirmation:{boundary.boundary_id}")
    return tuple(sorted(set(unresolved)))


def derive_target_state_pattern_inputs(workload: Workload) -> Workload:
    """Derive normalized target-pattern recommendation inputs from canonical facts.

    No target platform, Databricks service, implementation pattern, or architecture
    is selected here. Recommendation belongs to later modernization capabilities.
    """

    relationship_kinds_by_boundary: dict[str, tuple[RelationshipKind, ...]] = {}
    for boundary in workload.boundaries:
        entity_ids = (
            set(boundary.artifact_ids)
            | set(boundary.dataset_ids)
            | set(boundary.external_dependency_ids)
        )
        relationship_kinds_by_boundary[boundary.boundary_id] = tuple(
            sorted(
                {
                    rel.kind
                    for rel in workload.relationships
                    if rel.source_id in entity_ids or rel.target_id in entity_ids
                },
                key=lambda item: item.value,
            )
        )

    inputs = []
    for boundary in workload.boundaries:
        disposition = _disposition_input(workload, boundary.boundary_id)
        inputs.append(
            TargetStatePatternInput(
                pattern_input_id=stable_id(
                    "TPI", {"workload": workload.workload_id, "boundary": boundary.boundary_id}
                ),
                boundary_id=boundary.boundary_id,
                disposition_input_id=(disposition.disposition_input_id if disposition else None),
                execution_behaviors=_execution_behaviors(workload, boundary),
                data_behaviors=_data_behaviors(workload, boundary),
                dataset_ids=tuple(sorted(boundary.dataset_ids)),
                external_dependency_ids=tuple(sorted(boundary.external_dependency_ids)),
                output_ids=tuple(sorted(boundary.output_ids)),
                relationship_kinds=relationship_kinds_by_boundary[boundary.boundary_id],
                selected_disposition=(disposition.selected_disposition if disposition else None),
                disposition_status=(
                    disposition.decision_status
                    if disposition
                    else DispositionDecisionStatus.UNRESOLVED
                ),
                unresolved_items=_unresolved_items(workload, boundary),
                evidence=boundary.evidence,
                metadata={
                    "basis": "canonical_current_state_evidence",
                    "target_pattern_selected": False,
                    "boundary_confidence": boundary.confidence.value,
                    "consumer_resolution_complete": not any(
                        item.startswith("output_consumer:")
                        for item in _unresolved_items(workload, boundary)
                    ),
                },
            )
        )

    metadata = {
        **workload.metadata,
        "target_state_pattern_inputs": {
            "input_count": len(inputs),
            "basis": "canonical_current_state_evidence",
            "target_pattern_selected_count": 0,
            "recommendation_engine_required": True,
        },
    }
    return replace(workload, target_state_pattern_inputs=tuple(inputs), metadata=metadata)
