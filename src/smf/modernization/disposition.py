"""Modernization disposition decision-input derivation.

WLD-11 bridges discovered current-state facts into governed modernization
assessment. Discovery context is summarized for every proposed workload
boundary without autonomously choosing RETIRE, CONSOLIDATE, REPLACE,
RE-ENGINEER, CONVERT, or PRESERVE.
"""

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    ConsumerResolution,
    DispositionDecisionStatus,
    ModernizationDispositionInput,
    Workload,
    WorkloadBoundary,
)


def _boundary_context(workload: Workload, boundary: WorkloadBoundary) -> dict[str, object]:
    outputs = {item.output_id: item for item in workload.outputs}
    boundary_outputs = [outputs[item_id] for item_id in boundary.output_ids if item_id in outputs]
    unresolved_outputs = sum(
        1 for item in boundary_outputs if item.consumer_resolution is ConsumerResolution.UNRESOLVED
    )
    partial_outputs = sum(
        1 for item in boundary_outputs if item.consumer_resolution is ConsumerResolution.PARTIAL
    )
    unresolved_adjacent = tuple(
        sorted(boundary.metadata.get("unresolved_adjacent_artifact_ids", ()))
    )
    return {
        "basis": "canonical_discovery_evidence_summary",
        "artifact_count": len(boundary.artifact_ids),
        "dataset_count": len(boundary.dataset_ids),
        "external_dependency_count": len(boundary.external_dependency_ids),
        "output_count": len(boundary.output_ids),
        "unresolved_output_consumer_count": unresolved_outputs,
        "partial_output_consumer_count": partial_outputs,
        "unresolved_adjacent_artifact_ids": unresolved_adjacent,
        "boundary_confidence": boundary.confidence.value,
        "boundary_requires_confirmation": bool(
            boundary.metadata.get("requires_confirmation", True)
        ),
        "selected_by_discovery": False,
    }


def derive_modernization_disposition_inputs(workload: Workload) -> Workload:
    """Create unresolved decision-input records for discovered workload boundaries.

    This function deliberately does not generate or rank disposition candidates.
    Candidate generation belongs to assessment/reasoning stages, and final
    selection belongs to a governed decision. The discovery layer contributes
    only the canonical evidence context needed by those later stages.
    """

    inputs = tuple(
        ModernizationDispositionInput(
            disposition_input_id=stable_id(
                "MDI", {"workload": workload.workload_id, "boundary": boundary.boundary_id}
            ),
            boundary_id=boundary.boundary_id,
            decision_status=DispositionDecisionStatus.UNRESOLVED,
            evidence=boundary.evidence,
            metadata=_boundary_context(workload, boundary),
        )
        for boundary in workload.boundaries
    )
    metadata = {
        **workload.metadata,
        "modernization_disposition": {
            "input_count": len(inputs),
            "selected_count": 0,
            "basis": "canonical_discovery_evidence_summary",
            "governed_selection_required": True,
        },
    }
    return replace(workload, disposition_inputs=inputs, metadata=metadata)
