"""Traceable modernization rationale and evidence records.

MOD-10 packages the decision state and canonical evidence already produced by prior
modernization stages. It does not invent a rationale, confirm a disposition, or turn
candidate evidence into a governed decision.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    DispositionDecisionStatus,
    ModernizationRationaleEvidence,
    Workload,
)


def _related_record_ids(workload: Workload, boundary_id: str) -> tuple[str, ...]:
    ids: set[str] = set()
    ids.update(
        item.finding_id
        for item in workload.logic_similarity_findings
        if boundary_id in {item.left_boundary_id, item.right_boundary_id}
    )
    ids.update(
        item.opportunity_id
        for item in workload.batch_incremental_opportunities
        if item.boundary_id == boundary_id
    )
    ids.update(
        item.opportunity_id
        for item in workload.intermediate_artifact_elimination_opportunities
        if item.boundary_id == boundary_id
    )
    ids.update(
        item.mapping_id
        for item in workload.databricks_pattern_mappings
        if item.boundary_id == boundary_id
    )
    ids.update(
        item.wave_group_id
        for item in workload.migration_wave_groups
        if boundary_id in item.boundary_ids
    )
    if workload.target_state_manifest is not None:
        ids.add(workload.target_state_manifest.manifest_id)
    return tuple(sorted(ids))


def derive_modernization_rationale_evidence(workload: Workload) -> Workload:
    """Build auditable rationale records without manufacturing decision rationale."""

    inputs = {item.boundary_id: item for item in workload.disposition_inputs}
    records: list[ModernizationRationaleEvidence] = []

    for boundary in sorted(workload.boundaries, key=lambda item: item.boundary_id):
        item = inputs.get(boundary.boundary_id)
        unresolved: set[str] = set()
        blockers: set[str] = set()
        candidate_ids: set[str] = set()
        evidence_ids: set[str] = set()

        if item is None:
            unresolved.add(f"disposition_input:{boundary.boundary_id}")
            disposition_input_id = None
            selected_disposition = None
            decision_status = DispositionDecisionStatus.UNRESOLVED
            decision_rationale = None
        else:
            disposition_input_id = item.disposition_input_id
            selected_disposition = item.selected_disposition
            decision_status = item.decision_status
            decision_rationale = item.rationale
            evidence_ids.update(evidence.evidence_id for evidence in item.evidence)
            candidate_ids.update(candidate.candidate_id for candidate in item.candidates)
            blockers.update(
                blocker_id for candidate in item.candidates for blocker_id in candidate.blocker_ids
            )
            evidence_ids.update(
                evidence.evidence_id
                for candidate in item.candidates
                for evidence in candidate.evidence
            )
            if decision_status is not DispositionDecisionStatus.CONFIRMED:
                unresolved.add(f"disposition_not_confirmed:{boundary.boundary_id}")
            if decision_status is DispositionDecisionStatus.CONFIRMED:
                if selected_disposition is None:
                    unresolved.add(f"selected_disposition:{boundary.boundary_id}")
                if not decision_rationale:
                    unresolved.add(f"decision_rationale:{boundary.boundary_id}")
                selected_candidates = tuple(
                    candidate
                    for candidate in item.candidates
                    if candidate.disposition is selected_disposition
                )
                selected_evidence = {
                    evidence.evidence_id
                    for candidate in selected_candidates
                    for evidence in candidate.evidence
                } | {evidence.evidence_id for evidence in item.evidence}
                if not selected_candidates and not selected_evidence:
                    unresolved.add(f"decision_evidence:{boundary.boundary_id}")

        record = ModernizationRationaleEvidence(
            record_id=stable_id(
                "MRE",
                {"workload": workload.workload_id, "boundary": boundary.boundary_id},
            ),
            boundary_id=boundary.boundary_id,
            disposition_input_id=disposition_input_id,
            selected_disposition=selected_disposition,
            decision_status=decision_status,
            decision_rationale=decision_rationale,
            candidate_ids=tuple(sorted(candidate_ids)),
            evidence_ids=tuple(sorted(evidence_ids)),
            related_record_ids=_related_record_ids(workload, boundary.boundary_id),
            blocker_ids=tuple(sorted(blockers)),
            unresolved_items=tuple(sorted(unresolved)),
            metadata={
                "basis": "canonical_modernization_evidence",
                "rationale_invented": False,
                "decision_changed": False,
                "candidate_evidence_is_decision": False,
                "audit_trace": True,
            },
        )
        records.append(record)

    record_by_boundary = {record.boundary_id: record for record in records}
    manifest = workload.target_state_manifest
    if manifest is not None:
        plans = tuple(
            replace(
                plan,
                rationale_record_id=(
                    record_by_boundary[plan.boundary_id].record_id
                    if plan.boundary_id in record_by_boundary
                    else None
                ),
                metadata={**plan.metadata, "rationale_generated": False},
            )
            for plan in manifest.boundary_plans
        )
        manifest = replace(
            manifest,
            boundary_plans=plans,
            metadata={
                **manifest.metadata,
                "rationale_stage": "MOD-10",
                "rationale_record_count": len(records),
                "rationale_generated": False,
            },
        )

    metadata = {
        **workload.metadata,
        "modernization_rationale_evidence": {
            "record_count": len(records),
            "basis": "canonical_modernization_evidence",
            "rationale_invented": False,
            "decision_changed": False,
            "audit_trace": True,
        },
    }
    return replace(
        workload,
        modernization_rationale_evidence=tuple(records),
        target_state_manifest=manifest,
        metadata=metadata,
    )
