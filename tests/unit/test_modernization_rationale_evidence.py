from smf.modernization.rationale import derive_modernization_rationale_evidence
from smf.workload.models import (
    Confidence,
    DiscoveryEvidence,
    DispositionCandidate,
    DispositionDecisionStatus,
    DispositionInputSource,
    EvidenceMethod,
    ModernizationDisposition,
    ModernizationDispositionInput,
    TargetStateBoundaryPlan,
    TargetStateWorkloadManifest,
    Workload,
    WorkloadBoundary,
)


def _evidence(evidence_id: str = "ev-1") -> DiscoveryEvidence:
    return DiscoveryEvidence(
        evidence_id=evidence_id,
        method=EvidenceMethod.HUMAN_CONFIRMATION,
        source="assessment",
        confidence=Confidence.CONFIRMED,
        confirmed=True,
    )


def _workload(*, confirmed: bool = True, rationale: str | None = "Governed decision.") -> Workload:
    candidate = DispositionCandidate(
        candidate_id="cand-1",
        disposition=ModernizationDisposition.CONVERT,
        rationale="SAS source is present.",
        source=DispositionInputSource.ASSESSMENT,
        evidence=(_evidence(),),
        blocker_ids=("BLOCKER-X",),
    )
    disposition = ModernizationDispositionInput(
        disposition_input_id="di-1",
        boundary_id="b-1",
        candidates=(candidate,),
        selected_disposition=ModernizationDisposition.CONVERT if confirmed else None,
        decision_status=(
            DispositionDecisionStatus.CONFIRMED
            if confirmed
            else DispositionDecisionStatus.UNRESOLVED
        ),
        rationale=rationale if confirmed else None,
        evidence=(_evidence("ev-decision"),),
    )
    manifest = TargetStateWorkloadManifest(
        manifest_id="manifest-1",
        workload_id="w-1",
        boundary_plans=(TargetStateBoundaryPlan(boundary_id="b-1"),),
    )
    return Workload(
        workload_id="w-1",
        name="w",
        boundaries=(WorkloadBoundary(boundary_id="b-1", name="one"),),
        disposition_inputs=(disposition,),
        target_state_manifest=manifest,
    )


def test_builds_one_rationale_record_per_boundary():
    result = derive_modernization_rationale_evidence(_workload())
    assert [x.boundary_id for x in result.modernization_rationale_evidence] == ["b-1"]


def test_preserves_confirmed_decision_and_rationale_verbatim():
    record = derive_modernization_rationale_evidence(_workload()).modernization_rationale_evidence[
        0
    ]
    assert record.selected_disposition is ModernizationDisposition.CONVERT
    assert record.decision_status is DispositionDecisionStatus.CONFIRMED
    assert record.decision_rationale == "Governed decision."


def test_does_not_promote_candidate_rationale_to_decision_rationale():
    record = derive_modernization_rationale_evidence(
        _workload(confirmed=False)
    ).modernization_rationale_evidence[0]
    assert record.decision_rationale is None
    assert "disposition_not_confirmed:b-1" in record.unresolved_items


def test_missing_confirmed_rationale_is_explicit_gap():
    record = derive_modernization_rationale_evidence(
        _workload(rationale=None)
    ).modernization_rationale_evidence[0]
    assert "decision_rationale:b-1" in record.unresolved_items


def test_preserves_candidate_and_decision_evidence_ids():
    record = derive_modernization_rationale_evidence(_workload()).modernization_rationale_evidence[
        0
    ]
    assert set(record.evidence_ids) == {"ev-1", "ev-decision"}
    assert record.candidate_ids == ("cand-1",)


def test_preserves_candidate_blockers_as_audit_context():
    record = derive_modernization_rationale_evidence(_workload()).modernization_rationale_evidence[
        0
    ]
    assert record.blocker_ids == ("BLOCKER-X",)
    assert record.metadata["candidate_evidence_is_decision"] is False


def test_missing_disposition_input_remains_explicitly_unresolved():
    workload = Workload(
        workload_id="w-1",
        name="w",
        boundaries=(WorkloadBoundary(boundary_id="b-1", name="one"),),
    )
    record = derive_modernization_rationale_evidence(workload).modernization_rationale_evidence[0]
    assert "disposition_input:b-1" in record.unresolved_items
    assert record.selected_disposition is None


def test_links_rationale_record_into_existing_target_manifest():
    result = derive_modernization_rationale_evidence(_workload())
    plan = result.target_state_manifest.boundary_plans[0]
    assert plan.rationale_record_id == result.modernization_rationale_evidence[0].record_id
    assert plan.metadata["rationale_generated"] is False


def test_identity_and_output_are_deterministic_on_rerun():
    first = derive_modernization_rationale_evidence(_workload())
    second = derive_modernization_rationale_evidence(first)
    assert first.modernization_rationale_evidence == second.modernization_rationale_evidence
    assert first.target_state_manifest == second.target_state_manifest


def test_existing_governed_decision_is_not_changed():
    workload = _workload()
    result = derive_modernization_rationale_evidence(workload)
    assert result.disposition_inputs == workload.disposition_inputs
    assert result.metadata["modernization_rationale_evidence"]["decision_changed"] is False
