from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from smf.failure_taxonomy import (
    EvidenceClass,
    FailureCauseReference,
    FailureClassificationRequest,
    FailureEvidenceReference,
    FailureReason,
    FailureStage,
    prepare_failure_classification,
    publish_failure_classification,
    recover_failure_classification,
    telemetry_from_failure,
    verify_failure_classification,
    verify_failure_telemetry,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _request(
    root: Path,
    *,
    stage: FailureStage = FailureStage.DETERMINISTIC_CONVERSION,
    reason: FailureReason = FailureReason.DETERMINISTIC_CONVERSION_FAILED,
    evidence_class: EvidenceClass = EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
    workload_id: str = "workload-01",
    event_id: str = "event-01",
    causes: tuple[FailureCauseReference, ...] | None = None,
) -> FailureClassificationRequest:
    evidence_root = root / "upstream-evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    relative_path = f"{evidence_class.value}.json"
    evidence_bytes = (
        json.dumps(
            {"evidence_class": evidence_class.value, "result": "synthetic-governed-fixture"},
            sort_keys=True,
        )
        + "\n"
    ).encode()
    (evidence_root / relative_path).write_bytes(evidence_bytes)
    evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
    bound_causes = (
        (FailureCauseReference("evidence-01", evidence_digest, "observed_in"),)
        if causes is None
        else causes
    )
    return FailureClassificationRequest(
        output_root=root / "outputs",
        evidence_root=evidence_root,
        client_id="client-01",
        source_id="source-01",
        workload_id=workload_id,
        run_id="run-01",
        attempt_id="attempt-01",
        event_id=event_id,
        stage=stage,
        reason=reason,
        evaluation_time="2026-09-21T13:30:00Z",
        evidence=(
            FailureEvidenceReference(
                "evidence-01",
                evidence_class,
                relative_path,
                evidence_digest,
            ),
        ),
        causes=bound_causes,
    )


@pytest.mark.parametrize(
    ("stage", "reason", "evidence_class", "terminal", "retryability"),
    [
        (
            FailureStage.READINESS,
            FailureReason.PREREQUISITE_MISSING,
            EvidenceClass.READINESS_RESULT,
            "blocked",
            "retry_after_evidence",
        ),
        (
            FailureStage.DISCOVERY,
            FailureReason.UNSUPPORTED_SOURCE,
            EvidenceClass.DISCOVERY_RESULT,
            "unsupported",
            "not_retryable",
        ),
        (
            FailureStage.DEPENDENCY,
            FailureReason.DEPENDENCY_UNRESOLVED,
            EvidenceClass.DEPENDENCY_RESULT,
            "blocked",
            "retry_after_evidence",
        ),
        (
            FailureStage.DETERMINISTIC_CONVERSION,
            FailureReason.DETERMINISTIC_CONVERSION_FAILED,
            EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
            "failed",
            "not_retryable",
        ),
        (
            FailureStage.DETERMINISTIC_CONVERSION,
            FailureReason.DETERMINISTIC_CONVERSION_TRANSIENT,
            EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
            "failed",
            "bounded_retry",
        ),
        (
            FailureStage.AI_FALLBACK,
            FailureReason.AI_GATEWAY_AUTHORITY_REQUIRED,
            EvidenceClass.AI_REPAIR_RESULT,
            "blocked",
            "retry_after_authority",
        ),
        (
            FailureStage.AI_FALLBACK,
            FailureReason.AI_FALLBACK_EXHAUSTED,
            EvidenceClass.AI_REPAIR_RESULT,
            "human_pending",
            "not_retryable",
        ),
        (
            FailureStage.AI_FALLBACK,
            FailureReason.AI_OUTCOME_UNKNOWN,
            EvidenceClass.AI_REPAIR_RESULT,
            "outcome_unknown",
            "outcome_unknown_do_not_retry",
        ),
        (
            FailureStage.EXECUTION,
            FailureReason.EXECUTION_REJECTED,
            EvidenceClass.EXECUTION_RESULT,
            "blocked",
            "retry_after_authority",
        ),
        (
            FailureStage.EXECUTION,
            FailureReason.EXECUTION_FAILED_NO_SIDE_EFFECT,
            EvidenceClass.EXECUTION_RESULT,
            "failed",
            "bounded_retry",
        ),
        (
            FailureStage.EXECUTION,
            FailureReason.EXECUTION_OUTCOME_UNKNOWN,
            EvidenceClass.EXECUTION_RESULT,
            "outcome_unknown",
            "outcome_unknown_do_not_retry",
        ),
        (
            FailureStage.VALIDATION,
            FailureReason.VALIDATION_MISMATCH,
            EvidenceClass.VALIDATION_RESULT,
            "failed",
            "not_retryable",
        ),
        (
            FailureStage.RECONCILIATION,
            FailureReason.RECONCILIATION_INCOMPLETE,
            EvidenceClass.RECONCILIATION_RESULT,
            "blocked",
            "retry_after_evidence",
        ),
        (
            FailureStage.VALIDATION,
            FailureReason.VALIDATION_POLICY_MISSING,
            EvidenceClass.POLICY_RESULT,
            "human_pending",
            "retry_after_authority",
        ),
        (
            FailureStage.EVIDENCE,
            FailureReason.EVIDENCE_INTEGRITY_FAILED,
            EvidenceClass.EVIDENCE_INTEGRITY_RESULT,
            "failed",
            "not_retryable",
        ),
        (
            FailureStage.GOVERNANCE,
            FailureReason.SECURITY_BOUNDARY,
            EvidenceClass.SECURITY_RESULT,
            "human_pending",
            "not_retryable",
        ),
        (
            FailureStage.ENVIRONMENT,
            FailureReason.EXTERNAL_SYSTEM_UNAVAILABLE,
            EvidenceClass.EXTERNAL_OBSERVATION,
            "blocked",
            "bounded_retry",
        ),
    ],
)
def test_every_reason_has_a_closed_machine_actionable_policy(
    tmp_path: Path,
    stage: FailureStage,
    reason: FailureReason,
    evidence_class: EvidenceClass,
    terminal: str,
    retryability: str,
) -> None:
    prepared = prepare_failure_classification(
        _request(tmp_path, stage=stage, reason=reason, evidence_class=evidence_class)
    )

    assert prepared.result["classification"]["terminal_disposition"] == terminal
    assert prepared.result["classification"]["retryability"] == retryability
    assert prepared.result["classification"]["next_action"]
    assert prepared.telemetry["lifecycle"] == prepared.result["lifecycle"]
    assert not any(prepared.result["claims"].values())


def test_deterministic_failure_routes_to_bounded_ai_without_invoking_it(tmp_path: Path) -> None:
    prepared = prepare_failure_classification(_request(tmp_path))

    assert prepared.result["classification"] == {
        "stage": "deterministic_conversion",
        "reason_code": "deterministic_conversion_failed",
        "category": "conversion",
        "owner": "migration_engineering",
        "retryability": "not_retryable",
        "repairability": "ai_candidate",
        "blocker_class": "technical",
        "terminal_disposition": "failed",
        "next_action": "route_to_bounded_ai_repair",
        "side_effect_state": "not_attempted",
    }
    assert prepared.result["lifecycle"] == {
        "generated": "failed",
        "executed": "not_attempted",
        "validated": "not_attempted",
        "parity": "not_attempted",
        "human_assisted": "not_observed",
    }
    assert prepared.result["claims"]["ai_gateway_invoked"] is False


def test_unknown_execution_side_effects_are_never_automatically_retried(tmp_path: Path) -> None:
    prepared = prepare_failure_classification(
        _request(
            tmp_path,
            stage=FailureStage.EXECUTION,
            reason=FailureReason.EXECUTION_OUTCOME_UNKNOWN,
            evidence_class=EvidenceClass.EXECUTION_RESULT,
        )
    )

    classification = prepared.result["classification"]
    assert classification["retryability"] == "outcome_unknown_do_not_retry"
    assert classification["next_action"] == "perform_target_readback_before_retry"
    assert classification["side_effect_state"] == "unknown"


def test_stage_evidence_and_causal_chain_contradictions_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="authoritative stage"):
        prepare_failure_classification(_request(tmp_path, stage=FailureStage.EXECUTION))
    with pytest.raises(ValueError, match="reason-specific evidence"):
        prepare_failure_classification(
            _request(tmp_path, evidence_class=EvidenceClass.EXECUTION_RESULT)
        )
    with pytest.raises(ValueError, match="explicit cause"):
        prepare_failure_classification(_request(tmp_path, causes=()))
    with pytest.raises(ValueError, match="not bound to acquired evidence"):
        prepare_failure_classification(
            _request(
                tmp_path,
                causes=(FailureCauseReference("evidence-01", _sha("wrong"), "observed_in"),),
            )
        )
    with pytest.raises(ValueError, match="cyclic or duplicated"):
        prepare_failure_classification(
            _request(
                tmp_path,
                causes=(FailureCauseReference("event-01", _sha("cause")),),
            )
        )


def test_upstream_evidence_bytes_are_root_confined_and_replayed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    prepared = prepare_failure_classification(request)
    evidence_path = request.evidence_root / request.evidence[0].relative_path
    evidence_path.write_text('{"mutated":true}\n')
    with pytest.raises(ValueError, match="digest differs"):
        verify_failure_classification(prepared.result, request)

    outside = tmp_path / "outside.json"
    outside.write_text("{}\n")
    symlink = request.evidence_root / "symlink.json"
    symlink.symlink_to(outside)
    unsafe = replace(
        request,
        evidence=(
            FailureEvidenceReference(
                "evidence-symlink",
                EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
                "symlink.json",
                hashlib.sha256(outside.read_bytes()).hexdigest(),
            ),
        ),
    )
    with pytest.raises(ValueError, match="symlinked|regular"):
        prepare_failure_classification(unsafe)

    traversal = replace(
        request,
        evidence=(
            FailureEvidenceReference(
                "evidence-traversal",
                EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
                "../outside.json",
                hashlib.sha256(outside.read_bytes()).hexdigest(),
            ),
        ),
    )
    with pytest.raises(ValueError, match="Unsafe.*evidence reference"):
        prepare_failure_classification(traversal)


def test_unsafe_identity_is_rejected_without_echoing_the_canary(tmp_path: Path) -> None:
    canary = "api-key-secret-canary"
    with pytest.raises(ValueError) as error:
        prepare_failure_classification(replace(_request(tmp_path), workload_id=canary))

    assert canary not in str(error.value)


def test_publication_replay_recovery_mutation_and_isolation(tmp_path: Path) -> None:
    root_cause = FailureCauseReference("evidence-01", _sha("unused"), "observed_in")
    base = _request(tmp_path)
    root_cause = replace(root_cause, content_digest=base.evidence[0].sha256)
    prior = FailureCauseReference("FAILRES-deadbeef", _sha("cause"))
    first_request = replace(base, causes=(root_cause, prior))
    first = prepare_failure_classification(first_request)
    result_path, telemetry_path = publish_failure_classification(first_request, first)
    assert json.loads(result_path.read_text()) == first.result
    assert json.loads(telemetry_path.read_text()) == first.telemetry
    assert publish_failure_classification(first_request, first) == (result_path, telemetry_path)

    second_request = _request(
        tmp_path,
        workload_id="workload-02",
        event_id="event-02",
    )
    second = prepare_failure_classification(second_request)
    second_path, _ = publish_failure_classification(second_request, second)
    assert second_path != result_path
    assert json.loads(result_path.read_text()) == first.result

    telemetry_path.unlink()
    recovered = recover_failure_classification(first_request)
    assert recovered == first
    assert recover_failure_classification(first_request) == first

    tampered = json.loads(result_path.read_text())
    tampered["classification"]["retryability"] = "bounded_retry"
    with pytest.raises(ValueError, match="content digest"):
        verify_failure_classification(tampered, first_request)


def test_schema_and_replay_reject_unknown_fields_and_changed_inputs(tmp_path: Path) -> None:
    request = _request(tmp_path)
    prepared = prepare_failure_classification(request)
    unknown = json.loads(json.dumps(prepared.result))
    unknown["classification"]["caller_override"] = "retry"
    with pytest.raises(ValueError, match="schema validation"):
        verify_failure_classification(unknown, request)

    changed = replace(request, evaluation_time="2026-09-21T13:31:00Z")
    with pytest.raises(ValueError, match="current governed inputs"):
        verify_failure_classification(prepared.result, changed)

    altered_telemetry = telemetry_from_failure(prepared.result)
    altered_telemetry["claims"]["validated"] = True
    with pytest.raises(ValueError, match="schema validation"):
        verify_failure_telemetry(altered_telemetry, prepared.result)
