from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.failure_taxonomy import (
    EvidenceClass,
    FailureCauseReference,
    FailureClassificationRequest,
    FailureEvidenceReference,
    FailureReason,
    FailureStage,
    prepare_failure_classification,
    publish_failure_classification,
)
from smf.orchestration.lifecycle import (
    LifecycleEvidenceReference,
    LifecyclePolicy,
    LifecycleRequest,
    StageAuthority,
    prepare_lifecycle,
    publish_lifecycle,
    recover_lifecycle,
    verify_lifecycle,
    verify_lifecycle_result,
)
from smf.upstream.crypto import unsigned_payload
from smf.workload.identity import stable_id


def _write(root: Path, relative: str, value: dict[str, object]) -> tuple[str, str]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    return relative, hashlib.sha256(raw).hexdigest()


def _context(tmp_path: Path) -> tuple[LifecycleRequest, LifecyclePolicy, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    request = LifecycleRequest(
        output_root=tmp_path / "outputs",
        evidence_root=tmp_path / "evidence",
        client_id="client-01",
        deployment_id="deployment-01",
        environment_id="evaluation",
        source_id="source-01",
        source_artifact_id="source-artifact-01",
        source_artifact_digest=hashlib.sha256(b"source-artifact-01").hexdigest(),
        workload_id="workload-01",
        run_id="run-01",
        attempt_id="attempt-01",
        evaluation_time="2026-09-21T15:00:00Z",
    )
    policy = LifecyclePolicy(
        "day1-lifecycle",
        "1.0.0",
        "2026-09-21T00:00:00Z",
        "2026-09-22T00:00:00Z",
        (
            StageAuthority(
                "synthetic-test-authority",
                "test-key",
                public,
                (
                    "readiness_qualified",
                    "conversion_succeeded",
                    "execution_succeeded",
                    "validation_succeeded",
                    "repair_succeeded",
                    "human_approved",
                    "human_denied",
                    "cancellation_requested",
                ),
            ),
        ),
    )
    return request, policy, key


def _receipt(
    request: LifecycleRequest,
    key: Ed25519PrivateKey,
    sequence: int,
    kind: str,
    *,
    event_id: str | None = None,
    identity: dict[str, str] | None = None,
) -> LifecycleEvidenceReference:
    statuses = {
        "readiness_qualified": "ready",
        "conversion_succeeded": "converted",
        "execution_succeeded": "executed",
        "validation_succeeded": "validated",
        "repair_succeeded": "repaired",
        "human_approved": "approved",
        "human_denied": "denied",
        "cancellation_requested": "cancelled",
    }
    event = event_id or f"event-{sequence}"
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "receipt_id": "pending",
        "event_id": event,
        "sequence": sequence,
        "kind": kind,
        "status": statuses[kind],
        "observed_at": f"2026-09-21T14:{sequence:02d}:00Z",
        "identity": identity
        or {key: value for key, value in request.binding().items() if key != "evaluation_time"},
        "artifact_id": f"artifact-{sequence}",
        "artifact_digest": hashlib.sha256(f"artifact-{sequence}".encode()).hexdigest(),
        "authority_id": "synthetic-test-authority",
    }
    payload["receipt_id"] = stable_id(
        "ORCHREC", {name: value for name, value in payload.items() if name != "receipt_id"}
    )
    payload["proof"] = {
        "algorithm": "ed25519",
        "key_id": "test-key",
        "value": base64.b64encode(key.sign(unsigned_payload(payload))).decode(),
    }
    relative, sha = _write(request.evidence_root, f"events/{event}.json", payload)
    return LifecycleEvidenceReference(sequence, event, "stage_receipt", relative, sha)


def _failure(
    request: LifecycleRequest,
    sequence: int,
    *,
    reason: FailureReason = FailureReason.DETERMINISTIC_CONVERSION_FAILED,
) -> LifecycleEvidenceReference:
    classes = {
        FailureReason.DETERMINISTIC_CONVERSION_FAILED: (
            FailureStage.DETERMINISTIC_CONVERSION,
            EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
        ),
        FailureReason.EXECUTION_OUTCOME_UNKNOWN: (
            FailureStage.EXECUTION,
            EvidenceClass.EXECUTION_RESULT,
        ),
        FailureReason.SECURITY_BOUNDARY: (
            FailureStage.GOVERNANCE,
            EvidenceClass.SECURITY_RESULT,
        ),
    }
    stage, evidence_class = classes[reason]
    upstream = request.evidence_root / "failure-inputs"
    upstream.mkdir(parents=True, exist_ok=True)
    observed_path = upstream / f"observed-{sequence}.json"
    raw = (json.dumps({"observed": reason.value}, sort_keys=True) + "\n").encode()
    observed_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    event_id = f"failure-{sequence}"
    failure_request = FailureClassificationRequest(
        output_root=request.evidence_root,
        evidence_root=upstream,
        client_id=request.client_id,
        source_id=request.source_id,
        workload_id=request.workload_id,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
        event_id=event_id,
        stage=stage,
        reason=reason,
        evaluation_time=f"2026-09-21T14:{sequence:02d}:00Z",
        evidence=(
            FailureEvidenceReference(
                f"observed-{sequence}", evidence_class, observed_path.name, digest
            ),
        ),
        causes=(FailureCauseReference(f"observed-{sequence}", digest, "observed_in"),),
    )
    prepared = prepare_failure_classification(failure_request)
    result_path, _ = publish_failure_classification(failure_request, prepared)
    raw_result = result_path.read_bytes()
    relative = result_path.relative_to(request.evidence_root).as_posix()
    return LifecycleEvidenceReference(
        sequence,
        event_id,
        "failure_classification",
        relative,
        hashlib.sha256(raw_result).hexdigest(),
        failure_request,
    )


def test_day1_pipeline_is_replayable_but_makes_no_external_claim(tmp_path: Path) -> None:
    request, policy, key = _context(tmp_path)
    events = tuple(
        _receipt(request, key, index, kind)
        for index, kind in enumerate(
            (
                "readiness_qualified",
                "conversion_succeeded",
                "execution_succeeded",
                "validation_succeeded",
            ),
            1,
        )
    )
    prepared = prepare_lifecycle(request, policy, events)
    assert prepared.result["state"] == "validated"
    assert prepared.result["terminal"] is True
    assert [item["state_after"] for item in prepared.result["history"]] == [
        "ready",
        "converted",
        "executed",
        "validated",
    ]
    assert {item["authority"]["evidence_class"] for item in prepared.result["history"]} == {
        "synthetic_contract"
    }
    assert not any(prepared.result["claims"].values())
    paths = publish_lifecycle(request, policy, events, prepared)
    assert verify_lifecycle(request, policy, events) == prepared
    assert publish_lifecycle(request, policy, events, prepared) == paths


def test_failure_is_fully_replayed_and_bounded_repair_can_resume(tmp_path: Path) -> None:
    request, policy, key = _context(tmp_path)
    events = (
        _receipt(request, key, 1, "readiness_qualified"),
        _failure(request, 2),
        _receipt(request, key, 3, "repair_succeeded"),
        _receipt(request, key, 4, "execution_succeeded"),
        _receipt(request, key, 5, "validation_succeeded"),
    )
    prepared = prepare_lifecycle(request, policy, events)
    assert prepared.result["state"] == "validated"
    assert prepared.result["last_failure"]["next_action"] == "route_to_bounded_ai_repair"
    failure = events[1]
    assert failure.failure_request is not None
    observed = failure.failure_request.evidence_root / "observed-2.json"
    observed.write_text('{"observed":"mutated"}\n')
    with pytest.raises(ValueError, match="digest"):
        prepare_lifecycle(request, policy, events)


def test_unknown_external_outcome_and_cancel_are_terminal(tmp_path: Path) -> None:
    request, policy, key = _context(tmp_path)
    unknown = (
        _receipt(request, key, 1, "readiness_qualified"),
        _receipt(request, key, 2, "conversion_succeeded"),
        _failure(request, 3, reason=FailureReason.EXECUTION_OUTCOME_UNKNOWN),
    )
    result = prepare_lifecycle(request, policy, unknown).result
    assert result["state"] == "outcome_unknown"
    assert result["next_action"] == "reconcile_external_side_effects_do_not_retry"
    with pytest.raises(ValueError, match="cannot advance"):
        prepare_lifecycle(
            request, policy, (*unknown, _receipt(request, key, 4, "execution_succeeded"))
        )

    cancelled = (_receipt(request, key, 1, "cancellation_requested"),)
    assert prepare_lifecycle(request, policy, cancelled).result["state"] == "cancelled"
    with pytest.raises(ValueError, match="cannot advance"):
        prepare_lifecycle(
            request, policy, (*cancelled, _receipt(request, key, 2, "readiness_qualified"))
        )

    review_request, review_policy, review_key = _context(tmp_path / "review")
    pending = _failure(review_request, 1, reason=FailureReason.SECURITY_BOUNDARY)
    approved = _receipt(review_request, review_key, 2, "human_approved")
    review = prepare_lifecycle(review_request, review_policy, (pending, approved)).result
    assert review["state"] == "human_approved"
    assert review["claims"]["exception_approved"] is False

    invalid_request, invalid_policy, _ = _context(tmp_path / "invalid-stage")
    premature_execution = _failure(
        invalid_request, 1, reason=FailureReason.EXECUTION_OUTCOME_UNKNOWN
    )
    with pytest.raises(ValueError, match="failure transition precondition"):
        prepare_lifecycle(invalid_request, invalid_policy, (premature_execution,))


def test_forgery_identity_order_expiry_and_unsafe_values_fail_closed(tmp_path: Path) -> None:
    request, policy, key = _context(tmp_path)
    first = _receipt(request, key, 1, "readiness_qualified")
    path = request.evidence_root / first.relative_path
    forged = json.loads(path.read_text())
    forged["status"] = "converted"
    path.write_text(json.dumps(forged, sort_keys=True) + "\n")
    changed = replace(first, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="kind/status|signature"):
        prepare_lifecycle(request, policy, (changed,))

    request2, policy2, key2 = _context(tmp_path / "order")
    with pytest.raises(ValueError, match="out of order"):
        prepare_lifecycle(
            request2,
            policy2,
            (_receipt(request2, key2, 2, "readiness_qualified"),),
        )
    with pytest.raises(ValueError, match="not current"):
        prepare_lifecycle(replace(request2, evaluation_time=policy2.valid_until), policy2, ())
    with pytest.raises(ValueError, match="Unsafe"):
        replace(request2, workload_id="secret-canary-do-not-echo").binding()
    with pytest.raises(ValueError, match="evidence class"):
        replace(
            policy2,
            authorities=(replace(policy2.authorities[0], evidence_class="governed_runtime"),),
        ).binding()


def test_root_boundary_mutation_recovery_and_workload_isolation(tmp_path: Path) -> None:
    request, policy, key = _context(tmp_path)
    event = _receipt(request, key, 1, "readiness_qualified")
    prepared = prepare_lifecycle(request, policy, (event,))
    result_path, telemetry_path = publish_lifecycle(request, policy, (event,), prepared)
    telemetry_path.unlink()
    assert recover_lifecycle(request, policy, (event,)) == (result_path, telemetry_path)

    other = replace(request, workload_id="workload-02")
    other_event = _receipt(other, key, 1, "readiness_qualified", event_id="other-event")
    other_prepared = prepare_lifecycle(other, policy, (other_event,))
    other_result, _ = publish_lifecycle(other, policy, (other_event,), other_prepared)
    assert other_result != result_path and result_path.read_bytes()

    outside = tmp_path / "outside.json"
    outside.write_text("{}\n")
    link = request.evidence_root / "events" / "link.json"
    link.symlink_to(outside)
    with pytest.raises(ValueError, match="symlinked|regular"):
        prepare_lifecycle(
            request,
            policy,
            (
                LifecycleEvidenceReference(
                    1,
                    "link-event",
                    "stage_receipt",
                    "events/link.json",
                    hashlib.sha256(outside.read_bytes()).hexdigest(),
                ),
            ),
        )


def test_failure_ledger_roots_are_confined_and_swaps_fail_closed(tmp_path: Path) -> None:
    request, policy, _ = _context(tmp_path / "boundary")
    event = _failure(request, 1, reason=FailureReason.SECURITY_BOUNDARY)
    assert event.failure_request is not None
    original = event.failure_request

    outside_evidence = tmp_path / "outside-evidence"
    outside_evidence.mkdir()
    observed_name = original.evidence[0].relative_path
    (outside_evidence / observed_name).write_bytes(
        (original.evidence_root / observed_name).read_bytes()
    )
    with pytest.raises(ValueError, match="evidence root escapes"):
        prepare_lifecycle(
            request,
            policy,
            (replace(event, failure_request=replace(original, evidence_root=outside_evidence)),),
        )
    with pytest.raises(ValueError, match="output root escapes"):
        prepare_lifecycle(
            request,
            policy,
            (
                replace(
                    event,
                    failure_request=replace(original, output_root=tmp_path / "outside-output"),
                ),
            ),
        )
    with pytest.raises(ValueError, match="not bound to its authorized output root"):
        prepare_lifecycle(
            request,
            policy,
            (
                replace(
                    event,
                    failure_request=replace(
                        original, output_root=request.evidence_root / "different-output"
                    ),
                ),
            ),
        )

    linked_root = request.evidence_root / "linked-failure-inputs"
    linked_root.symlink_to(outside_evidence, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        prepare_lifecycle(
            request,
            policy,
            (replace(event, failure_request=replace(original, evidence_root=linked_root)),),
        )

    swap_request, swap_policy, _ = _context(tmp_path / "swap")
    swap_event = _failure(swap_request, 1, reason=FailureReason.SECURITY_BOUNDARY)
    assert swap_event.failure_request is not None
    swap_failure_request = swap_event.failure_request
    admitted_root = swap_failure_request.evidence_root
    admitted_backup = admitted_root.with_name("failure-inputs-admitted")
    admitted_root.rename(admitted_backup)
    swapped_outside = tmp_path / "swapped-outside"
    swapped_outside.mkdir()
    swapped_name = swap_failure_request.evidence[0].relative_path
    (swapped_outside / swapped_name).write_bytes((admitted_backup / swapped_name).read_bytes())
    admitted_root.symlink_to(swapped_outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        prepare_lifecycle(swap_request, swap_policy, (swap_event,))


def test_result_schema_and_recomputed_claim_forgery_fail(tmp_path: Path) -> None:
    request, policy, key = _context(tmp_path)
    event = _receipt(request, key, 1, "readiness_qualified")
    result = prepare_lifecycle(request, policy, (event,)).result
    unknown = deepcopy(result)
    unknown["unexpected"] = True
    with pytest.raises(ValueError, match="schema"):
        verify_lifecycle_result(unknown, request, policy, (event,))
    forged = deepcopy(result)
    forged["claims"]["humana_validated"] = True
    decision = {
        name: value for name, value in forged.items() if name not in {"result_id", "content_digest"}
    }
    forged["result_id"] = stable_id("ORCH01", decision)
    from smf.upstream.crypto import digest_value

    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    with pytest.raises(ValueError, match="schema|claim"):
        verify_lifecycle_result(forged, request, policy, (event,))

    state_forgery = deepcopy(result)
    state_forgery["state"] = "converted"
    state_forgery["terminal"] = False
    state_forgery["next_action"] = "execute_generated_artifact"
    decision = {
        name: value
        for name, value in state_forgery.items()
        if name not in {"result_id", "content_digest"}
    }
    state_forgery["result_id"] = stable_id("ORCH01", decision)
    state_forgery["content_digest"] = digest_value({**state_forgery, "content_digest": ""})
    with pytest.raises(ValueError, match="history final state"):
        verify_lifecycle_result(state_forgery, request, policy, (event,))

    stage_forgery = deepcopy(result)
    stage_forgery["history"][0]["evidence_id"] = "forged-stage-evidence"
    stage_forgery["history"][0]["evidence_sha256"] = hashlib.sha256(b"forged-stage").hexdigest()
    stage_forgery["history_digest"] = digest_value(stage_forgery["history"])
    decision = {
        name: value
        for name, value in stage_forgery.items()
        if name not in {"result_id", "content_digest"}
    }
    stage_forgery["result_id"] = stable_id("ORCH01", decision)
    stage_forgery["content_digest"] = digest_value({**stage_forgery, "content_digest": ""})
    with pytest.raises(ValueError, match="current governed inputs"):
        verify_lifecycle_result(stage_forgery, request, policy, (event,))

    failure_request, failure_policy, _ = _context(tmp_path / "failure-forgery")
    failure_event = _failure(failure_request, 1, reason=FailureReason.SECURITY_BOUNDARY)
    failure_result = prepare_lifecycle(failure_request, failure_policy, (failure_event,)).result
    failure_forgery = deepcopy(failure_result)
    forged_failure_id = "forged-failure-evidence"
    failure_forgery["history"][0]["evidence_id"] = forged_failure_id
    failure_forgery["history"][0]["evidence_sha256"] = hashlib.sha256(b"forged-failure").hexdigest()
    failure_forgery["last_failure"]["failure_id"] = forged_failure_id
    failure_forgery["history_digest"] = digest_value(failure_forgery["history"])
    decision = {
        name: value
        for name, value in failure_forgery.items()
        if name not in {"result_id", "content_digest"}
    }
    failure_forgery["result_id"] = stable_id("ORCH01", decision)
    failure_forgery["content_digest"] = digest_value({**failure_forgery, "content_digest": ""})
    with pytest.raises(ValueError, match="current governed inputs"):
        verify_lifecycle_result(failure_forgery, failure_request, failure_policy, (failure_event,))
