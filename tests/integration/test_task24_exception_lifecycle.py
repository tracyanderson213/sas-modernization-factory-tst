from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from importlib.resources import files
from pathlib import Path

import pytest

from smf.exception_lifecycle import (
    _ACTION_BY_NEXT_STEP,
    ExceptionEvent,
    ExceptionEvidence,
    ExceptionLifecycleRequest,
    ExceptionState,
    ResolutionAction,
    evaluate_exception_lifecycle,
    publish_exception_lifecycle,
    verify_exception_lifecycle,
)
from smf.failure_taxonomy import (
    EvidenceClass,
    FailureCauseReference,
    FailureClassificationRequest,
    FailureEvidenceReference,
    FailureReason,
    FailureStage,
    prepare_failure_classification,
)


def _failure(
    root: Path, workload: str = "workload-a"
) -> tuple[dict[str, object], FailureClassificationRequest]:
    evidence_root = root / "failure-evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    raw = b'{"synthetic":"conversion-failed"}\n'
    (evidence_root / "failure.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    request = FailureClassificationRequest(
        output_root=root / "failure-output",
        evidence_root=evidence_root,
        client_id="client-a",
        source_id="source-a",
        workload_id=workload,
        run_id="run-a",
        attempt_id="attempt-a",
        event_id="failure-event-a",
        stage=FailureStage.DETERMINISTIC_CONVERSION,
        reason=FailureReason.DETERMINISTIC_CONVERSION_FAILED,
        evaluation_time="2026-09-21T12:00:00Z",
        evidence=(
            FailureEvidenceReference(
                "failure-proof",
                EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
                "failure.json",
                digest,
            ),
        ),
        causes=(FailureCauseReference("failure-proof", digest, "observed_in"),),
    )
    return prepare_failure_classification(request).result, request


def _request(
    root: Path,
    states: tuple[ExceptionState, ...] = (
        ExceptionState.OPEN,
        ExceptionState.PENDING_OWNER,
        ExceptionState.RESOLUTION_AUTHORIZED,
        ExceptionState.CLOSED,
    ),
    workload: str = "workload-a",
) -> ExceptionLifecycleRequest:
    failure, failure_request = _failure(root, workload)
    evidence_root = root / "resolution-evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    raw = b'{"synthetic":"owner-resolution"}\n'
    (evidence_root / "resolution.json").write_bytes(raw)
    proof = ExceptionEvidence(
        "resolution-proof", "resolution.json", hashlib.sha256(raw).hexdigest()
    )
    times = [
        "2026-09-21T12:10:00Z",
        "2026-09-21T12:20:00Z",
        "2026-09-21T12:30:00Z",
        "2026-09-21T12:40:00Z",
    ]
    events: list[ExceptionEvent] = []
    for index, state in enumerate(states, start=1):
        events.append(
            ExceptionEvent(
                event_id=f"event-{index}",
                sequence=index,
                state=state,
                event_time=times[index - 1],
                actor_id="owner-a",
                owner_role="migration_engineering",
                evidence=(proof,)
                if state in {ExceptionState.RESOLUTION_AUTHORIZED, ExceptionState.CLOSED}
                else (),
                resolution_action=ResolutionAction.REPAIR_AND_REVALIDATE
                if state is ExceptionState.RESOLUTION_AUTHORIZED
                else None,
                authority_id="authority-a"
                if state is ExceptionState.RESOLUTION_AUTHORIZED
                else None,
                valid_until="2026-09-22T13:00:00Z"
                if state is ExceptionState.RESOLUTION_AUTHORIZED
                else None,
                authorization_event_id="event-3" if state is ExceptionState.CLOSED else None,
            )
        )
    return ExceptionLifecycleRequest(
        root / "output",
        evidence_root,
        failure,
        failure_request,
        "exception-a",
        "2026-09-21T13:00:00Z",
        tuple(events),
    )


def test_authorized_resolution_and_closure_bind_exact_failure_attempt(tmp_path: Path) -> None:
    request = _request(tmp_path)
    result = evaluate_exception_lifecycle(request)
    assert result["current_state"] == "closed"
    assert result["failure"]["attempt_id"] == "attempt-a"
    assert result["claims"]["resolution_authorized"] is True
    assert result["claims"]["resolution_executed"] is False
    assert result["claims"]["parity_passed"] is False


def test_denied_is_terminal_and_never_pending_or_closed(tmp_path: Path) -> None:
    denied = _request(
        tmp_path, (ExceptionState.OPEN, ExceptionState.PENDING_OWNER, ExceptionState.DENIED)
    )
    result = evaluate_exception_lifecycle(denied)
    assert result["current_state"] == "denied"
    assert result["claims"]["resolution_authorized"] is False
    bad = replace(
        denied,
        events=denied.events
        + (
            replace(
                denied.events[-1],
                event_id="event-4",
                sequence=4,
                state=ExceptionState.CLOSED,
                event_time="2026-09-21T12:40:00Z",
                authorization_event_id="event-3",
            ),
        ),
    )
    with pytest.raises(ValueError, match="transition"):
        evaluate_exception_lifecycle(bad)


def test_unknown_transition_owner_and_stale_authority_fail(tmp_path: Path) -> None:
    request = _request(tmp_path)
    with pytest.raises(ValueError, match="owner"):
        evaluate_exception_lifecycle(
            replace(request, events=(replace(request.events[0], owner_role="wrong-owner"),))
        )
    stale = replace(request.events[2], valid_until=request.evaluation_time)
    with pytest.raises(ValueError, match="expired"):
        evaluate_exception_lifecycle(
            replace(request, events=request.events[:2] + (stale,) + request.events[3:])
        )
    skipped = replace(request, events=(request.events[0], replace(request.events[2], sequence=2)))
    with pytest.raises(ValueError, match="transition"):
        evaluate_exception_lifecycle(skipped)
    unknown = replace(request.events[0], state="unknown")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown"):
        evaluate_exception_lifecycle(replace(request, events=(unknown,)))
    wrong_action = replace(
        request.events[2], resolution_action=ResolutionAction.RETRY_FROM_CHECKPOINT
    )
    with pytest.raises(ValueError, match="contradicts"):
        evaluate_exception_lifecycle(
            replace(request, events=request.events[:2] + (wrong_action,) + request.events[3:])
        )


def test_next_action_mapping_is_exhaustive_explicit_and_fail_closed(tmp_path: Path) -> None:
    schema = json.loads(
        files("smf.schemas").joinpath("failure-classification-result.schema.json").read_text()
    )
    governed_actions = set(
        schema["properties"]["classification"]["properties"]["next_action"]["enum"]
    )
    assert set(_ACTION_BY_NEXT_STEP) == governed_actions
    assert (
        _ACTION_BY_NEXT_STEP["retry_execution_from_checkpoint"]
        is ResolutionAction.RETRY_FROM_CHECKPOINT
    )
    assert (
        _ACTION_BY_NEXT_STEP["route_to_bounded_ai_repair"] is ResolutionAction.REPAIR_AND_REVALIDATE
    )
    assert _ACTION_BY_NEXT_STEP["investigate_unknown_gateway_outcome"] is ResolutionAction.NO_ACTION

    request = _request(tmp_path)
    forged = copy.deepcopy(request.failure_result)
    forged["classification"]["next_action"] = "future_unmapped_action"
    # Isolate TASK-24's defensive boundary from FAIL-01's own replay rejection.
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            "smf.exception_lifecycle.verify_failure_classification", lambda *_: None
        )
        with pytest.raises(ValueError, match="lacks an explicit exception disposition"):
            evaluate_exception_lifecycle(replace(request, failure_result=forged))


def test_missing_or_mutated_resolution_evidence_and_failure_reject(tmp_path: Path) -> None:
    request = _request(tmp_path)
    missing = replace(request.events[2], evidence=())
    with pytest.raises(ValueError, match="lacks authority"):
        evaluate_exception_lifecycle(
            replace(request, events=request.events[:2] + (missing,) + request.events[3:])
        )
    (request.evidence_root / "resolution.json").write_text("mutated\n")
    with pytest.raises(ValueError, match="digest differs"):
        evaluate_exception_lifecycle(request)
    fresh = _request(tmp_path / "fresh")
    forged = copy.deepcopy(fresh.failure_result)
    forged["identity"]["attempt_id"] = "other-attempt"
    with pytest.raises(ValueError):
        evaluate_exception_lifecycle(replace(fresh, failure_result=forged))
    symlinked = _request(tmp_path / "symlinked")
    target = symlinked.evidence_root / "real.json"
    target.write_text("safe\n")
    link = symlinked.evidence_root / "linked.json"
    link.symlink_to(target)
    linked = replace(
        symlinked.events[2],
        evidence=(
            ExceptionEvidence("linked-proof", "linked.json", hashlib.sha256(b"safe\n").hexdigest()),
        ),
    )
    with pytest.raises(ValueError, match="symlink|regular"):
        evaluate_exception_lifecycle(
            replace(symlinked, events=symlinked.events[:2] + (linked,) + symlinked.events[3:])
        )


def test_immutable_retry_mutation_replay_and_isolation(tmp_path: Path) -> None:
    request = _request(tmp_path)
    first, path = publish_exception_lifecycle(request)
    assert publish_exception_lifecycle(request) == (first, path)
    verify_exception_lifecycle(first, request)
    with pytest.raises(ValueError, match="current governed"):
        verify_exception_lifecycle(first, replace(request, evaluation_time="2026-09-21T13:01:00Z"))
    other, other_path = publish_exception_lifecycle(
        _request(tmp_path / "other", workload="workload-b")
    )
    assert other_path != path and other["failure"]["workload_id"] == "workload-b"
    path.write_text("{}\n")
    with pytest.raises((ValueError, FileExistsError)):
        publish_exception_lifecycle(request)


def test_strict_schema_and_public_package_parity(tmp_path: Path) -> None:
    result = evaluate_exception_lifecycle(_request(tmp_path))
    unknown = copy.deepcopy(result)
    unknown["claims"]["approved"] = True
    with pytest.raises(ValueError, match="schema validation"):
        verify_exception_lifecycle(unknown, _request(tmp_path / "again"))
    root = Path(__file__).parents[2]
    assert (root / "schemas/exception-lifecycle-result.schema.json").read_bytes() == (
        root / "src/smf/schemas/exception-lifecycle-result.schema.json"
    ).read_bytes()
