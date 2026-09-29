from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

import smf.execution.runtime_evidence as runtime
from smf.execution.databricks_remote import CurrentRemoteEvidence, RemoteExecutionRequest
from smf.execution.runtime_evidence import (
    CurrentExecutionPlanEvidence,
    OutputReference,
    RuntimeEvidenceRequest,
    SyntheticRuntimeObservation,
    TaskObservation,
    prepare_runtime_evidence,
    publish_runtime_evidence,
    verify_runtime_evidence,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _case(
    monkeypatch: pytest.MonkeyPatch, *, workload_id: str = "workload"
) -> tuple[RuntimeEvidenceRequest, SyntheticRuntimeObservation, CurrentExecutionPlanEvidence]:
    remote_request = RemoteExecutionRequest(
        "client",
        "deployment",
        "environment",
        workload_id,
        "source",
        "run",
        "attempt",
        "source-artifact",
        SHA_A,
        SHA_B,
        "CVPKG-package",
        SHA_C,
        "DBPKG01-plan",
        SHA_A,
        "auth-result",
        SHA_B,
        "compute-result",
        SHA_C,
        "2026-09-21T16:00:00Z",
    )
    plan = {
        "result_id": "DBX01-plan",
        "content_digest": SHA_A,
        "state": "blocked_external_authority",
        "request": remote_request.binding(),
    }
    request = RuntimeEvidenceRequest(
        "client",
        "deployment",
        "environment",
        workload_id,
        "source",
        "run",
        "attempt",
        "CVPKG-package",
        SHA_C,
        "DBX01-plan",
        SHA_A,
        "2026-09-21T16:00:00Z",
    )
    observation = SyntheticRuntimeObservation(
        "synthetic_contract",
        "observation-1",
        "synthetic-run",
        "synthetic-task",
        (
            TaskObservation("queued", "2026-09-21T15:55:00Z"),
            TaskObservation("succeeded", "2026-09-21T15:56:00Z"),
        ),
        ("synthetic task completed without persisted output bytes",),
        (OutputReference("evidence://synthetic/output", SHA_B, "2026-09-22T16:00:00Z"),),
        60,
        45,
    )

    def replay(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(runtime, "verify_remote_execution_plan", replay)
    current = CurrentExecutionPlanEvidence(
        plan,
        remote_request,
        cast(CurrentRemoteEvidence, None),
    )
    return request, observation, current


def test_synthetic_observation_is_immutable_but_never_live_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, observation, current = _case(monkeypatch)
    result = prepare_runtime_evidence(request, observation, current)
    assert result["state"] == "blocked_evidence_gaps"
    assert result["blockers"] == ["live_runtime_evidence_required"]
    assert result["claims"] == {
        "captured": True,
        "generated": True,
        "blocked": True,
        "submitted": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "humana_ready": False,
        "production_ready": False,
        "migration_complete": False,
    }
    path = publish_runtime_evidence(
        result, request, observation, current, output_root=tmp_path / "evidence"
    )
    assert path.read_text().endswith("\n")
    assert (
        publish_runtime_evidence(
            result, request, observation, current, output_root=tmp_path / "evidence"
        )
        == path
    )


def test_missing_contradictory_unknown_and_expired_evidence_stays_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, _, current = _case(monkeypatch)
    missing = SyntheticRuntimeObservation("synthetic_contract", "missing", None, None, (), (), ())
    assert prepare_runtime_evidence(request, missing, current)["blockers"] == [
        "live_runtime_evidence_required",
        "missing_output_references",
        "missing_safe_logs",
        "missing_task_observations",
    ]
    contradictory = SyntheticRuntimeObservation(
        "synthetic_contract",
        "contradictory",
        "run-id",
        "task-id",
        (
            TaskObservation("succeeded", "2026-09-21T15:55:00Z"),
            TaskObservation("failed", "2026-09-21T15:56:00Z"),
            TaskObservation("running", "2026-09-21T15:57:00Z"),
            TaskObservation("outcome_unknown", "2026-09-21T15:58:00Z"),
        ),
        ("safe",),
        (OutputReference("evidence://expired/output", SHA_B, request.evaluation_time),),
    )
    blockers = prepare_runtime_evidence(request, contradictory, current)["blockers"]
    assert {
        "contradictory_task_states",
        "outcome_unknown",
        "expired_output_reference",
        "live_runtime_evidence_required",
    } == set(blockers)
    nonterminal = SyntheticRuntimeObservation(
        "synthetic_contract",
        "nonterminal",
        "run-id",
        "task-id",
        (TaskObservation("running", "2026-09-21T15:55:00Z"),),
        ("safe",),
        (OutputReference("evidence://pending/output", SHA_B, "2026-09-22T16:00:00Z"),),
    )
    assert (
        "missing_terminal_outcome"
        in prepare_runtime_evidence(request, nonterminal, current)["blockers"]
    )


def test_secret_future_timestamp_and_unsafe_reference_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, observation, current = _case(monkeypatch)
    with pytest.raises(ValueError, match="log entry is unsafe"):
        prepare_runtime_evidence(
            request,
            SyntheticRuntimeObservation(
                **{**observation.__dict__, "safe_logs": ("secret-canary-do-not-persist",)}
            ),
            current,
        )
    with pytest.raises(ValueError, match="future"):
        prepare_runtime_evidence(
            request,
            SyntheticRuntimeObservation(
                **{
                    **observation.__dict__,
                    "tasks": (TaskObservation("running", "2026-09-21T16:00:01Z"),),
                }
            ),
            current,
        )
    with pytest.raises(ValueError, match="reference is unsafe"):
        OutputReference("evidence://safe/../escape", SHA_A, "2026-09-22T16:00:00Z").binding()


def test_identity_plan_drift_current_replay_and_recomputed_forgery_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, observation, current = _case(monkeypatch)
    result = prepare_runtime_evidence(request, observation, current)
    with pytest.raises(ValueError, match="identity mismatch"):
        prepare_runtime_evidence(
            RuntimeEvidenceRequest(**{**request.binding(), "source_id": "other-source"}),
            observation,
            current,
        )
    forged = deepcopy(result)
    forged["claims"]["executed"] = True
    decision = {
        key: value for key, value in forged.items() if key not in {"receipt_id", "content_digest"}
    }
    forged["receipt_id"] = stable_id("DBX04", decision)
    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    with pytest.raises(ValueError, match="schema|claim"):
        verify_runtime_evidence(forged, request, observation, current)

    def reject_replay(*args: Any, **kwargs: Any) -> None:
        raise ValueError("current execution plan mutation")

    monkeypatch.setattr(runtime, "verify_remote_execution_plan", reject_replay)
    with pytest.raises(ValueError, match="current execution plan mutation"):
        verify_runtime_evidence(result, request, observation, current)


def test_public_verification_rejects_observation_and_manifest_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, observation, current = _case(monkeypatch)
    result = prepare_runtime_evidence(request, observation, current)
    changed = SyntheticRuntimeObservation(
        **{**observation.__dict__, "safe_logs": ("different safe synthetic log",)}
    )
    with pytest.raises(ValueError, match="current governed inputs"):
        verify_runtime_evidence(result, request, changed, current)
    forged = deepcopy(result)
    forged["implementation_manifest"][0]["sha256"] = "f" * 64
    decision = {
        key: value for key, value in forged.items() if key not in {"receipt_id", "content_digest"}
    }
    forged["receipt_id"] = stable_id("DBX04", decision)
    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    with pytest.raises(ValueError, match="implementation manifest"):
        verify_runtime_evidence(forged, request, observation, current)


def test_workloads_publish_to_isolated_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first_request, first_observation, first_current = _case(monkeypatch)
    first = prepare_runtime_evidence(first_request, first_observation, first_current)
    first_path = publish_runtime_evidence(
        first,
        first_request,
        first_observation,
        first_current,
        output_root=tmp_path,
    )
    second_request, second_observation, second_current = _case(
        monkeypatch, workload_id="other-workload"
    )
    second = prepare_runtime_evidence(second_request, second_observation, second_current)
    second_path = publish_runtime_evidence(
        second,
        second_request,
        second_observation,
        second_current,
        output_root=tmp_path,
    )
    assert first_path != second_path
    assert first["receipt_id"] != second["receipt_id"]


def test_publication_rejects_symlinked_output_ancestor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, observation, current = _case(monkeypatch)
    result = prepare_runtime_evidence(request, observation, current)
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "runs").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        publish_runtime_evidence(result, request, observation, current, output_root=root)
