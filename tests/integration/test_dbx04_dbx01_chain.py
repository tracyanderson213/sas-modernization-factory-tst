from __future__ import annotations

from pathlib import Path

import pytest
from tests.unit.test_dbx01_remote_execution import _case as dbx01_case

from smf.execution.databricks_remote import (
    prepare_remote_execution_plan,
    publish_remote_execution_plan,
)
from smf.execution.runtime_evidence import (
    CurrentExecutionPlanEvidence,
    OutputReference,
    RuntimeEvidenceRequest,
    SyntheticRuntimeObservation,
    TaskObservation,
    prepare_runtime_evidence,
    publish_runtime_evidence,
)


def test_dbx04_replays_published_dbx01_plan_and_rejects_current_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    remote_request, remote_evidence = dbx01_case(monkeypatch, tmp_path)
    execution_plan = prepare_remote_execution_plan(remote_request, remote_evidence)
    publish_remote_execution_plan(
        execution_plan,
        remote_request,
        remote_evidence,
        output_root=tmp_path / "dbx01",
    )
    request = RuntimeEvidenceRequest(
        client_id=remote_request.client_id,
        deployment_id=remote_request.deployment_id,
        environment_id=remote_request.environment_id,
        workload_id=remote_request.workload_id,
        source_id=remote_request.source_id,
        run_id=remote_request.run_id,
        attempt_id=remote_request.attempt_id,
        package_id=remote_request.package_id,
        package_digest=remote_request.package_digest,
        execution_plan_id=execution_plan["result_id"],
        execution_plan_digest=execution_plan["content_digest"],
        evaluation_time=remote_request.evaluation_time,
    )
    observation = SyntheticRuntimeObservation(
        evidence_class="synthetic_contract",
        observation_id="dbx01-chain-observation",
        remote_run_id="synthetic-run",
        remote_task_id="synthetic-task",
        tasks=(TaskObservation("cancelled", "2026-09-21T15:59:00Z"),),
        safe_logs=("synthetic cancellation observed",),
        outputs=(
            OutputReference(
                "evidence://dbx01-chain/output",
                "e" * 64,
                "2026-09-22T16:00:00Z",
            ),
        ),
        elapsed_seconds=60,
        machine_seconds=30,
    )
    current = CurrentExecutionPlanEvidence(execution_plan, remote_request, remote_evidence)
    receipt = prepare_runtime_evidence(request, observation, current)
    path = publish_runtime_evidence(
        receipt,
        request,
        observation,
        current,
        output_root=tmp_path / "dbx04",
    )
    assert path.is_file()
    assert receipt["blockers"] == ["live_runtime_evidence_required"]

    object.__setattr__(remote_evidence.compute_result, "content_digest", "f" * 64)
    with pytest.raises(ValueError, match="identity or digest drift"):
        prepare_runtime_evidence(request, observation, current)
