from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import smf.execution.databricks_remote as remote
from smf.execution.databricks_auth_models import DatabricksAuthenticationState
from smf.execution.databricks_remote import (
    CurrentRemoteEvidence,
    RemoteExecutionRequest,
    SyntheticScenario,
    exercise_synthetic_transport,
    prepare_remote_execution_plan,
    publish_remote_execution_plan,
    verify_remote_execution_plan,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _request() -> RemoteExecutionRequest:
    return RemoteExecutionRequest(
        "client",
        "deployment",
        "evaluation",
        "workload",
        "source",
        "run",
        "attempt",
        "source-artifact",
        SHA_A,
        SHA_B,
        "CVPKG-package",
        SHA_C,
        "DBPKG01-plan",
        SHA_D,
        "dba-auth",
        SHA_A,
        "dcs-compute",
        SHA_B,
        "2026-09-21T16:00:00Z",
        60,
        3,
    )


def _case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[RemoteExecutionRequest, CurrentRemoteEvidence]:
    request = _request()
    package = {
        "package_id": request.package_id,
        "content_digest": request.package_digest,
        "status": "packaged",
        "generated_sha256": request.generated_sha256,
        "identity": {
            "client_id": request.client_id,
            "deployment_id": request.deployment_id,
            "environment_id": request.environment_id,
            "workload_id": request.workload_id,
            "source_artifact_id": request.source_artifact_id,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
        },
        "source": {"sha256": request.source_sha256},
    }
    catalog = {
        "result_id": request.catalog_plan_id,
        "content_digest": request.catalog_plan_digest,
        "request": {
            "client_id": request.client_id,
            "deployment_id": request.deployment_id,
            "environment_id": request.environment_id,
            "workload_id": request.workload_id,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
            "authentication_result_id": request.authentication_result_id,
            "authentication_content_digest": request.authentication_content_digest,
            "compute_result_id": request.compute_result_id,
            "compute_content_digest": request.compute_content_digest,
            "source_id": request.source_id,
        },
    }
    auth_request = SimpleNamespace(
        bindings=lambda: {
            "client_id": request.client_id,
            "deployment_id": request.deployment_id,
            "environment_id": request.environment_id,
            "workload_id": request.workload_id,
            "run_id": request.run_id,
            "workflow_attempt_id": request.attempt_id,
            "source_sha256": request.source_sha256,
            "generated_sha256": request.generated_sha256,
        }
    )
    auth = SimpleNamespace(
        authentication_request_id=request.authentication_result_id,
        content_digest=request.authentication_content_digest,
        state=DatabricksAuthenticationState.VERIFIED,
        request=auth_request.bindings(),
    )
    compute = SimpleNamespace(
        selection_request_id=request.compute_result_id,
        content_digest=request.compute_content_digest,
        request={
            "client_id": request.client_id,
            "deployment_id": request.deployment_id,
            "environment_id": request.environment_id,
            "workload_id": request.workload_id,
            "run_id": request.run_id,
            "workflow_attempt_id": request.attempt_id,
            "source_sha256": request.source_sha256,
            "generated_sha256": request.generated_sha256,
        },
    )
    monkeypatch.setattr(remote, "verify_provider_package", lambda *a, **k: package)
    monkeypatch.setattr(
        remote, "verify_unity_catalog_validation_against_inputs", lambda *a, **k: catalog
    )
    monkeypatch.setattr(remote, "load_authentication_result", lambda *a, **k: auth)
    monkeypatch.setattr(remote, "verify_compute_admission", lambda *a, **k: None)
    opaque = cast(Any, None)
    evidence = CurrentRemoteEvidence(
        tmp_path / "package.json",
        opaque,
        tmp_path / "catalog.json",
        cast(Any, SimpleNamespace(evaluation_time=request.evaluation_time)),
        opaque,
        opaque,
        opaque,
        tmp_path,
        tmp_path / "auth.json",
        cast(Any, auth_request),
        {},
        cast(Any, compute),
        cast(Any, SimpleNamespace(evaluated_at=request.evaluation_time)),
        b"source",
        b"generated",
        opaque,
        tmp_path / "readiness.json",
    )
    return request, evidence


def test_current_evidence_produces_only_blocked_immutable_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, evidence = _case(monkeypatch, tmp_path)
    result = prepare_remote_execution_plan(request, evidence)
    assert result["state"] == "blocked_external_authority"
    assert result["submission"]["enabled"] is False
    assert result["claims"] == {
        "generated": True,
        "submitted": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "humana_ready": False,
        "production_ready": False,
        "migration_complete": False,
    }
    path = publish_remote_execution_plan(result, request, evidence, output_root=tmp_path / "out")
    assert json.loads(path.read_text()) == result
    with pytest.raises(FileExistsError):
        publish_remote_execution_plan(result, request, evidence, output_root=tmp_path / "out")


def test_upstream_drift_and_forged_claims_fail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, evidence = _case(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="identity or digest drift"):
        prepare_remote_execution_plan(
            RemoteExecutionRequest(**{**request.binding(), "package_digest": "f" * 64}), evidence
        )
    result = prepare_remote_execution_plan(request, evidence)
    forged = deepcopy(result)
    forged["claims"]["executed"] = True
    decision = {k: v for k, v in forged.items() if k not in {"result_id", "content_digest"}}
    forged["result_id"] = stable_id("DBX01", decision)
    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    with pytest.raises(ValueError, match="schema|claim"):
        verify_remote_execution_plan(forged, request, evidence)


def test_public_verification_replays_current_inputs_and_rejects_coherent_forgery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, evidence = _case(monkeypatch, tmp_path)
    result = prepare_remote_execution_plan(request, evidence)
    forged = deepcopy(result)
    forged["upstream"]["package_digest"] = "f" * 64
    decision = {k: v for k, v in forged.items() if k not in {"result_id", "content_digest"}}
    forged["result_id"] = stable_id("DBX01", decision)
    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    with pytest.raises(ValueError, match="current governed inputs"):
        verify_remote_execution_plan(forged, request, evidence)


@pytest.mark.parametrize(
    "verifier",
    (
        "verify_provider_package",
        "verify_unity_catalog_validation_against_inputs",
        "load_authentication_result",
        "verify_compute_admission",
    ),
)
def test_public_verification_requires_every_current_upstream_replay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, verifier: str
) -> None:
    request, evidence = _case(monkeypatch, tmp_path)
    result = prepare_remote_execution_plan(request, evidence)

    def reject_current_mutation(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("current upstream mutation")

    monkeypatch.setattr(remote, verifier, reject_current_mutation)
    with pytest.raises(ValueError, match="current upstream mutation"):
        verify_remote_execution_plan(result, request, evidence)


def test_immutable_helper_manifest_mutation_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, evidence = _case(monkeypatch, tmp_path)
    result = prepare_remote_execution_plan(request, evidence)
    assert any(
        item["path"] == "smf/immutable_files.py" for item in result["implementation_manifest"]
    )
    forged = deepcopy(result)
    helper = next(
        item
        for item in forged["implementation_manifest"]
        if item["path"] == "smf/immutable_files.py"
    )
    helper["sha256"] = "f" * 64
    decision = {k: v for k, v in forged.items() if k not in {"result_id", "content_digest"}}
    forged["result_id"] = stable_id("DBX01", decision)
    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    with pytest.raises(ValueError, match="implementation"):
        verify_remote_execution_plan(forged, request, evidence)


def test_synthetic_submit_poll_success_is_never_live_claim() -> None:
    scenario = SyntheticScenario("accepted", ("queued", "running", "succeeded"), (1, 2, 3))
    result = exercise_synthetic_transport(_request(), scenario)
    assert result["state"] == "succeeded" and result["polls"] == 3
    assert result["evidence_class"] == "synthetic_contract"
    assert result["claims"] == {"submitted": False, "executed": False}


def test_lost_submit_response_is_unknown_and_never_retried() -> None:
    result = exercise_synthetic_transport(_request(), SyntheticScenario("lost_response"))
    assert result["state"] == "outcome_unknown" and result["retry_allowed"] is False


def test_timeout_cancels_once_and_unknown_status_stops() -> None:
    scenario = SyntheticScenario("accepted", ("running", "running"), (1, 60))
    result = exercise_synthetic_transport(_request(), scenario)
    assert result["state"] == "cancelled" and result["cancel_attempted"] is True
    unknown = exercise_synthetic_transport(
        _request(), SyntheticScenario("accepted", ("unknown",), (1,))
    )
    assert unknown["state"] == "outcome_unknown" and unknown["retry_allowed"] is False
    with pytest.raises(ValueError, match="internally owned"):
        exercise_synthetic_transport(_request(), cast(Any, object()))


def test_identity_secret_canary_and_workload_isolation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, evidence = _case(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="Unsafe"):
        RemoteExecutionRequest(
            **{**request.binding(), "workload_id": "secret-canary-do-not-echo"}
        ).binding()
    first = prepare_remote_execution_plan(request, evidence)
    other_request = RemoteExecutionRequest(**{**request.binding(), "workload_id": "other-workload"})
    catalog = {
        "result_id": other_request.catalog_plan_id,
        "content_digest": other_request.catalog_plan_digest,
        "request": {
            "client_id": other_request.client_id,
            "deployment_id": other_request.deployment_id,
            "environment_id": other_request.environment_id,
            "workload_id": other_request.workload_id,
            "run_id": other_request.run_id,
            "attempt_id": other_request.attempt_id,
            "authentication_result_id": other_request.authentication_result_id,
            "authentication_content_digest": other_request.authentication_content_digest,
            "compute_result_id": other_request.compute_result_id,
            "compute_content_digest": other_request.compute_content_digest,
            "source_id": other_request.source_id,
        },
    }
    monkeypatch.setattr(
        remote, "verify_unity_catalog_validation_against_inputs", lambda *a, **k: catalog
    )
    package = {
        "package_id": other_request.package_id,
        "content_digest": other_request.package_digest,
        "status": "packaged",
        "generated_sha256": other_request.generated_sha256,
        "source": {"sha256": other_request.source_sha256},
        "identity": {
            "client_id": other_request.client_id,
            "deployment_id": other_request.deployment_id,
            "environment_id": other_request.environment_id,
            "workload_id": other_request.workload_id,
            "source_artifact_id": other_request.source_artifact_id,
            "run_id": other_request.run_id,
            "attempt_id": other_request.attempt_id,
        },
    }
    monkeypatch.setattr(remote, "verify_provider_package", lambda *a, **k: package)
    auth = SimpleNamespace(
        authentication_request_id=other_request.authentication_result_id,
        content_digest=other_request.authentication_content_digest,
        state=DatabricksAuthenticationState.VERIFIED,
        request={
            "client_id": other_request.client_id,
            "deployment_id": other_request.deployment_id,
            "environment_id": other_request.environment_id,
            "workload_id": other_request.workload_id,
            "run_id": other_request.run_id,
            "workflow_attempt_id": other_request.attempt_id,
            "source_sha256": other_request.source_sha256,
            "generated_sha256": other_request.generated_sha256,
        },
    )
    compute = SimpleNamespace(
        selection_request_id=other_request.compute_result_id,
        content_digest=other_request.compute_content_digest,
        request=auth.request,
    )
    monkeypatch.setattr(remote, "load_authentication_result", lambda *a, **k: auth)
    other_evidence = CurrentRemoteEvidence(
        **{
            **asdict_evidence(evidence),
            "compute_result": compute,
            "authentication_request": SimpleNamespace(bindings=lambda: auth.request),
        }
    )
    second = prepare_remote_execution_plan(other_request, other_evidence)
    assert first["result_id"] != second["result_id"]


def asdict_evidence(value: CurrentRemoteEvidence) -> dict[str, Any]:
    return {name: getattr(value, name) for name in value.__dataclass_fields__}
