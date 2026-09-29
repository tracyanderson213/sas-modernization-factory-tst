from __future__ import annotations

import base64
import hashlib
import json
import os
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
from smf.immutable_files import publish_json
from smf.orchestration.lifecycle import (
    LifecycleEvidenceReference,
    LifecyclePolicy,
    LifecycleRequest,
    StageAuthority,
    prepare_lifecycle,
    publish_lifecycle,
)
from smf.orchestration.resume import (
    AttemptReplay,
    LineageReference,
    RestartAuthority,
    RestartPolicy,
    RestartRequest,
    prepare_restart_plan,
    publish_restart_plan,
    recover_restart_plan,
    verify_published_restart,
    verify_restart_plan,
)
from smf.upstream.crypto import digest_value, unsigned_payload
from smf.workload.identity import stable_id


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()


def _stage_receipt(
    request: LifecycleRequest,
    key: Ed25519PrivateKey,
    sequence: int,
    kind: str,
) -> LifecycleEvidenceReference:
    statuses = {
        "readiness_qualified": "ready",
        "conversion_succeeded": "converted",
        "execution_succeeded": "executed",
        "validation_succeeded": "validated",
        "cancellation_requested": "cancelled",
    }
    event_id = f"event-{sequence}"
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "receipt_id": "pending",
        "event_id": event_id,
        "sequence": sequence,
        "kind": kind,
        "status": statuses[kind],
        "observed_at": f"2026-09-21T14:{sequence:02d}:00Z",
        "identity": {
            name: value for name, value in request.binding().items() if name != "evaluation_time"
        },
        "artifact_id": f"artifact-{sequence}",
        "artifact_digest": hashlib.sha256(f"artifact-{sequence}".encode()).hexdigest(),
        "authority_id": "synthetic-stage-authority",
    }
    payload["receipt_id"] = stable_id(
        "ORCHREC", {name: value for name, value in payload.items() if name != "receipt_id"}
    )
    payload["proof"] = {
        "algorithm": "ed25519",
        "key_id": "stage-key",
        "value": base64.b64encode(key.sign(unsigned_payload(payload))).decode(),
    }
    path = request.evidence_root / "events" / f"{event_id}.json"
    publish_json(path, payload, "ORCH-03 synthetic stage receipt", root=request.evidence_root)
    return LifecycleEvidenceReference(
        sequence,
        event_id,
        "stage_receipt",
        path.relative_to(request.evidence_root).as_posix(),
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def _lifecycle(
    evidence_root: Path,
    stage_key: Ed25519PrivateKey,
    attempt_id: str,
    kinds: tuple[str, ...],
) -> AttemptReplay:
    request = LifecycleRequest(
        output_root=evidence_root / "attempts" / attempt_id / "output",
        evidence_root=evidence_root / "attempts" / attempt_id / "evidence",
        client_id="client-01",
        deployment_id="deployment-01",
        environment_id="evaluation",
        source_id="source-01",
        source_artifact_id="source-artifact-01",
        source_artifact_digest=hashlib.sha256(b"source").hexdigest(),
        workload_id="workload-01",
        run_id="run-01",
        attempt_id=attempt_id,
        evaluation_time="2026-09-21T15:00:00Z",
    )
    policy = LifecyclePolicy(
        "day1-lifecycle",
        "1.0.0",
        "2026-09-21T00:00:00Z",
        "2026-09-22T00:00:00Z",
        (
            StageAuthority(
                "synthetic-stage-authority",
                "stage-key",
                _public(stage_key),
                (
                    "readiness_qualified",
                    "conversion_succeeded",
                    "execution_succeeded",
                    "validation_succeeded",
                    "cancellation_requested",
                ),
            ),
        ),
    )
    events = tuple(
        _stage_receipt(request, stage_key, sequence, kind) for sequence, kind in enumerate(kinds, 1)
    )
    publish_lifecycle(request, policy, events, prepare_lifecycle(request, policy, events))
    return AttemptReplay(request, policy, events)


def _unknown_lifecycle(
    evidence_root: Path,
    stage_key: Ed25519PrivateKey,
    attempt_id: str,
) -> AttemptReplay:
    replay = _lifecycle(
        evidence_root,
        stage_key,
        attempt_id,
        ("readiness_qualified", "conversion_succeeded"),
    )
    request = replay.request
    observation_root = request.evidence_root / "failure-inputs"
    observation_path = observation_root / "execution-outcome.json"
    publish_json(
        observation_path,
        {"outcome": "unknown"},
        "ORCH-03 synthetic unknown outcome",
        root=observation_root,
    )
    observation_digest = hashlib.sha256(observation_path.read_bytes()).hexdigest()
    failure_request = FailureClassificationRequest(
        output_root=request.evidence_root,
        evidence_root=observation_root,
        client_id=request.client_id,
        source_id=request.source_id,
        workload_id=request.workload_id,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
        event_id="failure-3",
        stage=FailureStage.EXECUTION,
        reason=FailureReason.EXECUTION_OUTCOME_UNKNOWN,
        evaluation_time="2026-09-21T14:03:00Z",
        evidence=(
            FailureEvidenceReference(
                "execution-observation",
                EvidenceClass.EXECUTION_RESULT,
                observation_path.name,
                observation_digest,
            ),
        ),
        causes=(FailureCauseReference("execution-observation", observation_digest, "observed_in"),),
    )
    prepared = prepare_failure_classification(failure_request)
    result_path, _ = publish_failure_classification(failure_request, prepared)
    failure_reference = LifecycleEvidenceReference(
        3,
        "failure-3",
        "failure_classification",
        result_path.relative_to(request.evidence_root).as_posix(),
        hashlib.sha256(result_path.read_bytes()).hexdigest(),
        failure_request,
    )
    events = (*replay.events, failure_reference)
    # The prior two-event result is immutable at the same canonical path. Use a
    # distinct lifecycle output root while retaining the governed evidence root.
    updated_request = replace(
        request,
        output_root=evidence_root / "attempts" / attempt_id / "unknown-output",
    )
    prepared_lifecycle = prepare_lifecycle(updated_request, replay.policy, events)
    publish_lifecycle(updated_request, replay.policy, events, prepared_lifecycle)
    return AttemptReplay(updated_request, replay.policy, events)


def _restart_context(
    tmp_path: Path,
    replays: tuple[AttemptReplay, ...],
    lineage_key: Ed25519PrivateKey,
    *,
    max_attempts: int = 4,
    observed_at: str = "2026-09-21T15:30:00Z",
) -> tuple[RestartRequest, RestartPolicy, LineageReference]:
    latest = (
        prepare_lifecycle(replays[-1].request, replays[-1].policy, replays[-1].events).result
        if replays
        else None
    )
    request = RestartRequest(
        output_root=tmp_path / "restart-output",
        evidence_root=tmp_path / "governed-evidence",
        client_id="client-01",
        deployment_id="deployment-01",
        environment_id="evaluation",
        source_id="source-01",
        source_artifact_id="source-artifact-01",
        source_artifact_digest=hashlib.sha256(b"source").hexdigest(),
        workload_id="workload-01",
        run_id="run-01",
        restart_id="restart-01",
        evaluation_time="2026-09-21T16:00:00Z",
        expected_latest_attempt_id=(latest["identity"]["attempt_id"] if latest else None),
        expected_latest_result_id=(latest["result_id"] if latest else None),
    )
    policy = RestartPolicy(
        "day1-restart",
        "1.0.0",
        "2026-09-21T00:00:00Z",
        "2026-09-22T00:00:00Z",
        max_attempts,
        3600,
        RestartAuthority("synthetic-lineage-authority", "lineage-key", _public(lineage_key)),
    )
    attempts = []
    for ordinal, replay in enumerate(replays, 1):
        result = prepare_lifecycle(replay.request, replay.policy, replay.events).result
        attempts.append(
            {
                "ordinal": ordinal,
                "attempt_id": replay.request.attempt_id,
                "result_id": result["result_id"],
                "result_digest": result["content_digest"],
                "state": result["state"],
            }
        )
    identity = request.binding()
    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "lineage_id": "pending",
        "observed_at": observed_at,
        "identity": {
            key: identity[key]
            for key in (
                "client_id",
                "deployment_id",
                "environment_id",
                "source_id",
                "source_artifact_id",
                "source_artifact_digest",
                "workload_id",
                "run_id",
            )
        },
        "attempts": attempts,
        "authority_id": "synthetic-lineage-authority",
    }
    manifest["lineage_id"] = stable_id(
        "ORCHLINEAGE",
        {name: value for name, value in manifest.items() if name != "lineage_id"},
    )
    manifest["proof"] = {
        "algorithm": "ed25519",
        "key_id": "lineage-key",
        "value": base64.b64encode(lineage_key.sign(unsigned_payload(manifest))).decode(),
    }
    path = request.evidence_root / "lineage" / "attempts.json"
    publish_json(path, manifest, "ORCH-03 synthetic lineage", root=request.evidence_root)
    return (
        request,
        policy,
        LineageReference(
            path.relative_to(request.evidence_root).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        ),
    )


def test_ready_attempt_produces_idempotent_restart_plan_and_replays(tmp_path: Path) -> None:
    stage_key = Ed25519PrivateKey.generate()
    lineage_key = Ed25519PrivateKey.generate()
    evidence = tmp_path / "governed-evidence"
    replay = _lifecycle(evidence, stage_key, "attempt-01", ("readiness_qualified",))
    request, policy, reference = _restart_context(tmp_path, (replay,), lineage_key)

    prepared = prepare_restart_plan(request, policy, reference, (replay,))
    assert prepared.result["decision"]["state"] == "restart_planned"
    assert prepared.result["decision"]["resume_stage"] == "deterministic_conversion"
    assert prepared.result["decision"]["new_attempt_id"].startswith("ORCHATTEMPT-")
    assert prepared.result["lineage"]["authority_scope"] == "synthetic_contract"
    assert not any(prepared.result["claims"].values())
    paths = publish_restart_plan(prepared, request, policy, reference, (replay,))
    assert verify_published_restart(request, policy, reference, (replay,)) == prepared
    assert publish_restart_plan(prepared, request, policy, reference, (replay,)) == paths


def test_unknown_empty_cancelled_and_retry_boundaries_fail_closed(tmp_path: Path) -> None:
    stage_key = Ed25519PrivateKey.generate()
    lineage_key = Ed25519PrivateKey.generate()
    evidence = tmp_path / "governed-evidence"
    cancelled = _lifecycle(
        evidence,
        stage_key,
        "attempt-01",
        ("readiness_qualified", "cancellation_requested"),
    )
    request, policy, reference = _restart_context(tmp_path, (cancelled,), lineage_key)
    value = prepare_restart_plan(request, policy, reference, (cancelled,)).result
    assert value["decision"]["action"] == "stop"
    assert value["decision"]["new_attempt_id"] is None

    unknown = _unknown_lifecycle(
        tmp_path / "unknown" / "governed-evidence", stage_key, "attempt-unknown"
    )
    later = _lifecycle(
        tmp_path / "unknown" / "governed-evidence",
        stage_key,
        "attempt-later",
        ("readiness_qualified",),
    )
    unknown_request, unknown_policy, unknown_reference = _restart_context(
        tmp_path / "unknown", (unknown, later), lineage_key
    )
    unknown_result = prepare_restart_plan(
        unknown_request, unknown_policy, unknown_reference, (unknown, later)
    ).result
    assert unknown_result["decision"]["state"] == "blocked_unknown_external_effect"
    assert unknown_result["decision"]["action"] == ("reconcile_external_effects_before_retry")

    empty_request, empty_policy, empty_reference = _restart_context(
        tmp_path / "empty", (), lineage_key
    )
    empty = prepare_restart_plan(empty_request, empty_policy, empty_reference, ()).result
    assert empty["decision"]["state"] == "blocked_missing_attempt_evidence"

    # A ready attempt at the exact retry limit must not produce another attempt.
    ready = _lifecycle(
        tmp_path / "bounded" / "governed-evidence",
        stage_key,
        "attempt-ready",
        ("readiness_qualified",),
    )
    bounded_request, bounded_policy, bounded_reference = _restart_context(
        tmp_path / "bounded", (ready,), lineage_key, max_attempts=1
    )
    bounded = prepare_restart_plan(
        bounded_request, bounded_policy, bounded_reference, (ready,)
    ).result
    assert bounded["decision"]["state"] == "retry_exhausted"


def test_current_input_replay_rejects_forgery_mutation_and_isolation(tmp_path: Path) -> None:
    stage_key = Ed25519PrivateKey.generate()
    lineage_key = Ed25519PrivateKey.generate()
    replay = _lifecycle(
        tmp_path / "governed-evidence",
        stage_key,
        "attempt-01",
        ("readiness_qualified",),
    )
    request, policy, reference = _restart_context(tmp_path, (replay,), lineage_key)
    prepared = prepare_restart_plan(request, policy, reference, (replay,))

    forged = deepcopy(prepared.result)
    forged["decision"]["resume_stage"] = "execution"
    projection = {
        key: value for key, value in forged.items() if key not in {"result_id", "content_digest"}
    }
    forged["result_id"] = stable_id("ORCH03", projection)
    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    with pytest.raises(ValueError, match="current governed inputs"):
        verify_restart_plan(forged, request, policy, reference, (replay,))

    with pytest.raises(ValueError, match="lineage bytes"):
        prepare_restart_plan(
            request,
            policy,
            replace(reference, sha256=hashlib.sha256(b"forged").hexdigest()),
            (replay,),
        )
    with pytest.raises(ValueError, match="identity mismatch"):
        prepare_restart_plan(
            replace(request, workload_id="other-workload"), policy, reference, (replay,)
        )
    with pytest.raises(ValueError, match="latest pointer"):
        prepare_restart_plan(
            replace(request, expected_latest_result_id="stale-result"),
            policy,
            reference,
            (replay,),
        )
    with pytest.raises(ValueError, match="escapes"):
        prepare_restart_plan(
            request,
            policy,
            replace(reference, relative_path="../attempts.json"),
            (replay,),
        )
    with pytest.raises(ValueError, match="Unsafe") as reference_error:
        prepare_restart_plan(
            request,
            policy,
            replace(reference, relative_path="lineage/sk-test-secret-canary.json"),
            (replay,),
        )
    assert "sk-test-secret-canary" not in str(reference_error.value)

    lineage_path = request.evidence_root / reference.relative_path
    mutated = json.loads(lineage_path.read_text())
    mutated["observed_at"] = "2026-09-21T15:31:00Z"
    os.chmod(lineage_path, 0o600)
    lineage_path.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n")
    mutated_reference = replace(
        reference, sha256=hashlib.sha256(lineage_path.read_bytes()).hexdigest()
    )
    with pytest.raises(ValueError, match="signature"):
        prepare_restart_plan(request, policy, mutated_reference, (replay,))


def test_expiry_secret_symlink_and_recovery_boundaries(tmp_path: Path) -> None:
    stage_key = Ed25519PrivateKey.generate()
    lineage_key = Ed25519PrivateKey.generate()
    replay = _lifecycle(
        tmp_path / "governed-evidence",
        stage_key,
        "attempt-01",
        ("readiness_qualified",),
    )
    request, policy, reference = _restart_context(tmp_path, (replay,), lineage_key)
    with pytest.raises(ValueError, match="not current"):
        prepare_restart_plan(
            replace(request, evaluation_time=policy.valid_until), policy, reference, (replay,)
        )
    stale_replay = _lifecycle(
        tmp_path / "stale" / "governed-evidence",
        stage_key,
        "attempt-stale",
        ("readiness_qualified",),
    )
    stale_request, stale_policy, stale_reference = _restart_context(
        tmp_path / "stale",
        (stale_replay,),
        lineage_key,
        observed_at="2026-09-21T14:59:59Z",
    )
    # This manifest is correctly re-signed. Its age, not signature validity,
    # prevents it from authorizing a retry while omitting a newer attempt.
    with pytest.raises(ValueError, match="stale"):
        prepare_restart_plan(stale_request, stale_policy, stale_reference, (stale_replay,))
    with pytest.raises(ValueError, match="Unsafe") as secret_error:
        prepare_restart_plan(
            replace(request, restart_id="sk-test-secret-canary"), policy, reference, (replay,)
        )
    assert "sk-test-secret-canary" not in str(secret_error.value)

    target = request.evidence_root / reference.relative_path
    alias = request.evidence_root / "lineage" / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(ValueError, match="unsafe|symbolic|regular|published"):
        prepare_restart_plan(
            request,
            policy,
            replace(reference, relative_path=alias.relative_to(request.evidence_root).as_posix()),
            (replay,),
        )

    prepared = prepare_restart_plan(request, policy, reference, (replay,))
    result_path, telemetry_path = publish_restart_plan(
        prepared, request, policy, reference, (replay,)
    )
    os.chmod(telemetry_path, 0o600)
    telemetry_path.unlink()
    assert recover_restart_plan(request, policy, reference, (replay,)) == (
        result_path,
        telemetry_path,
    )
