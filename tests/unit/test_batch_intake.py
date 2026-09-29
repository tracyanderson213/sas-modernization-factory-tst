from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from tests.unit.batch_intake_support import make_manifest, make_policy, sign_manifest

from smf.intake import (
    IntakeRequest,
    build_intake_run_lineage,
    evaluate_batch_intake,
    verify_intake_workload,
    write_intake_result,
)
from smf.workload.lineage import lineage_path, verify_run_lineage


def _evaluate(tmp_path: Path, manifest: dict, policy) -> tuple[dict, Path]:
    out = tmp_path / "out"
    result = evaluate_batch_intake(
        IntakeRequest(manifest, policy, tmp_path / "source", out, "run-1", "attempt-1")
    )
    return result, write_intake_result(out, result, trusted_policy=policy)


def test_two_workloads_are_canonical_isolated_and_truthful(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    result, path = _evaluate(tmp_path, make_manifest(source, key), policy)
    assert result["disposition"] == "admitted"
    assert result["admitted_count"] == 2
    assert len({item["workload_id"] for item in result["decisions"]}) == 2
    assert all(
        item["readiness_input"]["authorizes_readiness"] is False for item in result["decisions"]
    )
    assert all(
        not item["telemetry"][claim]
        for item in result["decisions"]
        for claim in ("generated", "executed", "validated", "parity_passed", "certified")
    )
    decision = result["decisions"][0]
    verified = verify_intake_workload(
        path,
        output_root=tmp_path / "out",
        trusted_policy=policy,
        workload_id=decision["workload_id"],
        workload_revision_id=decision["workload_revision_id"],
        closure_digest=decision["closure_digest"],
        run_id="run-1",
        attempt_id="attempt-1",
    )
    assert verified.workload_id == decision["workload_id"]
    assert verified.sources[0].data == (source / "alpha.sas").read_bytes()


def test_repeat_is_idempotent_and_changed_bytes_create_revision(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    first, path = _evaluate(tmp_path, manifest, policy)
    second, second_path = _evaluate(tmp_path, manifest, policy)
    assert second == first
    assert second_path == path
    changed = b"data alpha; x=2; run;\n"
    (source / "alpha.sas").write_bytes(changed)
    revised = copy.deepcopy(manifest)
    revised["batch_version"] = "2"
    revised["artifacts"][0]["sha256"] = hashlib.sha256(changed).hexdigest()
    revised["artifacts"][0]["size_bytes"] = len(changed)
    revised = sign_manifest(revised, key)
    result = evaluate_batch_intake(
        IntakeRequest(revised, policy, source, tmp_path / "out", "run-2", "attempt-1")
    )
    assert result["batch_revision_id"] != first["batch_revision_id"]
    assert result["decisions"][0]["workload_id"] == first["decisions"][0]["workload_id"]
    assert (
        result["decisions"][0]["workload_revision_id"]
        != first["decisions"][0]["workload_revision_id"]
    )
    assert path.is_file()


def test_retry_recovers_missing_projection_without_changing_decision(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    result, path = _evaluate(tmp_path, make_manifest(source, key, two=False), policy)
    projection = (
        path.parent / "workloads" / result["decisions"][0]["workload_id"] / "readiness-input.json"
    )
    telemetry = path.with_name("intake.telemetry.json")
    lineage = build_intake_run_lineage(
        result,
        workload_id=result["decisions"][0]["workload_id"],
        trusted_policy=policy,
    )
    lineage_projection = lineage_path(tmp_path / "out", lineage)
    assert verify_run_lineage(json.loads(lineage_projection.read_text(encoding="utf-8"))) == lineage
    projection.unlink()
    telemetry.unlink()
    lineage_projection.unlink()
    replay_path = write_intake_result(tmp_path / "out", result, trusted_policy=policy)
    assert replay_path.read_bytes() == path.read_bytes()
    assert projection.is_file()
    assert telemetry.is_file()
    assert lineage_projection.is_file()


def test_thousand_script_denominator_is_preserved(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    manifest["expected_script_count"] = 1000
    manifest["unprocessable"] = [
        {
            "script_id": f"script-{index}",
            "reason_code": "missing_source",
            "owner": "inventory-owner",
        }
        for index in range(2, 1001)
    ]
    manifest = sign_manifest(manifest, key)
    result = evaluate_batch_intake(
        IntakeRequest(manifest, policy, source, tmp_path / "out", "run-1", "attempt-1")
    )
    assert result["observed_unique_script_count"] == 1000
    assert result["denominator_reconciled"] is True
    assert result["unprocessable_count"] == 999
    assert result["disposition"] == "partial"
