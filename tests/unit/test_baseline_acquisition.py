from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from tests.unit.baseline_test_support import _sign, build_baseline_case

from smf.baseline import (
    PreparedBaselineAcquisition,
    evaluate_baseline_acquisition,
    load_baseline_result,
    recover_baseline_result,
    write_baseline_result,
)
from smf.baseline.approved_export import approval_subject_digest
from smf.baseline.policy import baseline_policy_from_dict
from smf.readiness.policy import digest_value


def _resign_case(case, receipt) -> None:
    _sign(receipt, case["producer_key"], "producer-key")
    case["receipt_path"].write_text(json.dumps(receipt), encoding="utf-8")
    approval = {
        **case["approval"],
        "subject_digest": approval_subject_digest(receipt, case["policy"].policy_digest),
    }
    _sign(approval, case["approval_key"], "approval-key")
    case["approval_path"].write_text(json.dumps(approval), encoding="utf-8")


def test_approved_export_acquires_attributable_immutable_output(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    prepared = evaluate_baseline_acquisition(case["request"])
    assert prepared.result["disposition"] == "acquired"
    assert prepared.result["claims"] == {
        "baseline_acquired": True,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
    }
    path = write_baseline_result(tmp_path / "out", prepared, trusted_policy=case["policy"])
    loaded = load_baseline_result(path, output_root=tmp_path / "out", trusted_policy=case["policy"])
    artifact = tmp_path / "out" / loaded["outputs"][0]["artifact_uri"]
    assert artifact.read_bytes() == case["output_bytes"]
    assert not artifact.stat().st_mode & 0o222
    telemetry = json.loads(path.with_name("telemetry.json").read_text())
    assert telemetry["sas_execution_verified"] is True
    assert telemetry["executed"] is False
    assert telemetry["parity_passed"] is False


@pytest.mark.parametrize(
    ("state", "disposition", "blocker"),
    [
        ("pending", "human_required", "approval_pending"),
        ("denied", "blocked", "approval_denied"),
    ],
)
def test_pending_and_denied_are_distinct(tmp_path, state, disposition, blocker) -> None:
    case = build_baseline_case(tmp_path)
    approval = {**case["approval"], "state": state}
    _sign(approval, case["approval_key"], "approval-key")
    case["approval_path"].write_text(json.dumps(approval), encoding="utf-8")
    result = evaluate_baseline_acquisition(case["request"]).result
    assert result["disposition"] == disposition
    assert result["blockers"] == [blocker]
    assert result["outputs"] == []


def test_stale_approval_is_needs_evidence_and_replay_valid(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    now = datetime.now(UTC)
    approval = {
        **case["approval"],
        "issued_at": (now - timedelta(hours=2)).isoformat(),
        "expires_at": (now - timedelta(hours=1)).isoformat(),
    }
    _sign(approval, case["approval_key"], "approval-key")
    case["approval_path"].write_text(json.dumps(approval), encoding="utf-8")
    prepared = evaluate_baseline_acquisition(case["request"])
    assert prepared.result["disposition"] == "needs_evidence"
    assert prepared.result["blockers"] == ["approval_expired_or_not_yet_valid"]
    write_baseline_result(tmp_path / "out", prepared, trusted_policy=case["policy"])


def test_replay_rejects_changed_decision_semantics_even_with_valid_signature(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    approval = {**case["approval"], "state": "pending"}
    _sign(approval, case["approval_key"], "approval-key")
    case["approval_path"].write_text(json.dumps(approval), encoding="utf-8")
    prepared = evaluate_baseline_acquisition(case["request"])
    tampered = deepcopy(prepared.result)
    tampered["approval"]["state"] = "denied"
    _sign(tampered["approval"], case["approval_key"], "approval-key")
    tampered["content_digest"] = digest_value({**tampered, "content_digest": ""})
    with pytest.raises(ValueError, match="approval state does not match disposition"):
        write_baseline_result(
            tmp_path / "out",
            PreparedBaselineAcquisition(tampered),
            trusted_policy=case["policy"],
        )


def test_missing_approval_never_authorizes_output(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    request = replace(case["request"], approval_path=None)
    result = evaluate_baseline_acquisition(request).result
    assert result["disposition"] == "needs_evidence"
    assert result["claims"]["baseline_acquired"] is False
    assert result["outputs"] == []


def test_direct_sas_execution_without_provider_is_explicitly_blocked(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    request = replace(
        case["request"],
        mode="sas_execution",
        package_root=None,
        receipt_path=None,
        approval_path=None,
    )
    result = evaluate_baseline_acquisition(request).result
    assert result["disposition"] == "blocked"
    assert result["blockers"] == ["sas_execution_provider_unavailable"]
    assert result["claims"]["baseline_acquired"] is False


def test_producer_and_approval_cannot_share_authority_or_key_material(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    same_authority = json.loads(json.dumps(case["policy"].payload))
    same_authority["approval_provenance"]["authorities"] = ["sas-export-service"]
    with pytest.raises(ValueError, match="authorities must be distinct"):
        baseline_policy_from_dict(same_authority)
    same_key = json.loads(json.dumps(case["policy"].payload))
    same_key["verification_keys"]["approval-key"] = same_key["verification_keys"]["producer-key"]
    with pytest.raises(ValueError, match="public keys must be distinct"):
        baseline_policy_from_dict(same_key)


def test_approval_cannot_be_replayed_to_changed_source_subject(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    receipt = {**case["receipt"], "closure_digest": "c" * 64}
    _sign(receipt, case["producer_key"], "producer-key")
    case["receipt_path"].write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(ValueError, match="identity binding mismatch"):
        evaluate_baseline_acquisition(case["request"])


def test_output_mutation_after_signed_receipt_fails_closed(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    case["output_path"].write_bytes(b"changed")
    with pytest.raises(ValueError, match="do not match the signed receipt"):
        evaluate_baseline_acquisition(case["request"])


def test_stale_export_receipt_is_rejected(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    receipt = json.loads(case["receipt_path"].read_text())
    old = datetime.now(UTC) - timedelta(days=1)
    receipt["executed_at"] = (old - timedelta(minutes=1)).isoformat()
    receipt["exported_at"] = old.isoformat()
    receipt["execution"]["executed_at"] = receipt["executed_at"]
    _resign_case(case, receipt)
    with pytest.raises(ValueError, match="stale or future-dated"):
        evaluate_baseline_acquisition(case["request"])


def test_empty_duplicate_and_cross_boundary_outputs_fail_closed(tmp_path) -> None:
    empty = build_baseline_case(tmp_path / "empty")
    empty["output_path"].write_bytes(b"")
    receipt = json.loads(empty["receipt_path"].read_text())
    receipt["outputs"][0]["byte_count"] = 0
    receipt["outputs"][0]["content_digest"] = hashlib.sha256(b"").hexdigest()
    _resign_case(empty, receipt)
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_baseline_acquisition(empty["request"])

    duplicate = build_baseline_case(tmp_path / "duplicate")
    receipt = json.loads(duplicate["receipt_path"].read_text())
    receipt["outputs"].append(dict(receipt["outputs"][0]))
    _resign_case(duplicate, receipt)
    with pytest.raises(ValueError, match="duplicate output"):
        evaluate_baseline_acquisition(duplicate["request"])

    escaped = build_baseline_case(tmp_path / "boundary")
    receipt = json.loads(escaped["receipt_path"].read_text())
    receipt["outputs"][0]["output_id"] = "OUT-unrelated"
    _resign_case(escaped, receipt)
    with pytest.raises(ValueError, match="selected boundary"):
        evaluate_baseline_acquisition(escaped["request"])


def test_symlinked_output_and_protected_approval_identity_are_rejected(tmp_path) -> None:
    symlinked = build_baseline_case(tmp_path / "symlink")
    outside = tmp_path / "outside.json"
    outside.write_bytes(symlinked["output_bytes"])
    symlinked["output_path"].unlink()
    symlinked["output_path"].symlink_to(outside)
    with pytest.raises(ValueError, match="symlinked"):
        evaluate_baseline_acquisition(symlinked["request"])

    protected = build_baseline_case(tmp_path / "protected")
    approval = {**protected["approval"], "decision_id": "123-45-6789"}
    _sign(approval, protected["approval_key"], "approval-key")
    protected["approval_path"].write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe durable identity"):
        evaluate_baseline_acquisition(protected["request"])


def test_unknown_mode_and_target_derived_origin_are_rejected(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_baseline_acquisition(replace(case["request"], mode="approved-export"))
    receipt = json.loads(case["receipt_path"].read_text())
    receipt["outputs"][0]["origin"] = "target_generated"
    _sign(receipt, case["producer_key"], "producer-key")
    case["receipt_path"].write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_baseline_acquisition(case["request"])


def test_retry_recovers_derivatives_without_overwriting_canonical_result(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    prepared = evaluate_baseline_acquisition(case["request"])
    path = write_baseline_result(tmp_path / "out", prepared, trusted_policy=case["policy"])
    canonical = path.read_bytes()
    path.with_name("telemetry.json").unlink()
    path.with_name("readiness-evidence.json").unlink()
    assert case["request"].package_root is not None
    shutil.rmtree(case["request"].package_root)
    case["approval_path"].unlink()
    recover_baseline_result(path, output_root=tmp_path / "out", trusted_policy=case["policy"])
    assert path.read_bytes() == canonical
    assert path.with_name("telemetry.json").is_file()
    assert path.with_name("readiness-evidence.json").is_file()


def test_corrupt_canonical_artifact_is_detected_on_replay(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    prepared = evaluate_baseline_acquisition(case["request"])
    path = write_baseline_result(tmp_path / "out", prepared, trusted_policy=case["policy"])
    artifact = tmp_path / "out" / prepared.result["outputs"][0]["artifact_uri"]
    artifact.chmod(0o644)
    artifact.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="artifact is missing|artifact digest mismatch"):
        load_baseline_result(path, output_root=tmp_path / "out", trusted_policy=case["policy"])
