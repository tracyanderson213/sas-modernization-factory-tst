from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.baseline_test_support import _public, _sign, build_baseline_case

from smf.baseline import evaluate_baseline_acquisition, readiness_evidence, write_baseline_result
from smf.baseline.approved_export import approval_subject_digest
from smf.baseline.policy import baseline_policy_from_dict
from smf.readiness import (
    ReadinessRequest,
    evaluate_readiness,
    load_manifest,
    write_manifest,
)
from smf.readiness.policy import readiness_policy_from_dict


def _readiness_policy(case) -> object:
    raw = yaml.safe_load(Path("tests/fixtures/readiness-policy.yaml").read_text())
    raw["evidence_provenance"]["baseline"] = {
        "authorities": ["sas-export-service"],
        "acquisition_sources": ["governed-baseline-store"],
        "key_ids": ["producer-key"],
    }
    raw["verification_keys"]["producer-key"] = case["policy"].payload["verification_keys"][
        "producer-key"
    ]
    raw["verification_keys"]["approval-key"] = case["policy"].payload["verification_keys"][
        "approval-key"
    ]
    raw["baseline"]["authorities"] = ["sas-export-service"]
    raw["baseline"]["trusted_acquisition_policies"] = [
        {
            "policy_digest": case["policy"].policy_digest,
            "producer_authorities": ["sas-export-service"],
            "producer_key_ids": ["producer-key"],
            "approval_authorities": ["baseline-owner"],
            "approval_key_ids": ["approval-key"],
        }
    ]
    return readiness_policy_from_dict(raw)


def _workload(case) -> dict:
    intake = json.loads(case["request"].intake_result_path.read_text())
    return intake["decisions"][0]["discovery"]


def test_readiness_replays_result_and_hashes_canonical_output(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    prepared = evaluate_baseline_acquisition(case["request"])
    write_baseline_result(tmp_path / "out", prepared, trusted_policy=case["policy"])
    result = evaluate_readiness(
        ReadinessRequest(
            workload=_workload(case),
            evidence=tuple(readiness_evidence(prepared.result)),
            run_id="run-1",
            attempt_id="attempt-1",
            boundary_id=case["request"].boundary_id,
            result_root=tmp_path / "out",
        ),
        _readiness_policy(case),
    )
    check = next(item for item in result.checks if item.check_id.startswith("baseline:"))
    assert check.status.value == "pass"
    path = write_manifest(tmp_path / "out", result)
    replayed = load_manifest(path)
    replayed_check = next(
        item for item in replayed["checks"] if item["check_id"].startswith("baseline:")
    )
    assert replayed_check["status"] == "pass"


def test_readiness_rejects_projection_after_canonical_output_corruption(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    prepared = evaluate_baseline_acquisition(case["request"])
    write_baseline_result(tmp_path / "out", prepared, trusted_policy=case["policy"])
    artifact = tmp_path / "out" / prepared.result["outputs"][0]["artifact_uri"]
    artifact.chmod(0o644)
    artifact.write_bytes(b"changed")
    result = evaluate_readiness(
        ReadinessRequest(
            workload=_workload(case),
            evidence=tuple(readiness_evidence(prepared.result)),
            run_id="run-1",
            attempt_id="attempt-1",
            boundary_id=case["request"].boundary_id,
            result_root=tmp_path / "out",
        ),
        _readiness_policy(case),
    )
    check = next(item for item in result.checks if item.check_id.startswith("baseline:"))
    assert check.status.value == "missing"


def test_readiness_rejects_producer_controlled_approval_trust_root(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    trusted_readiness_policy = _readiness_policy(case)
    attacker_key = Ed25519PrivateKey.generate()
    policy_raw = deepcopy(case["policy"].payload)
    policy_raw["approval_provenance"] = {
        "authorities": ["attacker-self-approval"],
        "key_ids": ["attacker-key"],
    }
    policy_raw["verification_keys"]["attacker-key"] = _public(attacker_key)
    policy_raw["verification_keys"].pop("approval-key")
    malicious_policy = baseline_policy_from_dict(policy_raw)
    case["request"].policy_path.write_text(yaml.safe_dump(policy_raw), encoding="utf-8")

    receipt = case["receipt"]
    receipt["acquisition_policy_digest"] = malicious_policy.policy_digest
    _sign(receipt, case["producer_key"], "producer-key")
    case["receipt_path"].write_text(json.dumps(receipt), encoding="utf-8")
    approval = case["approval"]
    approval["authority"] = "attacker-self-approval"
    approval["subject_digest"] = approval_subject_digest(receipt, malicious_policy.policy_digest)
    _sign(approval, attacker_key, "attacker-key")
    case["approval_path"].write_text(json.dumps(approval), encoding="utf-8")

    prepared = evaluate_baseline_acquisition(case["request"])
    assert prepared.result["disposition"] == "acquired"
    write_baseline_result(tmp_path / "out", prepared, trusted_policy=malicious_policy)
    result = evaluate_readiness(
        ReadinessRequest(
            workload=_workload(case),
            evidence=tuple(readiness_evidence(prepared.result)),
            run_id="run-1",
            attempt_id="attempt-1",
            boundary_id=case["request"].boundary_id,
            result_root=tmp_path / "out",
        ),
        trusted_readiness_policy,
    )
    check = next(item for item in result.checks if item.check_id.startswith("baseline:"))
    assert check.status.value == "missing"


def test_readiness_blocks_conflicting_authoritative_baselines(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    first = evaluate_baseline_acquisition(case["request"])
    write_baseline_result(tmp_path / "out", first, trusted_policy=case["policy"])

    alternate_bytes = b'{"columns":["x"],"rows":[[2]]}\n'
    case["output_path"].write_bytes(alternate_bytes)
    receipt = case["receipt"]
    receipt["acquisition_id"] = "acq-2"
    receipt["execution"]["sas_execution_id"] = "sas-run-2"
    receipt["outputs"][0]["byte_count"] = len(alternate_bytes)
    receipt["outputs"][0]["content_digest"] = hashlib.sha256(alternate_bytes).hexdigest()
    receipt["outputs"][0]["schema_digest"] = "c" * 64
    _sign(receipt, case["producer_key"], "producer-key")
    case["receipt_path"].write_text(json.dumps(receipt), encoding="utf-8")
    approval = case["approval"]
    approval["decision_id"] = "decision-2"
    approval["subject_digest"] = approval_subject_digest(receipt, case["policy"].policy_digest)
    _sign(approval, case["approval_key"], "approval-key")
    case["approval_path"].write_text(json.dumps(approval), encoding="utf-8")
    second_request = replace(case["request"], acquisition_id="acq-2")
    second = evaluate_baseline_acquisition(second_request)
    write_baseline_result(tmp_path / "out", second, trusted_policy=case["policy"])

    evidence = readiness_evidence(first.result) + readiness_evidence(second.result)
    result = evaluate_readiness(
        ReadinessRequest(
            workload=_workload(case),
            evidence=tuple(evidence),
            run_id="run-1",
            attempt_id="attempt-1",
            boundary_id=case["request"].boundary_id,
            result_root=tmp_path / "out",
        ),
        _readiness_policy(case),
    )
    check = next(item for item in result.checks if item.check_id.startswith("baseline:"))
    assert check.status.value == "fail"
    assert "conflicting" in check.diagnostic


def test_readiness_deduplicates_identical_baseline_evidence_delivery(tmp_path) -> None:
    case = build_baseline_case(tmp_path)
    prepared = evaluate_baseline_acquisition(case["request"])
    write_baseline_result(tmp_path / "out", prepared, trusted_policy=case["policy"])
    projection = readiness_evidence(prepared.result)[0]
    result = evaluate_readiness(
        ReadinessRequest(
            workload=_workload(case),
            evidence=(projection, deepcopy(projection)),
            run_id="run-1",
            attempt_id="attempt-1",
            boundary_id=case["request"].boundary_id,
            result_root=tmp_path / "out",
        ),
        _readiness_policy(case),
    )
    check = next(item for item in result.checks if item.check_id.startswith("baseline:"))
    assert check.status.value == "pass"
    assert check.evidence_ids == (projection["evidence_id"],)
