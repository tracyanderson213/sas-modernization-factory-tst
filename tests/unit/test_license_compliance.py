"""LIC-01 offline compliance contract regressions."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from compliance_test_support import build_fixture

from smf.compliance import (
    evaluate_compliance,
    load_compliance_evidence,
    load_compliance_policy,
    load_compliance_result,
    publish_compliance_result,
)
from smf.upstream.crypto import digest_value, sign_payload


def test_license_compliance_contract_is_importable() -> None:
    assert callable(evaluate_compliance)


def _evaluate(tmp_path: Path, *, inconsistent: bool = True):
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=inconsistent)
    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )
    return policy, evidence, keys, result


def _resign_component_mutation(
    evidence: dict, keys: dict[str, Path], field: str, value: str
) -> None:
    for section in ("resolution", "installed_environment", "sbom"):
        evidence[section]["components"][0][field] = value
    if field == "artifact_digest":
        evidence["provenance"][0]["artifact_digest"] = value

    _refresh_component_bindings(evidence, keys)


def _refresh_component_bindings(evidence: dict, keys: dict[str, Path]) -> None:
    evidence["resolution"]["resolution_digest"] = digest_value(
        {
            "resolution_id": evidence["resolution"]["resolution_id"],
            "components": evidence["resolution"]["components"],
        }
    )
    evidence["installed_environment"]["environment_digest"] = digest_value(
        {
            "environment_id": evidence["installed_environment"]["environment_id"],
            "components": evidence["installed_environment"]["components"],
        }
    )
    evidence["sbom"]["resolution_digest"] = evidence["resolution"]["resolution_digest"]
    evidence["sbom"]["environment_digest"] = evidence["installed_environment"]["environment_digest"]
    evidence["sbom"]["sbom_digest"] = digest_value(
        {
            key: evidence["sbom"][key]
            for key in (
                "sbom_id",
                "format",
                "resolution_digest",
                "environment_digest",
                "components",
            )
        }
    )
    evidence["vulnerability"]["resolution_digest"] = evidence["resolution"]["resolution_digest"]
    evidence["vulnerability"]["environment_digest"] = evidence["installed_environment"][
        "environment_digest"
    ]
    evidence["vulnerability"]["sbom_digest"] = evidence["sbom"]["sbom_digest"]
    sign_payload(
        evidence["vulnerability"],
        private_key_path=keys["scanner"],
        key_id="scanner-key",
    )
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", "9.9"),
        ("artifact_type", "wheel"),
        ("artifact_digest", "9" * 64),
    ],
)
def test_signed_license_cannot_be_replayed_for_mutated_component(
    tmp_path: Path, field: str, value: str
) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    _resign_component_mutation(evidence, keys, field, value)

    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )

    assert result["outcome"] == "incompatible"
    assert "license_component_binding_mismatch" in result["blockers"]


def test_signed_license_cannot_be_replayed_for_mutated_source_revision(
    tmp_path: Path,
) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    evidence["provenance"][0]["source_revision"] = "entirely-different-revision"
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")

    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )

    assert result["outcome"] == "incompatible"
    assert "license_component_binding_mismatch" in result["blockers"]


@pytest.mark.parametrize(
    ("scanned_at", "expected_outcome", "expected_blocker"),
    [
        ("2000-01-01T00:00:00Z", "stale", "vulnerability_scan_stale"),
        ("2026-09-19T12:10:01Z", "ambiguous", "future_dated_vulnerability_scan"),
        ("2026-09-19T11:10:00Z", "contract_pass", None),
    ],
)
def test_vulnerability_scan_freshness_is_bound_to_scanner_time(
    tmp_path: Path,
    scanned_at: str,
    expected_outcome: str,
    expected_blocker: str | None,
) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    evidence["vulnerability"]["scanned_at"] = scanned_at
    sign_payload(
        evidence["vulnerability"],
        private_key_path=keys["scanner"],
        key_id="scanner-key",
    )
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")

    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )

    assert result["outcome"] == expected_outcome
    if expected_blocker is not None:
        assert expected_blocker in result["blockers"]


def test_sec03_scope_inconsistency_is_an_explicit_blocker(tmp_path: Path) -> None:
    _, _, _, result = _evaluate(tmp_path)
    assert result["outcome"] == "ambiguous"
    assert "sec03_acceptance_contract_inconsistent" in result["blockers"]
    assert not any(result["claims"].values())


def test_consistent_synthetic_contract_pass_never_authorizes_real_components(
    tmp_path: Path,
) -> None:
    policy, evidence, _, result = _evaluate(tmp_path, inconsistent=False)
    assert result["outcome"] == "contract_pass"
    path = publish_compliance_result(tmp_path / "output", result, evidence=evidence, policy=policy)
    projection = json.loads(path.with_name("license-compliance.projection.json").read_text())
    assert projection["synthetic_contract_pass"] is True
    assert projection["authorizes_real_components"] is False
    assert projection["authorizes_distribution"] is False


def test_real_evidence_cannot_be_approved_by_this_increment(tmp_path: Path) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    evidence["evidence_class"] = "real"
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")
    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )
    assert result["outcome"] == "blocked"
    assert result["blockers"] == ["real_component_approval_not_authorized"]
    assert not any(result["claims"].values())


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        ("blocked", "blocked"),
        ("pending", "pending"),
        ("denied", "denied"),
        ("failed", "failed"),
        ("ambiguous", "ambiguous"),
        ("incompatible", "incompatible"),
        ("stale", "stale"),
        ("unavailable_scanner", "unavailable_scanner"),
    ],
)
def test_scanner_outcomes_remain_explicit(tmp_path: Path, status: str, outcome: str) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    evidence["vulnerability"]["status"] = status
    sign_payload(
        evidence["vulnerability"],
        private_key_path=keys["scanner"],
        key_id="scanner-key",
    )
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")
    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )
    assert result["outcome"] == outcome


def test_default_deny_license_and_empty_exception_allowlist(tmp_path: Path) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    policy_data = copy.deepcopy(policy.payload)
    policy_data["approved_license_ids"] = []
    policy_path = tmp_path / "default-deny.json"
    policy_path.write_text(json.dumps(policy_data), encoding="utf-8")
    denied_policy = load_compliance_policy(policy_path)
    evidence["bundle_id"] = "LICB-invalid-until-resigned"
    from smf.workload.identity import stable_id

    evidence["bundle_id"] = stable_id(
        "LICB",
        {
            "client_id": evidence["client_id"],
            "workload_id": evidence["workload_id"],
            "source_digest": evidence["source_digest"],
            "run_id": evidence["run_id"],
            "attempt_id": evidence["attempt_id"],
            "observed_at": evidence["observed_at"],
            "policy_digest": denied_policy.policy_digest,
        },
    )
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")
    result = evaluate_compliance(
        evidence,
        policy=denied_policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )
    assert result["outcome"] == "denied"
    assert denied_policy.payload["vulnerability_exception_allowlist"] == []


def test_unknown_fields_and_duplicate_policy_keys_fail_closed(tmp_path: Path) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    evidence["license_approved"] = True
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")
    with pytest.raises(ValueError, match="Additional properties"):
        evaluate_compliance(
            evidence,
            policy=policy,
            evaluator_private_key=keys["evaluator"],
            evaluator_key_id="evaluator-key",
        )
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_compliance_policy(duplicate)
    duplicate_evidence = tmp_path / "duplicate-evidence.json"
    duplicate_evidence.write_text('{"schema_version":"1.0","schema_version":"1.0"}')
    with pytest.raises(ValueError, match="Duplicate"):
        load_compliance_evidence(duplicate_evidence)


def test_mutation_replay_conflict_and_projection_recovery(tmp_path: Path) -> None:
    policy, evidence, _, result = _evaluate(tmp_path, inconsistent=False)
    output = tmp_path / "output"
    path = publish_compliance_result(output, result, evidence=evidence, policy=policy)
    projection = path.with_name("license-compliance.projection.json")
    projection.unlink()
    assert publish_compliance_result(output, result, evidence=evidence, policy=policy) == path
    assert projection.is_file()
    mutated = copy.deepcopy(evidence)
    mutated["provenance"][0]["artifact_digest"] = "9" * 64
    with pytest.raises(ValueError, match="evidence changed"):
        load_compliance_result(path, output_root=output, evidence=mutated, policy=policy)
    conflicting = copy.deepcopy(result)
    conflicting["blockers"] = ["caller_authored_success"]
    with pytest.raises(ValueError, match="signature|different bytes"):
        publish_compliance_result(output, conflicting, evidence=evidence, policy=policy)


def test_cross_workload_and_component_ambiguity_fail_closed(tmp_path: Path) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    evidence["resolution"]["components"].append(
        {**evidence["resolution"]["components"][0], "component_id": "SYNTHETIC-COMPONENT"}
    )
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")
    with pytest.raises(ValueError, match="Duplicate or ambiguous"):
        evaluate_compliance(
            evidence,
            policy=policy,
            evaluator_private_key=keys["evaluator"],
            evaluator_key_id="evaluator-key",
        )


def test_duplicate_canonical_component_id_cannot_hide_unlicensed_artifact(
    tmp_path: Path,
) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    second_component = copy.deepcopy(evidence["resolution"]["components"][0])
    second_component.update(version="2.0", artifact_digest="9" * 64)
    for section in ("resolution", "installed_environment", "sbom"):
        evidence[section]["components"].append(copy.deepcopy(second_component))

    second_license = copy.deepcopy(evidence["licenses"][0])
    second_license.update(version="2.0", artifact_digest="9" * 64)
    sign_payload(second_license, private_key_path=keys["legal"], key_id="legal-key")
    evidence["licenses"] = [copy.deepcopy(second_license), copy.deepcopy(second_license)]

    second_provenance = copy.deepcopy(evidence["provenance"][0])
    second_provenance["artifact_digest"] = "9" * 64
    evidence["provenance"] = [
        copy.deepcopy(second_provenance),
        copy.deepcopy(second_provenance),
    ]
    _refresh_component_bindings(evidence, keys)

    with pytest.raises(ValueError, match="Duplicate or ambiguous"):
        evaluate_compliance(
            evidence,
            policy=policy,
            evaluator_private_key=keys["evaluator"],
            evaluator_key_id="evaluator-key",
        )


def test_notice_cannot_escape_the_qualified_component_scope(tmp_path: Path) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    evidence["notice_files"].append(
        {
            "component_id": "outside-resolution",
            "notice_path": "notices/outside.NOTICE",
            "notice_digest": "8" * 64,
        }
    )
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")

    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )

    assert result["outcome"] == "incompatible"
    assert "notice_component_scope_mismatch" in result["blockers"]


def test_exception_expired_before_decision_cannot_authorize_vulnerability(
    tmp_path: Path,
) -> None:
    policy, evidence, keys = build_fixture(tmp_path, inconsistent_sec03=False)
    exception_policy = {
        "exception_id": "exception-1",
        "advisory_id": "ADV-1",
        "component_id": "synthetic-component",
        "expires_at": "2026-09-19T12:05:00Z",
        "authority": "synthetic-security-authority",
    }
    policy_data = copy.deepcopy(policy.payload)
    policy_data["vulnerability_exception_allowlist"] = [exception_policy]
    policy_path = tmp_path / "exception-policy.json"
    policy_path.write_text(json.dumps(policy_data), encoding="utf-8")
    policy = load_compliance_policy(policy_path)

    exception = {**exception_policy, "proof": {}}
    sign_payload(exception, private_key_path=keys["security"], key_id="security-key")
    vulnerability = evidence["vulnerability"]
    vulnerability["advisories"] = [
        {
            "advisory_id": "ADV-1",
            "source": "synthetic-db",
            "source_digest": "7" * 64,
        }
    ]
    vulnerability["advisories_digest"] = digest_value(vulnerability["advisories"])
    vulnerability["findings"] = [
        {
            "finding_id": "finding-1",
            "advisory_id": "ADV-1",
            "component_id": "synthetic-component",
            "severity": "high",
            "status": "affected",
            "exception_id": "exception-1",
        }
    ]
    vulnerability["exceptions"] = [exception]
    sign_payload(vulnerability, private_key_path=keys["scanner"], key_id="scanner-key")

    from smf.workload.identity import stable_id

    evidence["bundle_id"] = stable_id(
        "LICB",
        {
            "client_id": evidence["client_id"],
            "workload_id": evidence["workload_id"],
            "source_digest": evidence["source_digest"],
            "run_id": evidence["run_id"],
            "attempt_id": evidence["attempt_id"],
            "observed_at": evidence["observed_at"],
            "policy_digest": policy.policy_digest,
        },
    )
    sign_payload(evidence, private_key_path=keys["collector"], key_id="collector-key")

    result = evaluate_compliance(
        evidence,
        policy=policy,
        evaluator_private_key=keys["evaluator"],
        evaluator_key_id="evaluator-key",
    )

    assert result["outcome"] == "stale"
    assert "vulnerability_exception_expired" in result["blockers"]
