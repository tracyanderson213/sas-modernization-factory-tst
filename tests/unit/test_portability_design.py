from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from smf.portability.design import (
    evaluate_portability_design,
    load_portability_design,
    load_published_portability_result,
    publish_portability_result,
    verify_portability_result,
)
from smf.upstream.crypto import digest_value

SHA = "a" * 64
AUTHORITY = "b" * 64
FIXTURE = Path(__file__).parents[1] / "fixtures" / "portability" / "source-only-synthetic.json"


def contract(
    *, profile: str = "source-only", evidence_class: str = "synthetic_contract"
) -> dict[str, object]:
    matrix = [
        {
            "matrix_id": "linux-x86_64-py312",
            "os": "linux",
            "architecture": "x86_64",
            "python_version": "3.12",
            "spark_version": None,
            "scala_binary": None,
            "jvm_version": None,
            "databricks_runtime": None,
        }
    ]
    requirements = [
        {
            "component_id": "qualified-reader",
            "kind": "python-wheel",
            "version": "1.2.3",
            "platform_id": "linux-x86_64-py312",
            "artifact_sha256": SHA,
        }
    ]
    observations = [
        {
            "component_id": "qualified-reader",
            "state": "present",
            "version": "1.2.3",
            "platform_id": "linux-x86_64-py312",
            "runtime_matrix_digest": digest_value(matrix[0]),
            "artifact_sha256": SHA,
            "authority_digest": AUTHORITY,
            "observed_at": "2026-09-20T11:59:00Z",
        }
    ]
    artifacts = [
        {
            "component_id": "qualified-reader",
            "kind": "python-wheel",
            "filename": "qualified_reader-1.2.3-py3-none-any.whl",
            "version": "1.2.3",
            "platform_id": "linux-x86_64-py312",
            "sha256": SHA,
            "source_revision": "revision-123",
            "license_digest": "c" * 64,
            "notice_digest": "9" * 64,
            "sbom_digest": "d" * 64,
            "provenance_digest": "e" * 64,
            "vulnerability_digest": "f" * 64,
            "intake_state": "approved",
        }
    ]
    return {
        "schema_version": "1.0",
        "evidence_class": evidence_class,
        "profile": profile,
        "client_id": "synthetic-client",
        "workload_id": "synthetic-workload",
        "source_digest": "1" * 64,
        "upstream_revision": "revision-123",
        "run_id": "run-001",
        "attempt_id": "attempt-001",
        "observed_at": "2026-09-20T12:00:00Z",
        "evaluated_at": "2026-09-20T12:05:00Z",
        "freshness_max_age_seconds": 3600,
        "design_id": "design-001",
        "runtime_matrix": matrix,
        "requirements": requirements,
        "observations": observations,
        "offline_artifacts": artifacts,
        "digests": {
            "runtime_matrix": digest_value(matrix),
            "dependency_lock": digest_value(requirements),
            "offline_artifact_plan": digest_value(artifacts),
        },
    }


def write_contract(root: Path, payload: dict[str, object]) -> Path:
    path = root / "portability.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_source_only_synthetic_contract_pass_is_non_authorizing() -> None:
    result = evaluate_portability_design(contract())
    assert result["outcome"] == "contract_pass"
    assert result["required_offline_artifacts"] == []
    assert not any(result["claims"].values())


def test_checked_in_contract_evidence_replays() -> None:
    loaded = load_portability_design(FIXTURE, authorized_root=FIXTURE.parents[2])
    result = evaluate_portability_design(loaded)
    assert result["outcome"] == "contract_pass"
    assert result["contract_digest"] == digest_value(loaded)


def test_real_evidence_never_authorizes_runtime() -> None:
    result = evaluate_portability_design(contract(evidence_class="real"))
    assert result["outcome"] == "blocked"
    assert "real_runtime_approval_not_authorized" in result["blockers"]
    assert result["claims"]["authorizes_runtime"] is False


def test_missing_source_only_component_names_offline_artifact() -> None:
    payload = contract()
    payload["observations"] = []
    result = evaluate_portability_design(payload)
    assert result["outcome"] == "blocked"
    required = result["required_offline_artifacts"]
    assert required == [
        {
            "component_id": "qualified-reader",
            "filename": "qualified_reader-1.2.3-py3-none-any.whl",
            "kind": "python-wheel",
            "version": "1.2.3",
            "platform_id": "linux-x86_64-py312",
            "runtime_matrix": payload["runtime_matrix"][0],
            "expected_sha256": SHA,
            "source_revision": "revision-123",
            "license_digest": "c" * 64,
            "notice_digest": "9" * 64,
            "sbom_digest": "d" * 64,
            "provenance_digest": "e" * 64,
            "vulnerability_digest": "f" * 64,
            "intake_state": "approved",
        }
    ]
    assert "missing:qualified-reader" in result["blockers"]


def test_absent_or_incomplete_offline_plan_never_emits_partial_descriptor(
    tmp_path: Path,
) -> None:
    absent = contract()
    absent["observations"] = []
    absent["offline_artifacts"] = []
    absent["digests"]["offline_artifact_plan"] = digest_value([])
    result = evaluate_portability_design(absent)
    assert result["outcome"] == "blocked"
    assert "missing_offline_artifact_plan:qualified-reader" in result["blockers"]
    assert result["required_offline_artifacts"] == []
    with pytest.raises(ValueError, match="diagnostic-only"):
        verify_portability_result(result, contract=absent)
    with pytest.raises(ValueError, match="diagnostic-only"):
        publish_portability_result(tmp_path / "output", result, contract=absent)

    output = tmp_path / "bypassed-output"
    bypassed = (
        output
        / "runs"
        / result["run_id"]
        / "workloads"
        / result["workload_id"]
        / "attempts"
        / result["attempt_id"]
        / "portability-design.result.json"
    )
    bypassed.parent.mkdir(parents=True)
    bypassed.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="diagnostic-only"):
        load_published_portability_result(bypassed, output_root=output, contract=absent)

    incomplete = contract()
    del incomplete["offline_artifacts"][0]["notice_digest"]
    incomplete["digests"]["offline_artifact_plan"] = digest_value(incomplete["offline_artifacts"])
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_portability_design(incomplete)


@pytest.mark.parametrize(
    "state, outcome",
    [
        ("unapproved", "pending"),
        ("stale", "stale"),
        ("ambiguous", "ambiguous"),
        ("incompatible", "incompatible"),
    ],
)
def test_runtime_states_fail_closed(state: str, outcome: str) -> None:
    payload = contract()
    payload["observations"][0]["state"] = state
    assert evaluate_portability_design(payload)["outcome"] == outcome


def test_offline_profile_requires_complete_approved_intake() -> None:
    payload = contract(profile="offline-packaged")
    payload["offline_artifacts"][0]["intake_state"] = "pending"
    payload["digests"]["offline_artifact_plan"] = digest_value(payload["offline_artifacts"])
    result = evaluate_portability_design(payload)
    assert result["outcome"] == "pending"
    assert result["required_offline_artifacts"][0]["component_id"] == "qualified-reader"
    assert result["required_offline_artifacts"][0]["expected_sha256"] == SHA


def test_runtime_observation_cannot_interchange_platform_matrix() -> None:
    payload = contract()
    aarch64 = deepcopy(payload["runtime_matrix"][0])
    aarch64["matrix_id"] = "linux-aarch64-py312"
    aarch64["architecture"] = "aarch64"
    payload["runtime_matrix"].append(aarch64)
    payload["requirements"][0]["platform_id"] = "linux-aarch64-py312"
    payload["digests"]["runtime_matrix"] = digest_value(payload["runtime_matrix"])
    payload["digests"]["dependency_lock"] = digest_value(payload["requirements"])
    result = evaluate_portability_design(payload)
    assert result["outcome"] == "incompatible"
    assert "runtime_lock_mismatch:qualified-reader" in result["blockers"]
    assert "offline_artifact_lock_mismatch:qualified-reader" in result["blockers"]
    assert result["required_offline_artifacts"] == []


def test_freshness_is_computed_not_trusted_from_caller_state() -> None:
    stale = contract()
    stale["observations"][0]["state"] = "present"
    stale["observations"][0]["observed_at"] = "2026-09-20T10:00:00Z"
    result = evaluate_portability_design(stale)
    assert result["outcome"] == "stale"
    assert "runtime_observation_stale:qualified-reader" in result["blockers"]

    future = contract()
    future["observations"][0]["observed_at"] = "2026-09-20T12:06:00Z"
    result = evaluate_portability_design(future)
    assert result["outcome"] == "ambiguous"
    assert "runtime_observation_in_future:qualified-reader" in result["blockers"]

    malformed = contract()
    malformed["evaluated_at"] = "not-a-time"
    with pytest.raises(ValueError, match="time is malformed"):
        evaluate_portability_design(malformed)


def test_lock_mutation_and_unknown_platform_fail_closed() -> None:
    payload = contract()
    payload["requirements"][0]["version"] = "9.9.9"
    with pytest.raises(ValueError, match="digest mismatch"):
        evaluate_portability_design(payload)
    payload = contract()
    payload["requirements"][0]["platform_id"] = "unknown"
    payload["digests"]["dependency_lock"] = digest_value(payload["requirements"])
    with pytest.raises(ValueError, match="unknown runtime matrix"):
        evaluate_portability_design(payload)


def test_duplicate_key_symlink_and_outside_root_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_portability_design(duplicate, authorized_root=tmp_path)
    target = write_contract(tmp_path, contract())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="unsafe"):
        load_portability_design(link, authorized_root=tmp_path)
    with pytest.raises(ValueError, match="outside"):
        load_portability_design(target, authorized_root=tmp_path / "other")


def test_immutable_publication_replay_and_mutation_detection(tmp_path: Path) -> None:
    payload = contract()
    loaded = load_portability_design(write_contract(tmp_path, payload), authorized_root=tmp_path)
    result = evaluate_portability_design(loaded)
    output = tmp_path / "output"
    path = publish_portability_result(output, result, contract=loaded)
    assert load_published_portability_result(path, output_root=output, contract=loaded) == result
    assert publish_portability_result(output, result, contract=loaded) == path
    mutated = deepcopy(loaded)
    mutated["observations"] = []
    with pytest.raises(ValueError, match="deterministic replay"):
        verify_portability_result(result, contract=mutated)
    changed = deepcopy(result)
    changed["claims"]["qualifies_final_bundle"] = True
    with pytest.raises(ValueError, match="schema validation"):
        verify_portability_result(changed, contract=loaded)


def test_unknown_fields_and_duplicate_identities_are_rejected() -> None:
    payload = contract()
    payload["caller_approved"] = True
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_portability_design(payload)
    payload = contract()
    payload["requirements"].append(deepcopy(payload["requirements"][0]))
    payload["digests"]["dependency_lock"] = digest_value(payload["requirements"])
    with pytest.raises(ValueError, match="Duplicate or ambiguous dependency"):
        evaluate_portability_design(payload)
