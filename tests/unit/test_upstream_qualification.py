from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from tests.unit.upstream_test_support import build_upstream_fixture, resign_json

from smf.cli.main import main
from smf.upstream import (
    UpstreamQualificationRequest,
    load_qualification_result,
    load_upstream_inventory,
    qualify_upstreams,
    verify_consumer_projection,
    write_qualification_result,
)
from smf.upstream.crypto import digest_value, sign_payload
from smf.workload.identity import stable_id


def _request(fixture: dict[str, object]) -> UpstreamQualificationRequest:
    keys = fixture["keys"]
    assert isinstance(keys, dict)
    return UpstreamQualificationRequest(
        policy_path=fixture["policy_path"],  # type: ignore[arg-type]
        inventory_path=fixture["inventory_path"],  # type: ignore[arg-type]
        evidence_root=fixture["evidence"],  # type: ignore[arg-type]
        output_root=fixture["output"],  # type: ignore[arg-type]
        scope_id="program",
        run_id="run-1",
        attempt_id="attempt-1",
        evaluation_time="2026-09-18T12:00:00Z",
        signing_key_path=keys["qualification-key"],
        signing_key_id="qualification-key",
        signing_authority="qualification-service",
    )


def _mutate_execution_evidence(
    fixture: dict[str, Any], receipt: dict[str, Any], **updates: object
) -> None:
    supporting_paths = fixture["supporting_paths"]
    path = supporting_paths["execution_evidence"]
    record = json.loads(path.read_text(encoding="utf-8"))
    record["payload"].update(updates)
    record["record_id"] = stable_id(
        "UPQE",
        {
            key: record[key]
            for key in (
                "upstream_id",
                "revision",
                "scope_id",
                "run_id",
                "attempt_id",
                "evidence_id",
                "evidence_class",
                "authority",
                "payload",
            )
        },
    )
    keys = fixture["keys"]
    record["proof"] = {}
    sign_payload(record, private_key_path=keys["supporting-key"], key_id="supporting-key")
    path.write_text(json.dumps(record), encoding="utf-8")
    data = path.read_bytes()
    capability = receipt["capability_evidence"][0]
    capability["execution_evidence"]["byte_count"] = len(data)
    capability["execution_evidence"]["sha256"] = hashlib.sha256(data).hexdigest()


def test_qualifies_and_replays_signed_exact_evidence(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    result = qualify_upstreams(_request(fixture))
    assert result["outcome"] == "qualified"
    assert result["claims"] == {key: False for key in result["claims"]}
    path = write_qualification_result(
        fixture["output"],  # type: ignore[arg-type]
        result,
        evidence_root=fixture["evidence"],  # type: ignore[arg-type]
        trusted_policy=fixture["policy"],  # type: ignore[arg-type]
        trusted_inventory=fixture["inventory"],  # type: ignore[arg-type]
    )
    loaded = load_qualification_result(
        path,
        output_root=fixture["output"],  # type: ignore[arg-type]
        evidence_root=fixture["evidence"],  # type: ignore[arg-type]
        trusted_policy=fixture["policy"],  # type: ignore[arg-type]
        trusted_inventory=fixture["inventory"],  # type: ignore[arg-type]
    )
    projection_path = path.with_name("consumer.projection.json")
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    verify_consumer_projection(projection, loaded)
    projection_path.unlink()
    write_qualification_result(
        fixture["output"],  # type: ignore[arg-type]
        loaded,
        evidence_root=fixture["evidence"],  # type: ignore[arg-type]
        trusted_policy=fixture["policy"],  # type: ignore[arg-type]
        trusted_inventory=fixture["inventory"],  # type: ignore[arg-type]
    )
    assert projection_path.is_file()


def test_mutation_between_qualification_and_publication_fails(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    result = qualify_upstreams(_request(fixture))
    fixture["artifact_path"].write_bytes(b"mutated")  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="changed after qualification"):
        write_qualification_result(
            fixture["output"],  # type: ignore[arg-type]
            result,
            evidence_root=fixture["evidence"],  # type: ignore[arg-type]
            trusted_policy=fixture["policy"],  # type: ignore[arg-type]
            trusted_inventory=fixture["inventory"],  # type: ignore[arg-type]
        )


def test_prerequisite_mutation_between_qualification_and_publication_fails(
    tmp_path: Path,
) -> None:
    fixture = build_upstream_fixture(tmp_path)
    result = qualify_upstreams(_request(fixture))
    fixture["prereq_path"].write_bytes(b"mutated")  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="changed after qualification"):
        write_qualification_result(
            fixture["output"],  # type: ignore[arg-type]
            result,
            evidence_root=fixture["evidence"],  # type: ignore[arg-type]
            trusted_policy=fixture["policy"],  # type: ignore[arg-type]
            trusted_inventory=fixture["inventory"],  # type: ignore[arg-type]
        )


def test_missing_receipt_is_visible_and_cannot_authorize_use(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    fixture["receipt_path"].unlink()  # type: ignore[union-attr]
    result = qualify_upstreams(_request(fixture))
    assert result["outcome"] == "blocked_missing"
    assert result["decisions"][0]["blockers"] == ["observation_receipt_missing"]
    assert result["decisions"][0]["permitted_use"] == []


def test_untrusted_observer_signature_is_rejected(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    keys = fixture["keys"]
    resign_json(receipt_path, keys["qualification-key"], "qualification-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="untrusted authority"):
        qualify_upstreams(_request(fixture))


@pytest.mark.parametrize(
    ("state", "expected"),
    [("Pending", "blocked_pending"), ("Denied", "denied"), ("Failed", "failed")],
)
def test_prerequisite_states_remain_distinct(tmp_path: Path, state: str, expected: str) -> None:
    fixture = build_upstream_fixture(tmp_path)
    prereq_path = fixture["prereq_path"]
    assert isinstance(prereq_path, Path)
    payload = json.loads(prereq_path.read_text(encoding="utf-8"))
    payload["status"] = state
    payload["implementation_state"] = "Blocked" if state != "Failed" else "Failed"
    prereq_path.write_text(json.dumps(payload), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(prereq_path, keys["prereq-key"], "prereq-key")  # type: ignore[index]
    assert qualify_upstreams(_request(fixture))["outcome"] == expected


def test_skipped_or_mocked_capability_cannot_qualify(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["capability_evidence"][0]["execution_state"] = "skipped"
    receipt["capability_evidence"][0]["mocked"] = True
    _mutate_execution_evidence(fixture, receipt, execution_state="skipped")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    result = qualify_upstreams(_request(fixture))
    assert result["outcome"] == "unsupported"
    assert result["decisions"][0]["permitted_use"] == []


def test_stale_activity_observation_cannot_qualify(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["activity"]["observed_at"] = "2000-01-01T00:00:00Z"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    result = qualify_upstreams(_request(fixture))
    assert result["outcome"] == "stale"
    assert result["decisions"][0]["blockers"] == ["activity_observation_expired"]


@pytest.mark.parametrize(
    ("observed_at", "expected_outcome", "expected_blockers"),
    [
        ("2026-09-17T12:00:00Z", "qualified", []),
        ("2026-09-18T12:05:00Z", "qualified", []),
        ("2026-09-18T12:05:01Z", "stale", ["activity_observation_from_future"]),
    ],
)
def test_activity_freshness_boundaries_are_deterministic(
    tmp_path: Path,
    observed_at: str,
    expected_outcome: str,
    expected_blockers: list[str],
) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["activity"]["observed_at"] = observed_at
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    result = qualify_upstreams(_request(fixture))
    assert result["evaluation_time"] == "2026-09-18T12:00:00Z"
    assert result["outcome"] == expected_outcome
    assert result["decisions"][0]["blockers"] == expected_blockers


def test_missing_freshness_policy_fails_closed(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    policy_path = fixture["policy_path"]
    assert isinstance(policy_path, Path)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    del policy["activity_freshness"]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation failed"):
        qualify_upstreams(_request(fixture))


def test_assertion_only_capability_and_compatibility_cannot_qualify(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["capability_evidence"][0]["command"] = [
        "definitely-not-an-executable",
        "--claim-success",
    ]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    supporting_paths = fixture["supporting_paths"]
    supporting_paths["execution_evidence"].unlink()  # type: ignore[index]
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="Capability execution evidence"):
        qualify_upstreams(_request(fixture))


@pytest.mark.parametrize(
    "evidence_name",
    [
        "execution_evidence",
        "environment_evidence",
        "output_evidence",
        "negative_case_evidence",
        "compatibility_evidence",
    ],
)
def test_mutated_runtime_evidence_cannot_qualify(tmp_path: Path, evidence_name: str) -> None:
    fixture = build_upstream_fixture(tmp_path)
    supporting_paths = fixture["supporting_paths"]
    supporting_paths[evidence_name].write_bytes(b"substituted evidence")  # type: ignore[index]
    with pytest.raises(ValueError, match="bytes do not match attributable evidence"):
        qualify_upstreams(_request(fixture))


def test_prerequisite_acceptance_and_decision_are_governed(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    prereq_path = fixture["prereq_path"]
    assert isinstance(prereq_path, Path)
    prerequisite = json.loads(prereq_path.read_text(encoding="utf-8"))
    prerequisite["acceptance_digest"] = "0" * 64
    prereq_path.write_text(json.dumps(prerequisite), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(prereq_path, keys["prereq-key"], "prereq-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="approved acceptance source|reconstructable"):
        qualify_upstreams(_request(fixture))


def test_arbitrary_prerequisite_decision_identity_cannot_qualify(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    prereq_path = fixture["prereq_path"]
    assert isinstance(prereq_path, Path)
    prerequisite = json.loads(prereq_path.read_text(encoding="utf-8"))
    prerequisite["decision_id"] = "arbitrary-unreconciled-decision"
    prereq_path.write_text(json.dumps(prerequisite), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(prereq_path, keys["prereq-key"], "prereq-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="reconstructable"):
        qualify_upstreams(_request(fixture))


def test_observer_cannot_self_attest_supporting_execution(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    supporting_paths = fixture["supporting_paths"]
    execution_path = supporting_paths["execution_evidence"]  # type: ignore[index]
    keys = fixture["keys"]
    resign_json(execution_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    data = execution_path.read_bytes()
    receipt["capability_evidence"][0]["execution_evidence"].update(
        {"byte_count": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    )
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="untrusted authority"):
        qualify_upstreams(_request(fixture))


def test_superseded_prerequisite_decision_cannot_qualify(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    prereq_path = fixture["prereq_path"]
    assert isinstance(prereq_path, Path)
    prerequisite = json.loads(prereq_path.read_text(encoding="utf-8"))
    prerequisite["decision_state"] = "superseded"
    prereq_path.write_text(json.dumps(prerequisite), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(prereq_path, keys["prereq-key"], "prereq-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="superseded"):
        qualify_upstreams(_request(fixture))


def test_nonzero_capability_exit_and_protected_metadata_fail_closed(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["capability_evidence"][0]["exit_status"] = 9
    _mutate_execution_evidence(fixture, receipt, exit_status=9)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    assert qualify_upstreams(_request(fixture))["outcome"] == "failed"

    fixture = build_upstream_fixture(tmp_path / "protected")
    receipt_path = fixture["receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    receipt["capability_evidence"][0]["command"] = ["api_key=secret-canary-value"]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")  # type: ignore[union-attr]
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[arg-type,index]
    with pytest.raises(ValueError, match="protected data or a secret"):
        qualify_upstreams(_request(fixture))


def test_caller_disposition_and_optional_attestation_cannot_authorize(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["disposition"] = "adopt_directly"
    receipt["license_approved"] = True
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="schema validation failed"):
        qualify_upstreams(_request(fixture))


def test_unknown_enum_and_boundary_escape_fail_closed(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    receipt_path = fixture["receipt_path"]
    assert isinstance(receipt_path, Path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["compatibility"]["state"] = "compatibile"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[index]
    with pytest.raises(ValueError, match="schema validation failed"):
        qualify_upstreams(_request(fixture))
    fixture = build_upstream_fixture(tmp_path / "second")
    receipt_path = fixture["receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    receipt["artifact"]["relative_path"] = "artifacts/%252e%252e/escape.bin"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")  # type: ignore[union-attr]
    keys = fixture["keys"]
    resign_json(receipt_path, keys["observer-key"], "observer-key")  # type: ignore[arg-type,index]
    with pytest.raises(ValueError, match="schema validation failed|escapes evidence root"):
        qualify_upstreams(_request(fixture))


def test_strict_verifier_rejects_resigned_broadened_disposition(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    result = qualify_upstreams(_request(fixture))
    result["decisions"][0]["disposition"] = "adopt_directly"
    result["decisions"][0]["permitted_use"] = ["runtime"]
    result["content_digest"] = digest_value({**result, "content_digest": "", "proof": {}})
    keys = fixture["keys"]
    sign_payload(
        result,
        private_key_path=keys["qualification-key"],  # type: ignore[index]
        key_id="qualification-key",
    )
    with pytest.raises(ValueError, match="broadens or substitutes"):
        write_qualification_result(
            fixture["output"],  # type: ignore[arg-type]
            result,
            evidence_root=fixture["evidence"],  # type: ignore[arg-type]
            trusted_policy=fixture["policy"],  # type: ignore[arg-type]
            trusted_inventory=fixture["inventory"],  # type: ignore[arg-type]
        )


def test_upstream_publication_fails_closed_on_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = build_upstream_fixture(tmp_path)
    result = qualify_upstreams(_request(fixture))
    output_root = fixture["output"]
    assert isinstance(output_root, Path)
    parent = (
        output_root
        / "runs"
        / result["run_id"]
        / "upstream"
        / result["scope_id"]
        / "attempts"
        / result["attempt_id"]
    )
    displaced = tmp_path / "displaced-upstream"
    outside = tmp_path / "outside-upstream"
    outside.mkdir()
    real_link = os.link
    swapped = False

    def swap_parent_then_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(displaced)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr("smf.immutable_files.os.link", swap_parent_then_link)

    with pytest.raises(ValueError, match="malformed|unsafe|outside"):
        write_qualification_result(
            output_root,
            result,
            evidence_root=fixture["evidence"],  # type: ignore[arg-type]
            trusted_policy=fixture["policy"],  # type: ignore[arg-type]
            trusted_inventory=fixture["inventory"],  # type: ignore[arg-type]
        )

    assert not (outside / "qualification.result.json").exists()
    assert not (outside / "consumer.projection.json").exists()
    assert not (outside / "telemetry.json").exists()


def test_duplicate_and_empty_inventories_are_rejected(tmp_path: Path) -> None:
    fixture = build_upstream_fixture(tmp_path)
    inventory_path = fixture["inventory_path"]
    assert isinstance(inventory_path, Path)
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    duplicate = dict(inventory["upstreams"][0])
    duplicate["upstream_id"] = "DEMO"
    inventory["upstreams"].append(duplicate)
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicated or case-ambiguous"):
        load_upstream_inventory(inventory_path)
    inventory["upstreams"] = []
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation failed"):
        load_upstream_inventory(inventory_path)


def test_approved_inventory_covers_recovery_report_set() -> None:
    inventory = load_upstream_inventory(Path("competition/upstream/approved-inventory.json"))
    assert len(inventory.payload["upstreams"]) == 24
    assert {item["disposition"] for item in inventory.payload["upstreams"]} == {
        "adopt_directly",
        "wrap",
        "reuse_transitively",
        "reuse_selected_licensed_components",
        "patterns_only",
        "reject",
    }


def test_cli_qualifies_and_recovers_missing_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = build_upstream_fixture(tmp_path)
    keys = fixture["keys"]
    arguments = [
        "smf",
        "upstream",
        "qualify",
        "--policy",
        str(fixture["policy_path"]),
        "--inventory",
        str(fixture["inventory_path"]),
        "--evidence-root",
        str(fixture["evidence"]),
        "--scope-id",
        "program",
        "--run-id",
        "run-1",
        "--attempt-id",
        "attempt-1",
        "--evaluation-time",
        "2026-09-18T12:00:00Z",
        "--signing-key",
        str(keys["qualification-key"]),  # type: ignore[index]
        "--signing-key-id",
        "qualification-key",
        "--signing-authority",
        "qualification-service",
        "--out",
        str(fixture["output"]),
        "--json",
    ]
    monkeypatch.setattr("sys.argv", arguments)
    assert main() == 0
    summary = json.loads(capsys.readouterr().out)
    result_path = Path(summary["result_path"])
    projection = result_path.with_name("consumer.projection.json")
    projection.unlink()
    assert main() == 0
    assert projection.is_file()
