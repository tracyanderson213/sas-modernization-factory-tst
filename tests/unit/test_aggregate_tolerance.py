from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from smf.validation.aggregate_tolerance import (
    AggregatePolicy,
    AggregateRequest,
    GroupObservation,
    evaluate_aggregates,
    publish_aggregates,
    verify_aggregate_result,
    verify_current_aggregates,
)

D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64


def _policy(**changes: object) -> AggregatePolicy:
    values: dict[str, object] = {
        "policy_id": "aggregate-policy",
        "policy_version": "1.0.0",
        "measure_id": "amount",
        "group_keys": ("region",),
        "absolute_tolerance": "1",
        "relative_tolerance": "0.01",
        "maximum_absolute_value": "1000000",
    }
    values.update(changes)
    return AggregatePolicy(**values)  # type: ignore[arg-type]


def _group(key: str, value: str | None, nulls: int = 0) -> GroupObservation:
    return GroupObservation((("region", key),), value, nulls)


def _request(
    source: tuple[GroupObservation, ...], target: tuple[GroupObservation, ...], **changes: object
) -> AggregateRequest:
    values: dict[str, object] = {
        "client_id": "client-a",
        "workload_id": "workload-a",
        "source_id": "source-a",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "source_snapshot_digest": D1,
        "target_snapshot_digest": D2,
        "source": source,
        "target": target,
    }
    values.update(changes)
    return AggregateRequest(**values)  # type: ignore[arg-type]


def _rehash(result: dict[str, object]) -> None:
    projection = copy.deepcopy(result)
    projection.pop("content_digest")
    projection.pop("result_id")
    encoded = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    result["result_id"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    content = copy.deepcopy(result)
    content.pop("content_digest")
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    result["content_digest"] = "sha256:" + hashlib.sha256(encoded).hexdigest()


def test_each_group_must_pass_and_offsetting_errors_cannot_hide() -> None:
    result = evaluate_aggregates(
        _request((_group("a", "100"), _group("b", "100")), (_group("a", "102"), _group("b", "98"))),
        _policy(),
    )
    assert result["status"] == "failed"
    assert [x["status"] for x in result["checks"]] == ["failed", "failed"]
    assert result["claims"]["data_parity_passed"] is False


def test_absolute_and_relative_inclusive_boundary() -> None:
    passed = evaluate_aggregates(_request((_group("a", "100"),), (_group("a", "101"),)), _policy())
    failed = evaluate_aggregates(
        _request((_group("a", "100"),), (_group("a", "101.0001"),)), _policy()
    )
    assert passed["status"] == "passed"
    assert failed["status"] == "failed"


@pytest.mark.parametrize(
    ("source", "target", "reason"),
    [
        ((_group("a", "1"),), (), "missing_group"),
        ((_group("a", None, 1),), (_group("a", "0", 1),), "null_semantics_mismatch"),
        ((_group("a", "1", 1),), (_group("a", "1", 2),), "null_count_mismatch"),
    ],
)
def test_missing_groups_and_null_semantics_fail(
    source: tuple[GroupObservation, ...], target: tuple[GroupObservation, ...], reason: str
) -> None:
    result = evaluate_aggregates(_request(source, target), _policy())
    assert result["status"] == "failed"
    assert result["checks"][0]["reason"] == reason


@pytest.mark.parametrize("value", ["NaN", "Infinity", "1.0", "01"])
def test_nonfinite_and_noncanonical_values_reject(value: str) -> None:
    with pytest.raises(ValueError):
        evaluate_aggregates(_request((_group("a", value),), (_group("a", "1"),)), _policy())


def test_overflow_blocks_and_duplicates_reject() -> None:
    blocked = evaluate_aggregates(
        _request((_group("a", "1000001"),), (_group("a", "1000001"),)), _policy()
    )
    assert blocked["status"] == "blocked"
    with pytest.raises(ValueError, match="Duplicate"):
        evaluate_aggregates(
            _request((_group("a", "1"), _group("a", "1")), (_group("a", "1"),)), _policy()
        )


def test_duplicate_group_keys_and_boolean_null_counts_reject_before_projection() -> None:
    duplicate_key = GroupObservation((("region", "a"), ("region", "b")), "1", 0)
    with pytest.raises(ValueError, match="Duplicate aggregate group key"):
        evaluate_aggregates(_request((duplicate_key,), (_group("a", "1"),)), _policy())
    boolean_null = GroupObservation((("region", "a"),), "1", True)
    with pytest.raises(ValueError, match="null_count"):
        evaluate_aggregates(_request((boolean_null,), (_group("a", "1"),)), _policy())


def test_protected_identity_and_symlink_publication_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsafe"):
        evaluate_aggregates(
            _request((_group("Bearer-secret", "1"),), (_group("Bearer-secret", "1"),)),
            _policy(),
        )
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "client-a").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|directory"):
        publish_aggregates(
            tmp_path,
            _request((_group("a", "1"),), (_group("a", "1"),)),
            _policy(),
        )


def test_current_replay_mutation_immutable_restart_and_isolation(tmp_path: Path) -> None:
    request = _request((_group("a", "10"),), (_group("a", "10"),))
    result, path = publish_aggregates(tmp_path, request, _policy())
    assert publish_aggregates(tmp_path, request, _policy()) == (result, path)
    with pytest.raises(ValueError, match="current request"):
        verify_current_aggregates(result, replace(request, target=(_group("a", "11"),)), _policy())
    other, other_path = publish_aggregates(
        tmp_path, replace(request, workload_id="workload-b"), _policy()
    )
    assert other_path != path and other["request"]["workload_id"] == "workload-b"
    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises((ValueError, FileExistsError)):
        publish_aggregates(tmp_path, request, _policy())


def test_snapshot_policy_and_claim_mutations_fail_current_replay() -> None:
    request = _request((_group("a", "10"),), (_group("a", "10"),))
    result = evaluate_aggregates(request, _policy())
    forged = copy.deepcopy(result)
    forged["claims"]["data_parity_passed"] = True
    with pytest.raises(ValueError, match="current request|schema validation"):
        verify_current_aggregates(forged, request, _policy())


@pytest.mark.parametrize("mutation", ["value", "policy", "math"])
def test_standalone_verifier_rejects_coherent_outer_rehash(mutation: str) -> None:
    result: dict[str, object] = copy.deepcopy(
        evaluate_aggregates(_request((_group("a", "10"),), (_group("a", "10"),)), _policy())
    )
    if mutation == "value":
        request = result["request"]
        assert isinstance(request, dict)
        request["target"][0]["value"] = "11"
    elif mutation == "policy":
        policy = result["policy"]
        assert isinstance(policy, dict)
        policy["absolute_tolerance"] = "2"
    else:
        result["status"] = "failed"
        checks = result["checks"]
        claims = result["claims"]
        assert isinstance(checks, list) and isinstance(checks[0], dict)
        assert isinstance(claims, dict)
        checks[0]["status"] = "failed"
        checks[0]["reason"] = "outside_tolerance"
        claims["aggregate_check_passed"] = False
    _rehash(result)
    with pytest.raises(ValueError, match="governed request and policy"):
        verify_aggregate_result(result)


def test_strict_schema_and_schema_byte_parity() -> None:
    result = evaluate_aggregates(_request((_group("a", "1"),), (_group("a", "1"),)), _policy())
    verify_aggregate_result(result)
    unknown = copy.deepcopy(result)
    unknown["claims"]["warning"] = True
    with pytest.raises(ValueError, match="schema validation"):
        verify_aggregate_result(unknown)
    root = Path(__file__).parents[2]
    assert (root / "schemas/aggregate-tolerance-result.schema.json").read_bytes() == (
        root / "src/smf/schemas/aggregate-tolerance-result.schema.json"
    ).read_bytes()
