from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.validation.row_count import (
    RowCountPolicy,
    RowCountRequest,
    evaluate_row_count,
    publish_row_count,
    verify_current_row_count,
    verify_row_count_result,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _request(**changes: object) -> RowCountRequest:
    values: dict[str, object] = {
        "client_id": "synthetic-client",
        "workload_id": "workload-a",
        "source_id": "dataset-a",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "source_snapshot_id": "source-v1",
        "source_snapshot_digest": DIGEST_A,
        "target_snapshot_id": "target-v1",
        "target_snapshot_digest": DIGEST_B,
        "evaluated_at": "2026-09-21T17:00:00Z",
        "source_count": 100,
        "target_count": 100,
    }
    values.update(changes)
    return RowCountRequest(**values)  # type: ignore[arg-type]


def _policy(mode: str = "exact", **changes: object) -> RowCountPolicy:
    values: dict[str, object] = {
        "policy_id": "synthetic-row-count",
        "policy_version": "1.0.0",
        "mode": mode,
    }
    values.update(changes)
    return RowCountPolicy(**values)  # type: ignore[arg-type]


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _rehash_outer(result: dict[str, object]) -> None:
    projection = copy.deepcopy(result)
    projection.pop("content_digest")
    projection.pop("result_id")
    result["result_id"] = _digest(projection)
    content = copy.deepcopy(result)
    content.pop("content_digest")
    result["content_digest"] = _digest(content)


@pytest.mark.parametrize(
    ("policy", "source", "target", "expected"),
    [
        (_policy(), 100, 100, "passed"),
        (_policy(), 100, 101, "failed"),
        (_policy("absolute", absolute_tolerance=2), 100, 102, "passed"),
        (_policy("absolute", absolute_tolerance=2), 100, 103, "failed"),
        (_policy("relative", relative_tolerance="0.02"), 100, 102, "passed"),
        (_policy("relative", relative_tolerance="0.02"), 100, 103, "failed"),
        (_policy("relative", relative_tolerance="0.02"), 0, 0, "passed"),
        (_policy("relative", relative_tolerance="1"), 0, 1, "failed"),
    ],
)
def test_exact_absolute_relative_and_zero_boundaries(
    policy: RowCountPolicy, source: int, target: int, expected: str
) -> None:
    result = evaluate_row_count(_request(source_count=source, target_count=target), policy)
    assert result["status"] == expected
    assert result["claims"]["row_count_check_passed"] is (expected == "passed")
    assert result["claims"]["data_parity_passed"] is False
    assert result["claims"]["certified"] is False


def test_relative_uses_source_denominator_without_rounding_boundary() -> None:
    policy = _policy("relative", relative_tolerance="0.015")
    at_boundary = evaluate_row_count(_request(source_count=200, target_count=203), policy)
    outside = evaluate_row_count(_request(source_count=200, target_count=204), policy)
    assert at_boundary["permitted_difference"] == "3.000"
    assert at_boundary["relative_denominator_value"] == 200
    assert at_boundary["status"] == "passed"
    assert outside["status"] == "failed"


@pytest.mark.parametrize(("source", "target"), [(None, 10), (10, None), (None, None)])
def test_missing_counts_are_blocked_not_warned(source: int | None, target: int | None) -> None:
    result = evaluate_row_count(_request(source_count=source, target_count=target), _policy())
    assert result["status"] == "blocked"
    assert result["claims"]["source_target_counts_compared"] is False
    assert result["claims"]["row_count_check_passed"] is False
    assert result["blockers"]


@pytest.mark.parametrize(("field", "value"), [("source_count", -1), ("target_count", -1)])
def test_negative_and_boolean_counts_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=field):
        evaluate_row_count(_request(**{field: value}), _policy())
    with pytest.raises(ValueError, match=field):
        evaluate_row_count(_request(**{field: True}), _policy())


@pytest.mark.parametrize(
    "policy",
    [
        _policy("exact", absolute_tolerance=1),
        _policy("absolute", absolute_tolerance=1, relative_tolerance="0.1"),
        _policy("relative", relative_tolerance="1.0"),
        _policy("relative", relative_tolerance="0.00"),
        _policy("exact", relative_tolerance="0.0"),
        _policy("absolute", absolute_tolerance=1, relative_tolerance="0.0"),
        _policy("relative", relative_tolerance="1.1"),
    ],
)
def test_ambiguous_or_noncanonical_policies_are_rejected(policy: RowCountPolicy) -> None:
    with pytest.raises(ValueError):
        policy.to_dict()


def test_current_replay_rejects_coherent_result_and_policy_mutations() -> None:
    request = _request()
    policy = _policy()
    result = evaluate_row_count(request, policy)
    forged = evaluate_row_count(replace(request, target_count=101), policy)
    verify_row_count_result(forged)
    with pytest.raises(ValueError, match="current request and policy"):
        verify_current_row_count(forged, request, policy)
    with pytest.raises(ValueError, match="current request and policy"):
        verify_current_row_count(result, request, _policy("absolute", absolute_tolerance=1))


@pytest.mark.parametrize(
    "evaluated_at",
    ["2026-09-21 17:00:00+00:00", "2026-09-21", "2026-W39-1T17:00:00Z", "invalid"],
)
def test_evaluation_time_requires_canonical_rfc3339(evaluated_at: str) -> None:
    with pytest.raises(ValueError, match="RFC3339"):
        evaluate_row_count(_request(evaluated_at=evaluated_at), _policy())


def test_recomputed_digest_forgery_and_claim_escalation_are_rejected() -> None:
    result = evaluate_row_count(_request(), _policy())
    forged = copy.deepcopy(result)
    forged["status"] = "failed"
    with pytest.raises(ValueError, match="digest"):
        verify_row_count_result(forged)
    claim = copy.deepcopy(result)
    claim["claims"]["data_parity_passed"] = True
    with pytest.raises(ValueError):
        verify_row_count_result(claim)


@pytest.mark.parametrize("mutation", ["count", "policy", "math"])
def test_coherent_outer_rehash_cannot_hide_nested_inconsistency(mutation: str) -> None:
    result: dict[str, object] = copy.deepcopy(evaluate_row_count(_request(), _policy()))
    if mutation == "count":
        request = result["request"]
        assert isinstance(request, dict)
        request["target_count"] = 101
    elif mutation == "policy":
        policy = result["policy"]
        assert isinstance(policy, dict)
        policy["mode"] = "absolute"
        policy["absolute_tolerance"] = 1
    else:
        result["status"] = "failed"
        result["difference"] = 99
        claims = result["claims"]
        assert isinstance(claims, dict)
        claims["row_count_check_passed"] = False
    _rehash_outer(result)
    with pytest.raises(ValueError, match="governed request and policy|digest mismatch"):
        verify_row_count_result(result)


def test_result_schema_rejects_missing_and_unknown_nested_fields() -> None:
    result = evaluate_row_count(_request(), _policy())
    missing = copy.deepcopy(result)
    del missing["request"]["source_snapshot_id"]
    with pytest.raises(ValueError, match="schema validation"):
        verify_row_count_result(missing)
    unknown = copy.deepcopy(result)
    unknown["claims"]["warning_only"] = True
    with pytest.raises(ValueError, match="schema validation"):
        verify_row_count_result(unknown)


def test_immutable_publication_restart_mutation_and_isolation(tmp_path: Path) -> None:
    request = _request()
    policy = _policy()
    first, first_path = publish_row_count(tmp_path, request, policy)
    retry, retry_path = publish_row_count(tmp_path, request, policy)
    assert retry == first
    assert retry_path == first_path

    second_request = replace(request, workload_id="workload-b")
    second, second_path = publish_row_count(tmp_path, second_request, policy)
    assert second_path != first_path
    assert second["request"]["workload_id"] == "workload-b"

    first_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises((FileExistsError, ValueError)):
        publish_row_count(tmp_path, request, policy)


def test_path_escape_secret_like_identity_and_symlink_are_rejected(tmp_path: Path) -> None:
    for unsafe in ("../escape", "Bearer-secret", "a/b"):
        with pytest.raises(ValueError, match="Unsafe"):
            publish_row_count(tmp_path, replace(_request(), client_id=unsafe), _policy())
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "synthetic-client").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|directory"):
        publish_row_count(tmp_path, _request(), _policy())


def test_public_and_packaged_schemas_match_and_validate_real_result() -> None:
    root = Path(__file__).parents[2]
    public_policy = root / "schemas/row-count-tolerance-policy.schema.json"
    package_policy = root / "src/smf/schemas/row-count-tolerance-policy.schema.json"
    public_result = root / "schemas/row-count-tolerance-result.schema.json"
    package_result = root / "src/smf/schemas/row-count-tolerance-result.schema.json"
    assert public_policy.read_bytes() == package_policy.read_bytes()
    assert public_result.read_bytes() == package_result.read_bytes()
    policy_schema = json.loads(public_policy.read_text(encoding="utf-8"))
    result_schema = json.loads(public_result.read_text(encoding="utf-8"))
    registry = Registry().with_resource(policy_schema["$id"], Resource.from_contents(policy_schema))
    Draft202012Validator(result_schema, registry=registry).validate(
        evaluate_row_count(_request(), _policy())
    )
