"""Versioned, fail-closed row-count tolerance evaluation for TASK-11.

The evaluator consumes caller-supplied *observations* but never treats a passing
row-count comparison as data parity, certification, or customer approval.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.immutable_files import publish_json, read_published_json

Mode = Literal["exact", "absolute", "relative"]
Status = Literal["passed", "failed", "blocked"]

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(payload: dict[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(_canonical(payload)).hexdigest()}"


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{name} must contain an object")
    return cast(dict[str, Any], value)


def _validate_schema(payload: dict[str, Any], name: str, label: str) -> None:
    policy_schema = _schema("row-count-tolerance-policy.schema.json")
    registry = Registry().with_resource(
        cast(str, policy_schema["$id"]), Resource.from_contents(policy_schema)
    )
    errors = sorted(
        Draft202012Validator(_schema(name), registry=registry).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"{label} schema validation failed: {detail}")


def _safe_id(value: str, label: str) -> None:
    lowered = value.casefold()
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or any(marker in lowered for marker in ("bearer", "secret", "password", "api-key", "token"))
    ):
        raise ValueError(f"Unsafe {label}")


@dataclass(frozen=True)
class RowCountPolicy:
    policy_id: str
    policy_version: str
    mode: Mode
    absolute_tolerance: int = 0
    relative_tolerance: str = "0"
    relative_denominator: Literal["source"] = "source"
    zero_source_rule: Literal["both_zero_only"] = "both_zero_only"
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        validate_policy(payload)
        return payload


@dataclass(frozen=True)
class RowCountRequest:
    client_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    source_snapshot_id: str
    source_snapshot_digest: str
    target_snapshot_id: str
    target_snapshot_digest: str
    evaluated_at: str
    source_count: int | None
    target_count: int | None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for name in (
            "client_id",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "source_snapshot_id",
            "target_snapshot_id",
        ):
            _safe_id(cast(str, payload[name]), name)
        for name in ("source_snapshot_digest", "target_snapshot_digest"):
            if not _DIGEST.fullmatch(cast(str, payload[name])):
                raise ValueError(f"Invalid {name}")
        if not _RFC3339.fullmatch(self.evaluated_at):
            raise ValueError("evaluated_at must be canonical UTC RFC3339")
        try:
            datetime.fromisoformat(self.evaluated_at.removesuffix("Z") + "+00:00")
        except ValueError as exc:
            raise ValueError("evaluated_at must be canonical UTC RFC3339") from exc
        for name in ("source_count", "target_count"):
            value = payload[name]
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer or null")
        return payload


def validate_policy(payload: dict[str, Any]) -> None:
    _validate_schema(payload, "row-count-tolerance-policy.schema.json", "Row-count policy")
    for name in ("policy_id", "policy_version"):
        _safe_id(cast(str, payload[name]), name)
    try:
        relative = Decimal(cast(str, payload["relative_tolerance"]))
    except InvalidOperation as exc:
        raise ValueError("relative_tolerance must be a canonical decimal") from exc
    if not relative.is_finite() or relative < 0 or relative > 1:
        raise ValueError("relative_tolerance must be between zero and one")
    canonical = "0" if relative == 0 else format(relative.normalize(), "f")
    if canonical != payload["relative_tolerance"]:
        raise ValueError("relative_tolerance must use canonical decimal notation")
    mode = payload["mode"]
    absolute = payload["absolute_tolerance"]
    if mode == "exact" and (absolute != 0 or relative != 0):
        raise ValueError("exact policy cannot carry a tolerance")
    if mode == "absolute" and relative != 0:
        raise ValueError("absolute policy cannot carry relative tolerance")
    if mode == "relative" and absolute != 0:
        raise ValueError("relative policy cannot carry absolute tolerance")


def _result_projection(request: RowCountRequest, policy: RowCountPolicy) -> dict[str, Any]:
    request_payload = request.to_dict()
    policy_payload = policy.to_dict()
    source = request.source_count
    target = request.target_count
    difference = None if source is None or target is None else abs(source - target)
    denominator: int | None = None
    permitted_difference: str | None = None
    blockers: list[str] = []
    if source is None:
        blockers.append("source_row_count_missing")
    if target is None:
        blockers.append("target_row_count_missing")
    passed = False
    if not blockers:
        assert source is not None and target is not None and difference is not None
        if policy.mode == "exact":
            permitted_difference = "0"
            passed = difference == 0
        elif policy.mode == "absolute":
            permitted_difference = str(policy.absolute_tolerance)
            passed = difference <= policy.absolute_tolerance
        elif source == 0:
            denominator = 0
            permitted_difference = "0"
            passed = target == 0
        else:
            denominator = source
            permitted = Decimal(source) * Decimal(policy.relative_tolerance)
            permitted_difference = format(permitted, "f")
            passed = Decimal(difference) <= permitted
    status: Status = "blocked" if blockers else ("passed" if passed else "failed")
    projection: dict[str, Any] = {
        "schema_version": "1.0",
        "request": request_payload,
        "request_digest": _digest(request_payload),
        "policy": policy_payload,
        "policy_digest": _digest(policy_payload),
        "status": status,
        "difference": difference,
        "relative_denominator_value": denominator,
        "permitted_difference": permitted_difference,
        "blockers": blockers,
        "claims": {
            "policy_evaluated": True,
            "source_target_counts_compared": not blockers,
            "row_count_check_passed": status == "passed",
            "data_parity_passed": False,
            "certified": False,
            "human_approved": False,
            "humana_validated": False,
        },
    }
    return projection


def evaluate_row_count(request: RowCountRequest, policy: RowCountPolicy) -> dict[str, Any]:
    projection = _result_projection(request, policy)
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    verify_row_count_result(result)
    return result


def verify_row_count_result(result: dict[str, Any]) -> None:
    _validate_schema(result, "row-count-tolerance-result.schema.json", "Row-count result")
    content = dict(result)
    observed_content = cast(str, content.pop("content_digest"))
    if observed_content != _digest(content):
        raise ValueError("Row-count result content digest mismatch")
    projection = dict(content)
    observed_id = cast(str, projection.pop("result_id"))
    if observed_id != _digest(projection):
        raise ValueError("Row-count result identity mismatch")
    blockers = cast(list[str], result["blockers"])
    status = cast(str, result["status"])
    claims = cast(dict[str, bool], result["claims"])
    if (status == "blocked") != bool(blockers):
        raise ValueError("Row-count blocker/status mismatch")
    if claims["source_target_counts_compared"] != (not blockers):
        raise ValueError("Row-count comparison claim mismatch")
    if claims["row_count_check_passed"] != (status == "passed"):
        raise ValueError("Row-count pass claim mismatch")
    if result["claims"]["data_parity_passed"] or result["claims"]["certified"]:
        raise ValueError("Row-count evidence cannot establish parity or certification")
    request = RowCountRequest(**cast(dict[str, Any], result["request"]))
    policy = RowCountPolicy(**cast(dict[str, Any], result["policy"]))
    expected_projection = _result_projection(request, policy)
    expected = {"result_id": _digest(expected_projection), **expected_projection}
    expected["content_digest"] = _digest(expected)
    if result != expected:
        raise ValueError("Row-count result does not match its governed request and policy")


def verify_current_row_count(
    result: dict[str, Any], request: RowCountRequest, policy: RowCountPolicy
) -> None:
    verify_row_count_result(result)
    if result != evaluate_row_count(request, policy):
        raise ValueError("Row-count result does not match current request and policy")


def result_path(root: Path, request: RowCountRequest) -> Path:
    request.to_dict()
    return (
        root
        / request.client_id
        / request.workload_id
        / request.run_id
        / request.attempt_id
        / "row-count"
        / "result.json"
    )


def publish_row_count(
    root: Path, request: RowCountRequest, policy: RowCountPolicy
) -> tuple[dict[str, Any], Path]:
    result = evaluate_row_count(request, policy)
    path = result_path(root, request)
    publish_json(path, result, "row-count result", root=root)
    observed = read_published_json(path, root=root, label="row-count result")
    if not isinstance(observed, dict):
        raise ValueError("Published row-count result must be an object")
    verify_current_row_count(observed, request, policy)
    return observed, path
