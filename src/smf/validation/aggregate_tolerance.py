"""Deterministic per-group aggregate tolerance mechanics for TASK-12."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft202012Validator

from smf.immutable_files import publish_json, read_published_json

_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _safe_identity(value: str) -> bool:
    lowered = value.casefold()
    return bool(_SAFE.fullmatch(value)) and not any(
        marker in lowered for marker in ("secret", "token", "password", "bearer", "api-key")
    )


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _validate_schema(payload: dict[str, Any]) -> None:
    schema = cast(
        dict[str, Any],
        json.loads(
            files("smf.schemas")
            .joinpath("aggregate-tolerance-result.schema.json")
            .read_text(encoding="utf-8")
        ),
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"Aggregate result schema validation failed: {detail}")


def _decimal(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be a decimal") from exc
    if not parsed.is_finite():
        raise ValueError(f"{label} must be finite")
    canonical = "0" if parsed == 0 else format(parsed.normalize(), "f")
    if canonical != value:
        raise ValueError(f"{label} must use canonical decimal notation")
    return parsed


@dataclass(frozen=True)
class AggregatePolicy:
    policy_id: str
    policy_version: str
    measure_id: str
    group_keys: tuple[str, ...]
    absolute_tolerance: str
    relative_tolerance: str
    maximum_absolute_value: str
    relative_denominator: Literal["source_absolute"] = "source_absolute"
    null_rule: Literal["both_null_only"] = "both_null_only"
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["group_keys"] = list(self.group_keys)
        for name in ("policy_id", "policy_version", "measure_id", *self.group_keys):
            if not _safe_identity(name):
                raise ValueError("Unsafe aggregate policy identity")
        if not self.group_keys or len(set(self.group_keys)) != len(self.group_keys):
            raise ValueError("Aggregate group keys must be non-empty and unique")
        absolute = _decimal(self.absolute_tolerance, "absolute_tolerance")
        relative = _decimal(self.relative_tolerance, "relative_tolerance")
        maximum = _decimal(self.maximum_absolute_value, "maximum_absolute_value")
        if absolute < 0 or relative < 0 or relative > 1 or maximum <= 0:
            raise ValueError("Aggregate tolerance bounds are invalid")
        return payload


@dataclass(frozen=True)
class GroupObservation:
    group: tuple[tuple[str, str], ...]
    value: str | None
    null_count: int

    def to_dict(self) -> dict[str, Any]:
        if (
            not isinstance(self.null_count, int)
            or isinstance(self.null_count, bool)
            or self.null_count < 0
        ):
            raise ValueError("null_count must be non-negative")
        group_keys = [key for key, _ in self.group]
        if len(group_keys) != len(set(group_keys)):
            raise ValueError("Duplicate aggregate group key")
        if self.value is not None:
            _decimal(self.value, "aggregate value")
        if any(not _safe_identity(key) or not _safe_identity(value) for key, value in self.group):
            raise ValueError("Unsafe aggregate group identity")
        return {"group": dict(self.group), "value": self.value, "null_count": self.null_count}


@dataclass(frozen=True)
class AggregateRequest:
    client_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    source_snapshot_digest: str
    target_snapshot_digest: str
    source: tuple[GroupObservation, ...]
    target: tuple[GroupObservation, ...]

    def to_dict(self) -> dict[str, Any]:
        for value in (
            self.client_id,
            self.workload_id,
            self.source_id,
            self.run_id,
            self.attempt_id,
        ):
            if not _safe_identity(value):
                raise ValueError("Unsafe aggregate request identity")
        for value in (self.source_snapshot_digest, self.target_snapshot_digest):
            if not _DIGEST.fullmatch(value):
                raise ValueError("Invalid snapshot digest")
        return {
            **asdict(self),
            "source": [x.to_dict() for x in self.source],
            "target": [x.to_dict() for x in self.target],
        }


def _index(
    items: tuple[GroupObservation, ...], policy: AggregatePolicy
) -> dict[tuple[str, ...], GroupObservation]:
    result: dict[tuple[str, ...], GroupObservation] = {}
    for item in items:
        values = dict(item.group)
        if set(values) != set(policy.group_keys):
            raise ValueError("Aggregate group shape does not match policy")
        identity = tuple(values[key] for key in policy.group_keys)
        if identity in result:
            raise ValueError("Duplicate aggregate group")
        item.to_dict()
        result[identity] = item
    return result


def evaluate_aggregates(request: AggregateRequest, policy: AggregatePolicy) -> dict[str, Any]:
    request_payload, policy_payload = request.to_dict(), policy.to_dict()
    source, target = _index(request.source, policy), _index(request.target, policy)
    absolute = Decimal(policy.absolute_tolerance)
    relative = Decimal(policy.relative_tolerance)
    maximum = Decimal(policy.maximum_absolute_value)
    checks: list[dict[str, Any]] = []
    for identity in sorted(set(source) | set(target)):
        left, right = source.get(identity), target.get(identity)
        status, reason, difference, permitted = "failed", "missing_group", None, None
        if left is not None and right is not None:
            if left.null_count != right.null_count:
                reason = "null_count_mismatch"
            elif (left.value is None) != (right.value is None):
                reason = "null_semantics_mismatch"
            elif left.value is None:
                status, reason = "passed", "both_null"
            else:
                assert right.value is not None
                left_value, right_value = Decimal(left.value), Decimal(right.value)
                if abs(left_value) > maximum or abs(right_value) > maximum:
                    status, reason = "blocked", "overflow_bound_exceeded"
                else:
                    delta = abs(left_value - right_value)
                    allowed = max(absolute, abs(left_value) * relative)
                    difference, permitted = format(delta, "f"), format(allowed, "f")
                    status = "passed" if delta <= allowed else "failed"
                    reason = "within_tolerance" if status == "passed" else "outside_tolerance"
        checks.append(
            {
                "group": dict(zip(policy.group_keys, identity, strict=True)),
                "status": status,
                "reason": reason,
                "difference": difference,
                "permitted_difference": permitted,
            }
        )
    status = (
        "blocked"
        if any(x["status"] == "blocked" for x in checks)
        else ("failed" if not checks or any(x["status"] == "failed" for x in checks) else "passed")
    )
    projection = {
        "schema_version": "1.0",
        "request": request_payload,
        "request_digest": _digest(request_payload),
        "policy": policy_payload,
        "policy_digest": _digest(policy_payload),
        "status": status,
        "checks": checks,
        "claims": {
            "aggregate_check_passed": status == "passed",
            "data_parity_passed": False,
            "certified": False,
            "humana_validated": False,
        },
    }
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    return result


def verify_current_aggregates(
    result: dict[str, Any], request: AggregateRequest, policy: AggregatePolicy
) -> None:
    verify_aggregate_result(result)
    if result != evaluate_aggregates(request, policy):
        raise ValueError("Aggregate result does not match current request and policy")


def verify_aggregate_result(result: dict[str, Any]) -> None:
    """Reconstruct every governed input and reject coherent outer rehashing."""
    _validate_schema(result)
    raw_policy = cast(dict[str, Any], result["policy"])
    policy = AggregatePolicy(
        policy_id=raw_policy["policy_id"],
        policy_version=raw_policy["policy_version"],
        measure_id=raw_policy["measure_id"],
        group_keys=tuple(raw_policy["group_keys"]),
        absolute_tolerance=raw_policy["absolute_tolerance"],
        relative_tolerance=raw_policy["relative_tolerance"],
        maximum_absolute_value=raw_policy["maximum_absolute_value"],
        relative_denominator=raw_policy["relative_denominator"],
        null_rule=raw_policy["null_rule"],
        schema_version=raw_policy["schema_version"],
    )
    raw_request = cast(dict[str, Any], result["request"])

    def observations(name: str) -> tuple[GroupObservation, ...]:
        return tuple(
            GroupObservation(
                tuple((key, item["group"][key]) for key in policy.group_keys),
                item["value"],
                item["null_count"],
            )
            for item in cast(list[dict[str, Any]], raw_request[name])
        )

    request = AggregateRequest(
        client_id=raw_request["client_id"],
        workload_id=raw_request["workload_id"],
        source_id=raw_request["source_id"],
        run_id=raw_request["run_id"],
        attempt_id=raw_request["attempt_id"],
        source_snapshot_digest=raw_request["source_snapshot_digest"],
        target_snapshot_digest=raw_request["target_snapshot_digest"],
        source=observations("source"),
        target=observations("target"),
    )
    if result != evaluate_aggregates(request, policy):
        raise ValueError("Aggregate result does not match its governed request and policy")


def publish_aggregates(
    root: Path, request: AggregateRequest, policy: AggregatePolicy
) -> tuple[dict[str, Any], Path]:
    result = evaluate_aggregates(request, policy)
    path = (
        root
        / request.client_id
        / request.workload_id
        / request.run_id
        / request.attempt_id
        / "aggregate"
        / "result.json"
    )
    publish_json(path, result, "aggregate result", root=root)
    observed = read_published_json(path, root=root, label="aggregate result")
    if not isinstance(observed, dict):
        raise ValueError("Aggregate result must be an object")
    verify_current_aggregates(observed, request, policy)
    return observed, path
