"""Versioned fail-closed workload-complexity policy loading."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from smf.assessment.workload_schema import validate_workload_complexity_policy
from smf.readiness.policy import digest_value
from smf.security.ai_admission import contains_protected_data
from smf.workload.sanitization import sanitize_discovery_value


@dataclass(frozen=True)
class WorkloadComplexityPolicy:
    payload: dict[str, Any]
    policy_digest: str


class _UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: _UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate workload complexity policy key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def workload_policy_digest(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("policy_digest", None)
    return digest_value(unsigned)


def workload_policy_from_dict(raw: dict[str, Any]) -> WorkloadComplexityPolicy:
    validate_workload_complexity_policy(raw)
    if sanitize_discovery_value(raw) != raw or contains_protected_data(
        yaml.safe_dump(raw, sort_keys=True)
    ):
        raise ValueError("Workload complexity policy contains protected or secret-bearing values")
    expected = workload_policy_digest(raw)
    if raw["policy_digest"] != expected:
        raise ValueError("Workload complexity policy digest mismatch")
    dimensions = raw["dimensions"]
    dimension_ids = [item["dimension_id"] for item in dimensions]
    if len(dimension_ids) != len(set(dimension_ids)):
        raise ValueError("Workload complexity policy dimension IDs must be unique")
    feature_ids = [feature["feature_id"] for item in dimensions for feature in item["features"]]
    if len(feature_ids) != len(set(feature_ids)):
        raise ValueError("Workload complexity policy feature IDs must be globally unique")
    for item in dimensions:
        if (
            sum(feature["weight"] * feature["max_count"] for feature in item["features"])
            < item["cap"]
        ):
            raise ValueError("Dimension cap exceeds its observable feature maximum")
    thresholds = raw["thresholds"]
    if [item["tier"] for item in thresholds] != [
        "simple",
        "moderate",
        "complex",
        "highly_complex",
    ] or thresholds[0]["min_score"] != 0:
        raise ValueError("Workload complexity thresholds must define ordered canonical tiers")
    scores = [item["min_score"] for item in thresholds]
    if scores != sorted(set(scores)):
        raise ValueError("Workload complexity thresholds must be strictly increasing")
    for field in ("valid_from", "valid_until"):
        if raw[field] is None:
            continue
        try:
            instant = datetime.fromisoformat(str(raw[field]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Workload complexity policy {field} is invalid") from exc
        if instant.tzinfo is None:
            raise ValueError(f"Workload complexity policy {field} must be timezone-aware")
    return WorkloadComplexityPolicy(payload=dict(raw), policy_digest=expected)


def load_workload_complexity_policy(path: Path) -> WorkloadComplexityPolicy:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid workload complexity policy YAML") from exc
    if not isinstance(raw, dict):
        raise ValueError("Workload complexity policy must be an object")
    return workload_policy_from_dict(raw)
