"""Load and bind explicit, versioned pilot-selection policy."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from smf.pilot.models import PilotSelectionPolicy
from smf.pilot.schema import validate_policy
from smf.readiness.policy import digest_value


class _UniquePolicyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniquePolicyLoader, node: yaml.Node, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate pilot selection policy key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniquePolicyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def policy_digest(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("policy_digest", None)
    return digest_value(unsigned)


def pilot_policy_from_dict(raw: dict[str, Any]) -> PilotSelectionPolicy:
    validate_policy(raw)
    expected = policy_digest(raw)
    if raw["policy_digest"] != expected:
        raise ValueError("Pilot selection policy digest mismatch")
    criterion_ids = [item["criterion_id"] for item in raw["criteria"]]
    if len(criterion_ids) != len(set(criterion_ids)):
        raise ValueError("Pilot selection policy criterion IDs must be unique")
    for field in ("valid_from", "valid_until"):
        if raw[field] is None:
            continue
        try:
            instant = datetime.fromisoformat(str(raw[field]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Pilot selection policy {field} is invalid") from exc
        if instant.tzinfo is None:
            raise ValueError(f"Pilot selection policy {field} must be timezone-aware")
    valid_from = datetime.fromisoformat(str(raw["valid_from"]).replace("Z", "+00:00"))
    valid_until = (
        datetime.fromisoformat(str(raw["valid_until"]).replace("Z", "+00:00"))
        if raw["valid_until"] is not None
        else None
    )
    if valid_until is not None and valid_until <= valid_from:
        raise ValueError("Pilot selection policy validity interval is invalid")
    return PilotSelectionPolicy(payload=raw, policy_digest=expected)


def load_pilot_policy(path: Path) -> PilotSelectionPolicy:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniquePolicyLoader)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid pilot selection policy YAML") from exc
    if not isinstance(raw, dict):
        raise ValueError("Pilot selection policy must be an object")
    return pilot_policy_from_dict(raw)
