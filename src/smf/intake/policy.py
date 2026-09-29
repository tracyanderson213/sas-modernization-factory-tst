"""Trusted deployment policy loading for offline batch intake."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from smf.intake.schema import validate_policy
from smf.readiness.policy import digest_value
from smf.security.ai_admission import contains_protected_data


@dataclass(frozen=True)
class IntakePolicy:
    payload: dict[str, Any]
    policy_digest: str


def intake_policy_from_dict(raw: dict[str, Any]) -> IntakePolicy:
    validate_policy(raw)
    if contains_protected_data(json.dumps(raw, sort_keys=True)):
        raise ValueError("Batch intake policy contains protected or secret-bearing values")
    payload = json.loads(json.dumps(raw))
    return IntakePolicy(payload=payload, policy_digest=digest_value(payload))


def verify_intake_policy(policy: IntakePolicy) -> None:
    """Reject a policy whose mutable payload no longer matches its trusted digest."""
    validate_policy(policy.payload)
    if contains_protected_data(json.dumps(policy.payload, sort_keys=True)):
        raise ValueError("Batch intake policy contains protected or secret-bearing values")
    if digest_value(policy.payload) != policy.policy_digest:
        raise ValueError("Batch intake policy digest mismatch")


def load_intake_policy(path: Path) -> IntakePolicy:
    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError("Batch intake policy must be an object")
    return intake_policy_from_dict(raw)
