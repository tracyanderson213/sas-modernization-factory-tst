"""Trusted acquisition-policy loading and integrity verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from smf.baseline.schema import validate_policy
from smf.readiness.policy import digest_value
from smf.security.ai_admission import contains_protected_data


@dataclass(frozen=True)
class BaselineAcquisitionPolicy:
    payload: dict[str, Any]
    policy_digest: str


def baseline_policy_from_dict(raw: dict[str, Any]) -> BaselineAcquisitionPolicy:
    validate_policy(raw)
    if contains_protected_data(json.dumps(raw, sort_keys=True)):
        raise ValueError("Baseline acquisition policy contains protected or secret-bearing values")
    producer = raw["producer_provenance"]
    approval = raw["approval_provenance"]
    if set(producer["authorities"]) & set(approval["authorities"]):
        raise ValueError("Baseline producer and approval authorities must be distinct")
    if set(producer["key_ids"]) & set(approval["key_ids"]):
        raise ValueError("Baseline producer and approval key identities must be distinct")
    keys = raw["verification_keys"]
    required_key_ids = set(producer["key_ids"]) | set(approval["key_ids"])
    if not required_key_ids.issubset(keys):
        raise ValueError("Baseline acquisition policy is missing a verification key")
    if len({keys[key_id] for key_id in required_key_ids}) != len(required_key_ids):
        raise ValueError("Baseline producer and approval public keys must be distinct")
    payload = json.loads(json.dumps(raw))
    return BaselineAcquisitionPolicy(payload, digest_value(payload))


def verify_baseline_policy(policy: BaselineAcquisitionPolicy) -> None:
    validate_policy(policy.payload)
    if digest_value(policy.payload) != policy.policy_digest:
        raise ValueError("Baseline acquisition policy digest mismatch")
    if contains_protected_data(json.dumps(policy.payload, sort_keys=True)):
        raise ValueError("Baseline acquisition policy contains protected or secret-bearing values")


def load_baseline_policy(path: Path) -> BaselineAcquisitionPolicy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Baseline acquisition policy must be an object")
    return baseline_policy_from_dict(raw)
