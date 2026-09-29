"""Strict loading and digesting of versioned readiness policies."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from smf.readiness.models import ReadinessClassification, ReadinessPolicy
from smf.readiness.schema import validate_policy_schema
from smf.strict_yaml import load_unique_yaml


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def serialize_readiness_policy(policy: ReadinessPolicy) -> dict[str, Any]:
    """Return the canonical, reconstructable policy payload used for its digest."""

    return {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "classification_precedence": [item.value for item in policy.classification_precedence],
        "supported_artifact_kinds": list(policy.supported_artifact_kinds),
        "unresolved_dependencies": {
            key: value.value for key, value in sorted(policy.unresolved_dependencies.items())
        },
        "required_environment_checks": list(policy.required_environment_checks),
        "required_runtime_checks": list(policy.required_runtime_checks),
        **(
            {
                "prerequisite_binding": dict(sorted(policy.prerequisite_binding.items())),
                "prerequisites": [dict(item) for item in policy.prerequisites],
            }
            if policy.prerequisite_binding is not None
            else {}
        ),
        "evidence_provenance": {
            kind: {
                "authorities": list(policy.evidence_authorities[kind]),
                "acquisition_sources": list(policy.evidence_acquisition_sources[kind]),
                "key_ids": list(policy.evidence_key_ids[kind]),
            }
            for kind in (
                "discovery_snapshot",
                "assessment",
                "dataset_mapping",
                "baseline",
                "environment",
                "runtime",
                "approval",
            )
        },
        "verification_keys": dict(sorted(policy.verification_keys.items())),
        "baseline": {
            "authorities": list(policy.required_baseline_authorities),
            "require_source_execution_id": policy.require_source_execution_id,
            "trusted_acquisition_policies": [
                {
                    "policy_digest": item["policy_digest"],
                    "producer_authorities": list(item["producer_authorities"]),
                    "producer_key_ids": list(item["producer_key_ids"]),
                    "approval_authorities": list(item["approval_authorities"]),
                    "approval_key_ids": list(item["approval_key_ids"]),
                }
                for item in policy.trusted_baseline_acquisition_policies
            ],
        },
        "mappings": {
            "require_inputs": policy.require_input_mappings,
            "require_outputs": policy.require_output_mappings,
        },
        "human_review": {
            "complexities": list(policy.human_review_complexities),
            "risk_factors": list(policy.human_review_risk_factors),
        },
        "max_evidence_age_seconds": policy.max_evidence_age_seconds,
        "owners": dict(sorted(policy.owners.items())),
        "next_actions": dict(sorted(policy.next_actions.items())),
    }


def readiness_policy_from_dict(raw: dict[str, Any]) -> ReadinessPolicy:
    """Reconstruct a policy from its canonical validated representation."""

    if not isinstance(raw, dict):
        raise ValueError("Readiness policy must be an object")
    validate_policy_schema(raw)
    prerequisites = raw.get("prerequisites", [])
    prerequisite_ids = [item["prerequisite_id"] for item in prerequisites]
    if len(prerequisite_ids) != len(set(prerequisite_ids)):
        raise ValueError("Readiness policy prerequisite IDs must be unique")
    baseline_policies = raw["baseline"]["trusted_acquisition_policies"]
    baseline_policy_digests = [item["policy_digest"] for item in baseline_policies]
    if len(baseline_policy_digests) != len(set(baseline_policy_digests)):
        raise ValueError("Trusted baseline acquisition policy digests must be unique")
    for item in baseline_policies:
        producer_keys = set(item["producer_key_ids"])
        approval_keys = set(item["approval_key_ids"])
        if producer_keys & approval_keys:
            raise ValueError("Trusted baseline producer and approval keys must be distinct")
        if not (producer_keys | approval_keys).issubset(raw["verification_keys"]):
            raise ValueError("Trusted baseline acquisition policy references an unknown key")
        if set(item["producer_authorities"]) & set(item["approval_authorities"]):
            raise ValueError("Trusted baseline producer and approval authorities must be distinct")
    policy = ReadinessPolicy(
        policy_id=str(raw["policy_id"]),
        policy_version=str(raw["policy_version"]),
        policy_digest="",
        classification_precedence=tuple(
            ReadinessClassification(item) for item in raw["classification_precedence"]
        ),
        supported_artifact_kinds=tuple(raw["supported_artifact_kinds"]),
        unresolved_dependencies={
            key: ReadinessClassification(value)
            for key, value in raw["unresolved_dependencies"].items()
        },
        required_environment_checks=tuple(raw["required_environment_checks"]),
        required_runtime_checks=tuple(raw["required_runtime_checks"]),
        prerequisite_binding=(
            dict(raw["prerequisite_binding"]) if "prerequisite_binding" in raw else None
        ),
        prerequisites=tuple(dict(item) for item in prerequisites),
        evidence_authorities={
            kind: tuple(raw["evidence_provenance"][kind]["authorities"])
            for kind in raw["evidence_provenance"]
        },
        evidence_acquisition_sources={
            kind: tuple(raw["evidence_provenance"][kind]["acquisition_sources"])
            for kind in raw["evidence_provenance"]
        },
        evidence_key_ids={
            kind: tuple(raw["evidence_provenance"][kind]["key_ids"])
            for kind in raw["evidence_provenance"]
        },
        verification_keys=dict(raw["verification_keys"]),
        required_baseline_authorities=tuple(raw["baseline"]["authorities"]),
        require_source_execution_id=bool(raw["baseline"]["require_source_execution_id"]),
        trusted_baseline_acquisition_policies=tuple(
            {
                "policy_digest": item["policy_digest"],
                "producer_authorities": tuple(item["producer_authorities"]),
                "producer_key_ids": tuple(item["producer_key_ids"]),
                "approval_authorities": tuple(item["approval_authorities"]),
                "approval_key_ids": tuple(item["approval_key_ids"]),
            }
            for item in raw["baseline"]["trusted_acquisition_policies"]
        ),
        require_input_mappings=bool(raw["mappings"]["require_inputs"]),
        require_output_mappings=bool(raw["mappings"]["require_outputs"]),
        human_review_complexities=tuple(raw["human_review"]["complexities"]),
        human_review_risk_factors=tuple(raw["human_review"]["risk_factors"]),
        max_evidence_age_seconds=raw.get("max_evidence_age_seconds"),
        owners=dict(raw["owners"]),
        next_actions=dict(raw["next_actions"]),
    )
    payload = serialize_readiness_policy(policy)
    return ReadinessPolicy(**{**policy.__dict__, "policy_digest": digest_value(payload)})


def load_readiness_policy(path: Path) -> ReadinessPolicy:
    raw = load_unique_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Readiness policy must be an object")
    return readiness_policy_from_dict(raw)
