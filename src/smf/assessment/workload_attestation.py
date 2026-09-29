"""Governed Ed25519 proof for workload-complexity results."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from smf.assessment.workload_policy import (
    WorkloadComplexityPolicy,
    workload_policy_digest,
)
from smf.assessment.workload_schema import validate_workload_complexity_result
from smf.readiness.policy import digest_value
from smf.workload.identity import stable_id


def workload_result_digest(payload: dict[str, Any]) -> str:
    unsigned = deepcopy(payload)
    unsigned.pop("result_digest", None)
    unsigned["proof"] = None
    return digest_value(unsigned)


def sign_workload_complexity_result(
    payload: dict[str, Any], *, authority: str, key_id: str, private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    signed = deepcopy(payload)
    expected = workload_result_digest(signed)
    if signed.get("result_digest") != expected:
        raise ValueError("Workload complexity result digest mismatch")
    signed["proof"] = {
        "algorithm": "ed25519",
        "authority": authority,
        "key_id": key_id,
        "value": base64.b64encode(private_key.sign(bytes.fromhex(expected))).decode("ascii"),
    }
    return signed


def verify_workload_complexity_attestation(
    payload: dict[str, Any],
    policy: WorkloadComplexityPolicy,
    *,
    verified_at: datetime | None = None,
) -> None:
    validate_workload_complexity_result(payload)
    if workload_policy_digest(policy.payload) != policy.policy_digest:
        raise ValueError("Workload complexity policy object is not canonical")
    if payload.get("result_digest") != workload_result_digest(payload):
        raise ValueError("Workload complexity result digest mismatch")
    if (
        payload.get("policy_id") != policy.payload["policy_id"]
        or payload.get("policy_version") != policy.payload["policy_version"]
        or payload.get("policy_digest") != policy.policy_digest
    ):
        raise ValueError("Workload complexity result attestation policy binding mismatch")
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("Workload complexity result is unsigned")
    if proof.get("authority") not in policy.payload["result_provenance"]["authorities"]:
        raise ValueError("Workload complexity result authority is not permitted")
    key_id = proof.get("key_id")
    if key_id not in policy.payload["result_provenance"]["key_ids"]:
        raise ValueError("Workload complexity result key is not permitted")
    try:
        public = base64.b64decode(policy.payload["verification_keys"][key_id], validate=True)
        signature = base64.b64decode(proof["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, bytes.fromhex(payload["result_digest"])
        )
    except (KeyError, ValueError, InvalidSignature) as exc:
        raise ValueError("Workload complexity result attestation is invalid") from exc
    _verify_result_semantics(payload, policy)
    instant = (verified_at or datetime.now(UTC)).astimezone(UTC)
    start = datetime.fromisoformat(policy.payload["valid_from"].replace("Z", "+00:00"))
    end = (
        datetime.fromisoformat(policy.payload["valid_until"].replace("Z", "+00:00"))
        if policy.payload["valid_until"]
        else None
    )
    if policy.payload["status"] != "active":
        raise ValueError(f"assessment_policy_{policy.payload['status']}")
    if instant < start:
        raise ValueError("assessment_policy_pending")
    if end is not None and instant > end:
        raise ValueError("assessment_policy_expired")


def _verify_result_semantics(payload: dict[str, Any], policy: WorkloadComplexityPolicy) -> None:
    """Reconstruct policy-derived fields instead of trusting signed projections."""

    if payload["client_id"] not in policy.payload["allowed_clients"]:
        raise ValueError("Workload complexity result semantic mismatch")
    if (
        payload["strategy_id"] != policy.payload["strategy"]["strategy_id"]
        or payload["strategy_version"] != policy.payload["strategy"]["strategy_version"]
    ):
        raise ValueError("Workload complexity result semantic mismatch")
    if (
        payload["macro_strategy_digest"] is not None
        and payload["macro_strategy_digest"]
        not in policy.payload["authoritative_versions"]["macro_strategy_digests"]
    ):
        raise ValueError("Workload complexity result semantic mismatch")

    definitions = {item["dimension_id"]: item for item in policy.payload["dimensions"]}
    dimensions = {item["dimension_id"]: item for item in payload["dimensions"]}
    if len(dimensions) != len(payload["dimensions"]) or set(dimensions) != set(definitions):
        raise ValueError("Workload complexity result semantic mismatch")
    feature_to_dimension = {
        feature["feature_id"]: dimension_id
        for dimension_id, definition in definitions.items()
        for feature in definition["features"]
    }
    observation_ids: set[str] = set()
    canonical_ids: set[str] = set()
    observations_by_feature: dict[str, list[dict[str, Any]]] = {
        feature_id: [] for feature_id in feature_to_dimension
    }
    for observation in payload["observations"]:
        canonical = digest_value(
            {
                key: observation[key]
                for key in (
                    "dimension_id",
                    "feature_id",
                    "subject_id",
                    "evidence_id",
                    "origin_digest",
                    "method",
                )
            }
        )
        feature_id = observation["feature_id"]
        if (
            feature_id not in feature_to_dimension
            or observation["dimension_id"] != feature_to_dimension[feature_id]
            or observation["method"] not in policy.payload["permitted_evidence_methods"]
            or observation["canonical_identity"] != canonical
            or observation["observation_id"] != stable_id("OBS", canonical)
            or observation["observation_id"] in observation_ids
            or canonical in canonical_ids
        ):
            raise ValueError("Workload complexity result semantic mismatch")
        observation_ids.add(observation["observation_id"])
        canonical_ids.add(canonical)
        observations_by_feature[feature_id].append(observation)

    score = 0
    unknowns: list[str] = []
    tier_blocking: list[str] = []
    for dimension_id, definition in definitions.items():
        result = dimensions[dimension_id]
        expected_features: list[dict[str, Any]] = []
        raw_contribution = 0
        for feature in sorted(definition["features"], key=lambda item: item["feature_id"]):
            matched = sorted(
                observations_by_feature[feature["feature_id"]],
                key=lambda item: item["canonical_identity"],
            )
            counted = min(len(matched), feature["max_count"])
            contribution = counted * feature["weight"]
            raw_contribution += contribution
            expected_features.append(
                {
                    "feature_id": feature["feature_id"],
                    "observed_count": len(matched),
                    "counted_count": counted,
                    "weight": feature["weight"],
                    "contribution": contribution,
                    "observation_ids": [item["observation_id"] for item in matched],
                }
            )
        contribution = min(raw_contribution, definition["cap"])
        expected = {
            "dimension_id": dimension_id,
            "status": result["status"],
            "required": definition["required"],
            "tier_critical": definition["tier_critical"],
            "raw_contribution": raw_contribution,
            "contribution": contribution,
            "cap": definition["cap"],
            "cap_applied": contribution != raw_contribution,
            "features": expected_features,
        }
        if result != expected:
            raise ValueError("Workload complexity result semantic mismatch")
        score += contribution
        if result["status"] != "observed":
            unknowns.append(dimension_id)
            if result["tier_critical"]:
                tier_blocking.append(dimension_id)

    evaluated = datetime.fromisoformat(payload["evaluated_at"].replace("Z", "+00:00"))
    start = datetime.fromisoformat(policy.payload["valid_from"].replace("Z", "+00:00"))
    end = (
        datetime.fromisoformat(policy.payload["valid_until"].replace("Z", "+00:00"))
        if policy.payload["valid_until"]
        else None
    )
    historical_state = None
    if policy.payload["status"] != "active":
        historical_state = policy.payload["status"]
    elif evaluated < start:
        historical_state = "pending"
    elif end is not None and evaluated > end:
        historical_state = "expired"
    expected_blockers = sorted(
        [
            f"required_dimension_{dimensions[item]['status']}:{item}"
            for item in definitions
            if dimensions[item]["required"] and dimensions[item]["status"] != "observed"
        ]
        + ([f"policy_{historical_state}"] if historical_state else [])
    )
    expected_tier = "unknown"
    if not tier_blocking and historical_state is None:
        expected_tier = max(
            (item["tier"] for item in policy.payload["thresholds"] if score >= item["min_score"]),
            key=["simple", "moderate", "complex", "highly_complex"].index,
        )
    maximum = score + sum(
        dimensions[item]["cap"] - dimensions[item]["contribution"] for item in unknowns
    )
    expected_sensitivity = {
        "current_score": score,
        "minimum_score": score,
        "maximum_score": maximum,
        "unknown_dimensions": sorted(unknowns),
        "threshold_distance": {
            item["tier"]: item["min_score"] - score for item in policy.payload["thresholds"]
        },
    }
    if (
        payload["score"] != score
        or payload["tier"] != expected_tier
        or payload["unknowns"] != sorted(unknowns)
        or payload["blockers"] != expected_blockers
        or payload["sensitivity"] != expected_sensitivity
        or payload["confidence_basis"]
        != (
            "incomplete_tier_critical_dimensions"
            if tier_blocking
            else "complete_tier_critical_dimensions"
        )
    ):
        raise ValueError("Workload complexity result semantic mismatch")
