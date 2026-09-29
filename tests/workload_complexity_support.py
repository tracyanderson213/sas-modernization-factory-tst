from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.assessment import (
    WorkloadComplexityRequest,
    assess_workload_complexity,
    sign_workload_complexity_result,
    workload_policy_digest,
    workload_policy_from_dict,
)

COMPLEXITY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
COMPLEXITY_PUBLIC = base64.b64encode(
    COMPLEXITY_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
).decode("ascii")
MACRO_STRATEGY_DIGEST = "b" * 64


def complexity_policy(client_id: str = "test-client") -> dict[str, Any]:
    feature_sets = {
        "static_constructs": [("sas_program", 1, 100)],
        "macro_behavior": [
            ("macro_observation", 1, 100),
            ("macro_dynamic", 20, 100),
        ],
        "dependency_topology": [("dependency_edge", 1, 100)],
        "data_access": [("dataset", 2, 100), ("data_relationship", 1, 100)],
        "source_scale": [("eligible_artifact", 1, 100), ("meaningful_entry_point", 1, 1)],
        "validation_difficulty": [("macro_blocker", 10, 100)],
    }
    raw: dict[str, Any] = {
        "schema_version": "1.0",
        "policy_id": "POL-pilot-complexity",
        "policy_version": "1.0.0",
        "policy_digest": "0" * 64,
        "status": "active",
        "valid_from": "2020-01-01T00:00:00+00:00",
        "valid_until": "2099-01-01T00:00:00+00:00",
        "allowed_clients": [client_id],
        "strategy": {"strategy_id": "workload-complexity", "strategy_version": "1.0.0"},
        "dimensions": [
            {
                "dimension_id": dimension,
                "required": True,
                "tier_critical": True,
                "cap": sum(weight * count for _, weight, count in features),
                "features": [
                    {"feature_id": name, "weight": weight, "max_count": count}
                    for name, weight, count in features
                ],
            }
            for dimension, features in feature_sets.items()
        ],
        "thresholds": [
            {"tier": "simple", "min_score": 0},
            {"tier": "moderate", "min_score": 8},
            {"tier": "complex", "min_score": 15},
            {"tier": "highly_complex", "min_score": 50},
        ],
        "unknown_handling": "block_tier",
        "permitted_evidence_methods": ["filesystem", "static_analysis"],
        "authoritative_versions": {
            "discovery_providers": ["filesystem"],
            "macro_strategy_digests": [MACRO_STRATEGY_DIGEST],
        },
        "deduplication": "canonical_observation_identity",
        "aggregation": "capped_sum",
        "owner_roles": {
            "policy_approval": "policy-owner",
            "missing_evidence": "source-owner",
            "classification_exception": "pilot-owner",
        },
        "result_provenance": {
            "authorities": ["assessment-service"],
            "key_ids": ["complexity-key"],
        },
        "verification_keys": {"complexity-key": COMPLEXITY_PUBLIC},
        "authorizes_readiness": False,
        "authorizes_execution": False,
        "authorizes_parity": False,
        "authorizes_certification": False,
    }
    raw["policy_digest"] = workload_policy_digest(raw)
    return raw


def attach_governed_assessments(
    root: Path,
    discovery: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    client_id: str = "test-client",
    run_id: str = "run-1",
    attempt_id: str = "attempt-1",
) -> str:
    policy_raw = complexity_policy(client_id)
    policy_path = root / "assessments/complexity-policy.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(json.dumps(policy_raw, sort_keys=True), encoding="utf-8")
    policy = workload_policy_from_dict(policy_raw)
    for candidate in candidates:
        result = assess_workload_complexity(
            WorkloadComplexityRequest(
                client_id=client_id,
                workload_id=candidate["workload_id"],
                boundary_id=candidate["boundary_id"],
                run_id=run_id,
                attempt_id=attempt_id,
                execution_id=f"exec-{candidate['workload_id']}",
                discovery_snapshot=discovery,
                source_closure=tuple(candidate["source_closure"]),
                source_root=root,
            ),
            policy,
            evaluated_at=datetime(2026, 9, 15, tzinfo=UTC),
        )
        result = sign_workload_complexity_result(
            result,
            authority="assessment-service",
            key_id="complexity-key",
            private_key=COMPLEXITY_KEY,
        )
        suffix = candidate["workload_id"].removeprefix("WL-")
        uri = f"assessments/{suffix}.json"
        path = root / uri
        path.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        candidate["assessment"] = {
            "assessment_id": result["assessment_id"],
            "strategy_id": result["strategy_id"],
            "strategy_version": result["strategy_version"],
            "uri": uri,
            "digest": hashlib.sha256(path.read_bytes()).hexdigest(),
            "result_digest": result["result_digest"],
            "policy_uri": "assessments/complexity-policy.json",
            "policy_digest": policy.policy_digest,
        }
        candidate["complexity"] = result["tier"]
        candidate["complexity_score"] = result["score"]
        candidate.update(result["projections"])
    return policy.policy_digest
