"""Deterministic estate distribution over immutable workload complexity results."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from smf.assessment.workload_attestation import verify_workload_complexity_attestation
from smf.assessment.workload_manifest import reverify_workload_complexity_sources
from smf.assessment.workload_policy import WorkloadComplexityPolicy
from smf.assessment.workload_schema import validate_workload_complexity_result
from smf.readiness.policy import digest_value


def summarize_workload_complexity(
    results: Iterable[dict[str, Any]],
    *,
    policies: Iterable[WorkloadComplexityPolicy],
    source_root: Path,
    verified_at: datetime | None = None,
    partition_mixed_policies: bool = False,
) -> dict[str, Any]:
    items = list(results)
    for item in items:
        validate_workload_complexity_result(item)
    policies_by_digest: dict[str, WorkloadComplexityPolicy] = {}
    for policy in policies:
        if policy.policy_digest in policies_by_digest:
            raise ValueError("Duplicate workload complexity policy digest")
        policies_by_digest[policy.policy_digest] = policy
    identities: set[tuple[str, str]] = set()
    script_ids: set[str] = set()
    result_policy_digests = {item["policy_digest"] for item in items}
    if len(result_policy_digests) > 1 and not partition_mixed_policies:
        raise ValueError("Mixed workload complexity policies require explicit partitioning")
    for item in items:
        trusted_policy = policies_by_digest.get(item["policy_digest"])
        if trusted_policy is None:
            raise ValueError("Workload complexity report policy is not trusted")
        verify_workload_complexity_attestation(item, trusted_policy, verified_at=verified_at)
        reverify_workload_complexity_sources(item, source_root)
        identity = (item["workload_id"], item["boundary_id"])
        if identity in identities:
            raise ValueError("Duplicate workload complexity subject identity")
        identities.add(identity)
        artifact_ids = [artifact["artifact_id"] for artifact in item["artifacts"]]
        overlap = script_ids.intersection(artifact_ids)
        if overlap:
            raise ValueError("Duplicate canonical script identity across workload results")
        script_ids.update(artifact_ids)
    partitions: dict[str, Any] = {}
    for policy_digest in sorted(result_policy_digests):
        selected = [item for item in items if item["policy_digest"] == policy_digest]
        tier_counts = Counter(item["tier"] for item in selected)
        state_counts = Counter(
            "blocked"
            if item["blockers"]
            else "unknown"
            if item["tier"] == "unknown"
            else "classified"
            for item in selected
        )
        partitions[policy_digest] = {
            "workload_count": len(selected),
            "script_count": len(
                {artifact["artifact_id"] for item in selected for artifact in item["artifacts"]}
            ),
            "tier_distribution": dict(sorted(tier_counts.items())),
            "state_distribution": dict(sorted(state_counts.items())),
            "unknown_subjects": sorted(
                item["workload_id"] for item in selected if item["tier"] == "unknown"
            ),
        }
    report = {
        "schema_version": "1.0",
        "unique_workload_count": len(identities),
        "unique_script_count": len(script_ids),
        "partitions": partitions,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
    }
    report["report_digest"] = digest_value(report)
    return report
