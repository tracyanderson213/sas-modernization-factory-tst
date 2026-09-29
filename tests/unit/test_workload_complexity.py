from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.assessment import (
    WorkloadComplexityRequest,
    assess_workload_complexity,
    load_workload_complexity_policy,
    load_workload_complexity_result,
    sign_workload_complexity_result,
    summarize_workload_complexity,
    verify_workload_complexity_attestation,
    workload_policy_digest,
    workload_policy_from_dict,
    write_workload_complexity_result,
)

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC = base64.b64encode(
    KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
).decode("ascii")
MACRO_DIGEST = "a" * 64


def _policy(*, status: str = "active") -> dict:
    dimensions = {
        "static_constructs": [("sas_program", 1, 10), ("sas_macro_artifact", 2, 10)],
        "macro_behavior": [
            ("macro_observation", 1, 10),
            ("macro_dynamic", 8, 10),
            ("macro_unresolved", 6, 10),
        ],
        "dependency_topology": [
            ("dependency_edge", 2, 10),
            ("unresolved_dependency", 6, 10),
            ("external_dependency", 5, 10),
        ],
        "data_access": [("dataset", 2, 10), ("data_relationship", 2, 10)],
        "source_scale": [("eligible_artifact", 1, 10), ("meaningful_entry_point", 1, 1)],
        "validation_difficulty": [("macro_blocker", 7, 10)],
    }
    raw = {
        "schema_version": "1.0",
        "policy_id": "POL-test-complexity",
        "policy_version": "1.0.0",
        "policy_digest": "0" * 64,
        "status": status,
        "valid_from": "2020-01-01T00:00:00+00:00",
        "valid_until": "2099-01-01T00:00:00+00:00",
        "allowed_clients": ["test-client"],
        "strategy": {"strategy_id": "workload-complexity", "strategy_version": "1.0.0"},
        "dimensions": [
            {
                "dimension_id": dimension,
                "required": True,
                "tier_critical": True,
                "cap": sum(weight * count for _, weight, count in features),
                "features": [
                    {"feature_id": feature, "weight": weight, "max_count": count}
                    for feature, weight, count in features
                ],
            }
            for dimension, features in dimensions.items()
        ],
        "thresholds": [
            {"tier": "simple", "min_score": 0},
            {"tier": "moderate", "min_score": 6},
            {"tier": "complex", "min_score": 14},
            {"tier": "highly_complex", "min_score": 30},
        ],
        "unknown_handling": "block_tier",
        "permitted_evidence_methods": ["filesystem", "static_analysis"],
        "authoritative_versions": {
            "discovery_providers": ["filesystem"],
            "macro_strategy_digests": [MACRO_DIGEST],
        },
        "deduplication": "canonical_observation_identity",
        "aggregation": "capped_sum",
        "owner_roles": {
            "policy_approval": "policy-owner",
            "missing_evidence": "source-owner",
            "classification_exception": "architect",
        },
        "result_provenance": {
            "authorities": ["assessment-service"],
            "key_ids": ["assessment-key"],
        },
        "verification_keys": {"assessment-key": PUBLIC},
        "authorizes_readiness": False,
        "authorizes_execution": False,
        "authorizes_parity": False,
        "authorizes_certification": False,
    }
    raw["policy_digest"] = workload_policy_digest(raw)
    return raw


def _case(root: Path, *, macro: bool = True, dynamic: bool = False):
    source = root / "sources/main.sas"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("data output; set input; run;\n", encoding="utf-8")
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    artifact = {
        "artifact_id": "ART-main",
        "logical_path": "sas/main.sas",
        "source_uri": "sources/main.sas",
        "sha256": sha,
        "size_bytes": source.stat().st_size,
    }
    workload = {
        "workload_id": "WL-1",
        "artifacts": [
            {
                "artifact_id": "ART-main",
                "kind": "sas_program",
                "logical_path": "sas/main.sas",
                "checksum": sha,
            }
        ],
        "datasets": [],
        "relationships": [],
        "external_dependencies": [],
        "boundaries": [
            {
                "boundary_id": "WB-1",
                "artifact_ids": ["ART-main"],
                "metadata": {"entry_point_artifact_id": "ART-main"},
            }
        ],
        "dependency_graph": {
            "graph_id": "GRAPH-1",
            "nodes": [{"node_id": "NODE-main", "kind": "artifact", "entity_id": "ART-main"}],
            "edges": [],
            "unresolved": [],
        },
    }
    if macro:
        workload["macro_analysis"] = {
            "analysis_id": "MAN-1",
            "strategy_digest": MACRO_DIGEST,
            "complete": True,
            "source_inventory": [{"source_artifact_id": "ART-main", "source_checksum": sha}],
            "observations": (
                [
                    {
                        "observation_id": "MOBS-1",
                        "kind": "dynamic_invocation" if dynamic else "literal_invocation",
                        "normalized_identity": "macro-one",
                        "location": {
                            "source_artifact_id": "ART-main",
                            "source_checksum": sha,
                            "byte_start": 0,
                            "byte_end": 4,
                            "line": 1,
                            "column": 1,
                            "span_digest": hashlib.sha256(b"data").hexdigest(),
                        },
                    }
                ]
                if dynamic
                else []
            ),
            "resolutions": [],
            "blockers": [],
        }
    discovery = {"provider": "filesystem", "workloads": [workload]}
    request = WorkloadComplexityRequest(
        client_id="test-client",
        workload_id="WL-1",
        boundary_id="WB-1",
        run_id="run-1",
        attempt_id="attempt-1",
        execution_id="exec-1",
        discovery_snapshot=discovery,
        source_closure=(artifact,),
        source_root=root,
    )
    return request, discovery, workload


def _assess(root: Path, *, macro: bool = True, dynamic: bool = False):
    request, _, _ = _case(root, macro=macro, dynamic=dynamic)
    return assess_workload_complexity(
        request,
        workload_policy_from_dict(_policy()),
        evaluated_at=datetime(2026, 9, 16, tzinfo=UTC),
    )


def test_known_vector_is_deterministic_explainable_and_non_authorizing(tmp_path: Path) -> None:
    first = _assess(tmp_path, dynamic=True)
    second = _assess(tmp_path, dynamic=True)
    assert first == second
    assert first["tier"] == "moderate"
    assert first["score"] == 12
    assert first["dimensions"]
    assert first["observations"]
    assert first["sensitivity"]["current_score"] == first["score"]
    assert not any(
        first[field]
        for field in (
            "authorizes_readiness",
            "authorizes_execution",
            "authorizes_parity",
            "authorizes_certification",
        )
    )


def test_required_unknown_never_defaults_to_simple(tmp_path: Path) -> None:
    result = _assess(tmp_path, macro=False)
    assert result["tier"] == "unknown"
    assert "macro_behavior" in result["unknowns"]
    assert "validation_difficulty" in result["unknowns"]
    assert result["sensitivity"]["maximum_score"] > result["score"]
    assert "required_dimension_unknown:macro_behavior" in result["blockers"]


def test_stale_macro_inventory_cannot_classify_revised_source(tmp_path: Path) -> None:
    request, discovery, workload = _case(tmp_path, dynamic=True)
    revised = b"data revised; set input; run;\n"
    source = tmp_path / "sources/main.sas"
    source.write_bytes(revised)
    revised_sha = hashlib.sha256(revised).hexdigest()
    workload["artifacts"][0]["checksum"] = revised_sha
    closure = dict(request.source_closure[0], sha256=revised_sha, size_bytes=len(revised))
    revised_request = WorkloadComplexityRequest(
        **{
            **request.__dict__,
            "discovery_snapshot": discovery,
            "source_closure": (closure,),
        }
    )

    with pytest.raises(ValueError, match="Macro analysis source binding mismatch"):
        assess_workload_complexity(
            revised_request,
            workload_policy_from_dict(_policy()),
            evaluated_at=datetime(2026, 9, 16, tzinfo=UTC),
        )


@pytest.mark.parametrize("status", ["pending", "denied", "expired"])
def test_non_active_policy_states_remain_distinct(tmp_path: Path, status: str) -> None:
    request, _, _ = _case(tmp_path)
    result = assess_workload_complexity(
        request,
        workload_policy_from_dict(_policy(status=status)),
        evaluated_at=datetime(2026, 9, 16, tzinfo=UTC),
    )
    assert result["tier"] == "unknown"
    assert f"policy_{status}" in result["blockers"]


def test_duplicate_and_unsupported_identities_fail_without_score_inflation(tmp_path: Path) -> None:
    request, discovery, _ = _case(tmp_path, dynamic=True)
    duplicated = deepcopy(discovery["workloads"][0]["macro_analysis"]["observations"][0])
    discovery["workloads"][0]["macro_analysis"]["observations"].append(duplicated)
    request = WorkloadComplexityRequest(**{**request.__dict__, "discovery_snapshot": discovery})
    with pytest.raises(ValueError, match="Duplicate or malformed macro observation"):
        assess_workload_complexity(request, workload_policy_from_dict(_policy()))

    malformed = _policy()
    malformed["dimensions"][0]["features"][0]["feature_id"] = "caller_passed"
    malformed["policy_digest"] = workload_policy_digest(malformed)
    with pytest.raises(ValueError, match="unsupported feature"):
        assess_workload_complexity(request, workload_policy_from_dict(malformed))


def test_empty_mutated_and_boundary_escape_inputs_fail_closed(tmp_path: Path) -> None:
    request, discovery, _ = _case(tmp_path)
    (tmp_path / "sources/main.sas").write_text("/* no entry point */\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bytes changed"):
        assess_workload_complexity(request, workload_policy_from_dict(_policy()))

    request, discovery, _ = _case(tmp_path / "second")
    discovery["workloads"][0]["boundaries"][0]["artifact_ids"] = []
    request = WorkloadComplexityRequest(**{**request.__dict__, "discovery_snapshot": discovery})
    with pytest.raises(ValueError, match="empty or ambiguous"):
        assess_workload_complexity(request, workload_policy_from_dict(_policy()))

    request, _, _ = _case(tmp_path / "third")
    escaped = dict(request.source_closure[0], source_uri="../main.sas")
    request = WorkloadComplexityRequest(**{**request.__dict__, "source_closure": (escaped,)})
    with pytest.raises(ValueError, match="Unsafe source"):
        assess_workload_complexity(request, workload_policy_from_dict(_policy()))

    request, _, _ = _case(tmp_path / "identity")
    unsafe_identity = WorkloadComplexityRequest(
        **{**request.__dict__, "client_id": "SSN-123-45-6789"}
    )
    with pytest.raises(ValueError, match="Unsafe client_id") as failure:
        assess_workload_complexity(unsafe_identity, workload_policy_from_dict(_policy()))
    assert "123-45-6789" not in str(failure.value)


def test_weight_sensitivity_and_advisory_recall_isolation(tmp_path: Path) -> None:
    request, discovery, _ = _case(tmp_path, dynamic=True)
    policy_raw = _policy()
    baseline = assess_workload_complexity(
        request,
        workload_policy_from_dict(policy_raw),
        evaluated_at=datetime(2026, 9, 16, tzinfo=UTC),
    )
    changed = deepcopy(policy_raw)
    changed["dimensions"][1]["features"][1]["weight"] += 3
    changed["policy_digest"] = workload_policy_digest(changed)
    weighted = assess_workload_complexity(
        request,
        workload_policy_from_dict(changed),
        evaluated_at=datetime(2026, 9, 16, tzinfo=UTC),
    )
    assert weighted["score"] == baseline["score"] + 3
    assert weighted["result_digest"] != baseline["result_digest"]

    discovery["advisory_recall"] = {"suggested_tier": "highly_complex", "passed": True}
    recalled_request = WorkloadComplexityRequest(
        **{**request.__dict__, "discovery_snapshot": discovery}
    )
    recalled = assess_workload_complexity(
        recalled_request,
        workload_policy_from_dict(policy_raw),
        evaluated_at=datetime(2026, 9, 16, tzinfo=UTC),
    )
    assert recalled["score"] == baseline["score"]
    assert recalled["tier"] == baseline["tier"]
    assert recalled["discovery_digest"] != baseline["discovery_digest"]


def test_governed_attestation_and_policy_binding_reject_self_assertion(tmp_path: Path) -> None:
    result = _assess(tmp_path)
    policy = workload_policy_from_dict(_policy())
    with pytest.raises(ValueError, match="unsigned"):
        verify_workload_complexity_attestation(result, policy)
    forged = deepcopy(result)
    forged["tier"] = "complex"
    with pytest.raises(ValueError, match="digest mismatch"):
        sign_workload_complexity_result(
            forged, authority="assessment-service", key_id="assessment-key", private_key=KEY
        )
    signed = sign_workload_complexity_result(
        result, authority="assessment-service", key_id="assessment-key", private_key=KEY
    )
    verify_workload_complexity_attestation(signed, policy)
    changed_policy = _policy()
    changed_policy["thresholds"][1]["min_score"] += 1
    changed_policy["policy_digest"] = workload_policy_digest(changed_policy)
    with pytest.raises(ValueError, match="attestation"):
        verify_workload_complexity_attestation(signed, workload_policy_from_dict(changed_policy))


def test_governed_attestation_rejects_policy_after_expiry(tmp_path: Path) -> None:
    raw_policy = _policy()
    raw_policy["valid_until"] = "2025-01-01T00:00:00+00:00"
    raw_policy["policy_digest"] = workload_policy_digest(raw_policy)
    policy = workload_policy_from_dict(raw_policy)
    request, _, _ = _case(tmp_path)
    result = assess_workload_complexity(
        request, policy, evaluated_at=datetime(2024, 1, 1, tzinfo=UTC)
    )
    signed = sign_workload_complexity_result(
        result, authority="assessment-service", key_id="assessment-key", private_key=KEY
    )

    with pytest.raises(ValueError, match="assessment_policy_expired"):
        verify_workload_complexity_attestation(
            signed, policy, verified_at=datetime(2026, 9, 16, tzinfo=UTC)
        )


def test_append_only_retry_recovers_derived_output_without_changing_decision(
    tmp_path: Path,
) -> None:
    result = _assess(tmp_path / "source")
    path = write_workload_complexity_result(
        tmp_path / "out", result, source_root=tmp_path / "source"
    )
    digest = load_workload_complexity_result(path)["result_digest"]
    path.with_name("explanation.json").unlink()
    assert (
        write_workload_complexity_result(tmp_path / "out", result, source_root=tmp_path / "source")
        == path
    )
    assert path.with_name("explanation.json").is_file()
    assert load_workload_complexity_result(path)["result_digest"] == digest
    conflict = deepcopy(result)
    conflict["warnings"] = ["changed"]
    from smf.assessment import workload_result_digest

    conflict["result_digest"] = workload_result_digest(conflict)
    with pytest.raises(FileExistsError, match="decision already exists"):
        write_workload_complexity_result(
            tmp_path / "out", conflict, source_root=tmp_path / "source"
        )


def test_publication_reverifies_qualified_bytes(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    result = _assess(source_root)
    (source_root / "sources/main.sas").write_text("data changed; run;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source bytes changed"):
        write_workload_complexity_result(tmp_path / "out", result, source_root=source_root)
    assert not (tmp_path / "out").exists()


def test_estate_report_counts_unique_subjects_and_rejects_mixed_policy(tmp_path: Path) -> None:
    result = _assess(tmp_path)
    policy = workload_policy_from_dict(_policy())
    signed = sign_workload_complexity_result(
        result, authority="assessment-service", key_id="assessment-key", private_key=KEY
    )
    report = summarize_workload_complexity(
        [signed],
        policies=[policy],
        source_root=tmp_path,
        verified_at=datetime(2026, 9, 16, tzinfo=UTC),
    )
    assert report["unique_workload_count"] == 1
    assert report["unique_script_count"] == 1
    assert not report["executed"]
    with pytest.raises(ValueError, match="Duplicate workload"):
        summarize_workload_complexity(
            [signed, signed],
            policies=[policy],
            source_root=tmp_path,
            verified_at=datetime(2026, 9, 16, tzinfo=UTC),
        )
    other = deepcopy(signed)
    other["workload_id"] = "WL-2"
    other["boundary_id"] = "WB-2"
    other["artifacts"] = [dict(other["artifacts"][0], artifact_id="ART-2")]
    other["policy_digest"] = "f" * 64
    with pytest.raises(ValueError, match="Mixed"):
        summarize_workload_complexity(
            [signed, other],
            policies=[policy],
            source_root=tmp_path,
            verified_at=datetime(2026, 9, 16, tzinfo=UTC),
        )


def test_estate_report_rejects_self_authored_and_fabricated_results(tmp_path: Path) -> None:
    policy = workload_policy_from_dict(_policy())
    fabricated = {
        "workload_id": "WL-fake",
        "boundary_id": "WB-fake",
        "policy_digest": policy.policy_digest,
        "tier": "highly_complex",
        "blockers": [],
        "artifacts": [{"artifact_id": "ART-fake"}],
    }
    with pytest.raises(ValueError, match="schema validation"):
        summarize_workload_complexity(
            [fabricated],
            policies=[policy],
            source_root=tmp_path,
            verified_at=datetime(2026, 9, 16, tzinfo=UTC),
        )

    result = _assess(tmp_path / "governed")
    result["tier"] = "highly_complex"
    from smf.assessment import workload_result_digest

    result["result_digest"] = workload_result_digest(result)
    signed_fabrication = sign_workload_complexity_result(
        result, authority="assessment-service", key_id="assessment-key", private_key=KEY
    )
    with pytest.raises(ValueError, match="semantic mismatch"):
        summarize_workload_complexity(
            [signed_fabrication],
            policies=[policy],
            source_root=tmp_path / "governed",
            verified_at=datetime(2026, 9, 16, tzinfo=UTC),
        )


def test_checked_in_humana_policy_is_structurally_valid_and_inactive() -> None:
    policy = load_workload_complexity_policy(Path("deployments/humana/complexity.yaml"))
    assert policy.payload["status"] == "pending"
    assert all(
        feature["weight"] == 0
        for item in policy.payload["dimensions"]
        for feature in item["features"]
    )
