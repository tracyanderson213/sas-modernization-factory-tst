from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.workload_complexity_support import (
    COMPLEXITY_KEY,
    MACRO_STRATEGY_DIGEST,
    attach_governed_assessments,
    complexity_policy,
)

from smf.assessment import (
    sign_workload_complexity_result,
    workload_policy_digest,
    workload_result_digest,
)
from smf.pilot import (
    PilotSelectionRequest,
    evaluate_pilot_selection,
    inventory_digest,
    load_pilot_policy,
    pilot_policy_from_dict,
    policy_digest,
    verify_selected_workload,
    write_manifest,
)
from smf.readiness.policy import digest_value

_INVENTORY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_INVENTORY_PUBLIC = base64.b64encode(
    _INVENTORY_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode("ascii")


def _seal_inventory(raw: dict) -> None:
    raw["inventory_digest"] = inventory_digest(raw)
    raw["proof"] = {
        "algorithm": "ed25519",
        "key_id": "inventory-key-1",
        "value": base64.b64encode(
            _INVENTORY_KEY.sign(bytes.fromhex(raw["inventory_digest"]))
        ).decode("ascii"),
    }


def _write_json(path: Path, payload: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy(size: int = 2) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": "1.0",
        "policy_id": "POL-pilot-test",
        "policy_version": "1.0",
        "policy_digest": "0" * 64,
        "client_id": "test-client",
        "authority": "test-governance",
        "cohort_size": size,
        "expected_inventory_size": 2,
        "criteria": [
            {
                "criterion_id": "complexity-complex",
                "dimension": "complexity",
                "value": "complex",
                "minimum_count": 1,
            },
            {
                "criterion_id": "macro-dynamic",
                "dimension": "macro_behavior",
                "value": "dynamic",
                "minimum_count": 1,
            },
            {
                "criterion_id": "data-database",
                "dimension": "data_access",
                "value": "database",
                "minimum_count": 1,
            },
        ],
        "required_prerequisites": [],
        "approval_policy": {
            "readiness_policy_digests": ["a" * 64],
            "workload_complexity_policy_digests": [complexity_policy()["policy_digest"]],
        },
        "inventory_provenance": {
            "authorities": ["inventory-service"],
            "key_ids": ["inventory-key-1"],
        },
        "verification_keys": {"inventory-key-1": _INVENTORY_PUBLIC},
        "permitted_origins": ["synthetic"],
        "dependency_grouping": "atomic",
        "blocked_members_occupy_slots": True,
        "ordering": ["coverage_gain_desc", "complexity_score_desc", "workload_id_asc"],
        "owner_roles": {"inventory": "inventory-owner", "selection_exception": "pilot-owner"},
        "status": "active",
        "valid_from": "2020-01-01T00:00:00+00:00",
        "valid_until": "2099-01-01T00:00:00+00:00",
        "supersedes": None,
    }
    raw["policy_digest"] = policy_digest(raw)
    return raw


def _candidate(root: Path, suffix: str, *, complex_workload: bool) -> tuple[dict, dict]:
    workload_id = f"WL-{suffix}"
    boundary_id = f"WB-{suffix}"
    artifact_id = f"ART-{suffix}"
    source_path = root / "sources" / f"{suffix}.sas"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(f"data output_{suffix}; set input_{suffix}; run;\n", encoding="utf-8")
    source_sha = hashlib.sha256(source_path.read_bytes()).hexdigest()
    artifact = {
        "artifact_id": artifact_id,
        "logical_path": f"sas/{suffix}.sas",
        "source_uri": f"sources/{suffix}.sas",
        "sha256": source_sha,
        "size_bytes": source_path.stat().st_size,
    }
    closure_digest = digest_value(
        [{key: artifact[key] for key in ("artifact_id", "logical_path", "sha256", "size_bytes")}]
    )
    discovered = {
        "workload_id": workload_id,
        "artifacts": [
            {
                "artifact_id": artifact_id,
                "kind": "sas_program",
                "logical_path": artifact["logical_path"],
                "checksum": source_sha,
            }
        ],
        "boundaries": [
            {
                "boundary_id": boundary_id,
                "artifact_ids": [artifact_id],
                "metadata": {"entry_point_artifact_id": artifact_id},
            }
        ],
        "datasets": (
            [{"dataset_id": f"DS-{suffix}", "kind": "database_table"}] if complex_workload else []
        ),
        "relationships": [],
        "external_dependencies": [],
        "dependency_graph": {
            "graph_id": f"GRAPH-{suffix}",
            "nodes": [
                {
                    "node_id": f"NODE-{artifact_id}",
                    "kind": "artifact",
                    "entity_id": artifact_id,
                }
            ],
            "edges": [],
            "unresolved": [],
        },
        "macro_analysis": {
            "analysis_id": f"MAN-{suffix}",
            "strategy_digest": MACRO_STRATEGY_DIGEST,
            "complete": True,
            "source_inventory": [
                {"source_artifact_id": artifact_id, "source_checksum": source_sha}
            ],
            "observations": (
                [
                    {
                        "observation_id": f"MOBS-{suffix}",
                        "kind": "dynamic_invocation",
                        "normalized_identity": "dynamic-macro",
                        "location": {
                            "source_artifact_id": artifact_id,
                            "source_checksum": source_sha,
                            "byte_start": 0,
                            "byte_end": 4,
                            "line": 1,
                            "column": 1,
                            "span_digest": hashlib.sha256(b"data").hexdigest(),
                        },
                    }
                ]
                if complex_workload
                else []
            ),
            "resolutions": [],
            "blockers": [],
        },
    }
    candidate = {
        "workload_id": workload_id,
        "boundary_id": boundary_id,
        "script_ids": [f"SCRIPT-{suffix}"],
        "entry_point_artifact_id": artifact_id,
        "source_closure": [artifact],
        "source_closure_digest": closure_digest,
        "closure_evidence_artifact_ids": [artifact_id],
        "discovery_workload_digest": digest_value(discovered),
        "assessment": {
            "assessment_id": f"ASSESS-{suffix}",
            "strategy_id": "assessment-v1",
            "strategy_version": "1.0",
            "uri": f"assessments/{suffix}.json",
            "digest": "0" * 64,
            "result_digest": "0" * 64,
            "policy_uri": "assessments/complexity-policy.json",
            "policy_digest": "0" * 64,
        },
        "complexity": "complex" if complex_workload else "simple",
        "complexity_score": 90 if complex_workload else 10,
        "constructs": ["proc_sql"] if complex_workload else ["data_step"],
        "macro_behaviors": ["dynamic"] if complex_workload else ["none"],
        "dependency_characteristics": ["external"] if complex_workload else ["isolated"],
        "coupling_group": None,
        "data_access_categories": ["database"] if complex_workload else ["files"],
        "validation_difficulty": "high" if complex_workload else "low",
        "validation_policy_ref": "VALIDATION-1",
        "prerequisites": [],
        "source_origin": "synthetic",
    }
    return candidate, discovered


def _inventory(root: Path) -> dict:
    hard, discovered_hard = _candidate(root, "hard", complex_workload=True)
    easy, discovered_easy = _candidate(root, "easy", complex_workload=False)
    discovery = {"provider": "filesystem", "workloads": [discovered_easy, discovered_hard]}
    attach_governed_assessments(root, discovery, [easy, hard])
    snapshot_digest = _write_json(root / "discovery.json", discovery)
    raw = {
        "schema_version": "1.0",
        "client_id": "test-client",
        "inventory_id": "INV-1",
        "inventory_version": "1.0",
        "inventory_digest": "0" * 64,
        "authority": "inventory-service",
        "proof": {
            "algorithm": "ed25519",
            "key_id": "inventory-key-1",
            "value": "A" * 88,
        },
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "expected_competition_denominator": 2,
        "observed_unique_script_denominator": 2,
        "discovery_snapshot": {
            "snapshot_id": "DISC-1",
            "uri": "discovery.json",
            "digest": snapshot_digest,
            "content_digest": digest_value(discovery),
            "authority": "discovery-service",
            "acquisition_id": "DISC-RUN-1",
        },
        "candidates": [easy, hard],
        "unprocessable": [],
    }
    _seal_inventory(raw)
    return raw


def _evaluate(
    root: Path,
    inventory: dict | None = None,
    policy: dict | None = None,
    *,
    evaluated_at: datetime | None = None,
):
    actual_inventory = inventory or _inventory(root)
    actual_policy = policy or _policy()
    return evaluate_pilot_selection(
        PilotSelectionRequest(
            inventory=actual_inventory,
            policy=pilot_policy_from_dict(actual_policy),
            inventory_root=root,
            run_id="run-1",
            attempt_id="attempt-1",
        ),
        evaluated_at=evaluated_at or datetime(2026, 9, 15, tzinfo=UTC),
    )


def test_representative_selection_is_deterministic_and_not_easy_only(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    first = _evaluate(tmp_path, inventory)
    second = _evaluate(tmp_path, deepcopy(inventory))
    assert first.to_dict() == second.to_dict()
    assert first.disposition == "qualified"
    included = {item.workload_id for item in first.decisions if item.membership == "included"}
    assert included == {"WL-hard", "WL-easy"}
    assert first.full_inventory_denominator == 2
    assert not any((first.generated, first.executed, first.validated, first.parity_passed))


def test_anti_cherry_pick_and_denominator_mutations_block_or_reject(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    inventory["candidates"] = [inventory["candidates"][0]]
    inventory["observed_unique_script_denominator"] = 1
    _seal_inventory(inventory)
    result = _evaluate(tmp_path, inventory)
    assert result.disposition == "blocked"
    assert "complexity-complex" in result.uncovered_criteria
    inventory["observed_unique_script_denominator"] = 2
    _seal_inventory(inventory)
    with pytest.raises(ValueError, match="denominator"):
        _evaluate(tmp_path, inventory)

    inventory = _inventory(tmp_path)
    inventory["expected_competition_denominator"] = 3
    _seal_inventory(inventory)
    mismatch = _evaluate(tmp_path, inventory)
    assert mismatch.disposition == "blocked"
    assert mismatch.blockers == (
        {"code": "inventory_denominator_mismatch", "owner": "inventory-owner"},
    )


def test_unknown_enum_duplicate_identity_and_secret_canary_fail_closed(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    inventory["candidates"][0]["complexity"] = "simpel"
    _seal_inventory(inventory)
    with pytest.raises(ValueError, match="schema"):
        _evaluate(tmp_path, inventory)

    inventory = _inventory(tmp_path)
    inventory["candidates"][1]["workload_id"] = "WL-easy"
    _seal_inventory(inventory)
    with pytest.raises(ValueError, match="Duplicate canonical workload"):
        _evaluate(tmp_path, inventory)

    inventory = _inventory(tmp_path)
    inventory["candidates"][0]["constructs"] = ["DB_PASSWORD=secret-canary"]
    _seal_inventory(inventory)
    with pytest.raises(ValueError, match="schema|secret-bearing"):
        _evaluate(tmp_path, inventory)


def test_unpermitted_origin_and_unprocessable_records_remain_visible(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    inventory["candidates"][0]["source_origin"] = "public"
    _seal_inventory(inventory)
    origin_result = _evaluate(tmp_path, inventory)
    easy = next(item for item in origin_result.decisions if item.workload_id == "WL-easy")
    assert easy.admission_state == "blocked"
    assert "source_origin_not_permitted" in easy.reasons
    assert origin_result.disposition == "blocked"

    inventory = _inventory(tmp_path)
    inventory["unprocessable"] = [
        {
            "record_id": "UNPROCESSABLE-1",
            "script_ids": ["SCRIPT-unprocessable"],
            "reason": "inventory-record-invalid",
            "owner": "inventory-owner",
        }
    ]
    inventory["observed_unique_script_denominator"] = 3
    inventory["expected_competition_denominator"] = 3
    policy = _policy()
    policy["expected_inventory_size"] = 3
    policy["policy_digest"] = policy_digest(policy)
    _seal_inventory(inventory)
    unprocessable = _evaluate(tmp_path, inventory, policy)
    assert unprocessable.full_inventory_denominator == 3
    assert unprocessable.unprocessable_count == 1
    assert unprocessable.disposition == "blocked"
    assert any(item["code"] == "unprocessable_inventory_records" for item in unprocessable.blockers)


def test_source_mutation_and_nonconvertible_entry_point_block(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    (tmp_path / "sources/hard.sas").write_text("/* configuration only */\n", encoding="utf-8")
    result = _evaluate(tmp_path, inventory)
    hard = next(item for item in result.decisions if item.workload_id == "WL-hard")
    assert result.disposition == "blocked"
    assert "source_bytes_changed" in hard.reasons
    assert "no_meaningful_sas_entry_point" in hard.reasons


def test_candidate_cannot_substitute_canonical_entry_artifact(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    candidate = inventory["candidates"][1]
    substituted = tmp_path / "sources/substituted.sas"
    substituted.write_text("data substituted; set other; run;\n", encoding="utf-8")
    artifact = {
        "artifact_id": "ART-substituted",
        "logical_path": "sas/substituted.sas",
        "source_uri": "sources/substituted.sas",
        "sha256": hashlib.sha256(substituted.read_bytes()).hexdigest(),
        "size_bytes": substituted.stat().st_size,
    }
    candidate["entry_point_artifact_id"] = artifact["artifact_id"]
    candidate["source_closure"] = [artifact]
    candidate["closure_evidence_artifact_ids"] = [artifact["artifact_id"]]
    candidate["source_closure_digest"] = digest_value(
        [{key: artifact[key] for key in ("artifact_id", "logical_path", "sha256", "size_bytes")}]
    )
    assessment_path = tmp_path / candidate["assessment"]["uri"]
    assessment = json.loads(assessment_path.read_text())
    assessment.update(
        entry_point_digest=artifact["sha256"],
        source_closure_digest=candidate["source_closure_digest"],
    )
    candidate["assessment"]["digest"] = _write_json(assessment_path, assessment)
    _seal_inventory(inventory)

    result = _evaluate(tmp_path, inventory)

    hard = next(item for item in result.decisions if item.workload_id == "WL-hard")
    assert result.disposition == "blocked"
    assert {
        "canonical_entry_point_mismatch",
        "canonical_source_closure_mismatch",
        "canonical_dependency_closure_mismatch",
    }.issubset(hard.reasons)


def test_candidate_cannot_omit_canonical_dependency_closure(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    discovery_path = tmp_path / "discovery.json"
    discovery = json.loads(discovery_path.read_text())
    hard = next(item for item in discovery["workloads"] if item["workload_id"] == "WL-hard")
    hard["artifacts"].append(
        {
            "artifact_id": "ART-hard-include",
            "kind": "sas_include",
            "logical_path": "sas/hard-include.sas",
            "checksum": "b" * 64,
        }
    )
    hard["dependency_graph"]["nodes"].append(
        {"node_id": "NODE-ART-hard-include", "kind": "artifact", "entity_id": "ART-hard-include"}
    )
    hard["dependency_graph"]["edges"].append(
        {
            "edge_id": "EDGE-hard-include",
            "source_id": "NODE-ART-hard",
            "kind": "includes",
            "target_id": "NODE-ART-hard-include",
        }
    )
    inventory["discovery_snapshot"]["digest"] = _write_json(discovery_path, discovery)
    inventory["discovery_snapshot"]["content_digest"] = digest_value(discovery)
    inventory["candidates"][1]["discovery_workload_digest"] = digest_value(hard)
    _seal_inventory(inventory)

    result = _evaluate(tmp_path, inventory)

    decision = next(item for item in result.decisions if item.workload_id == "WL-hard")
    assert result.disposition == "blocked"
    assert "canonical_dependency_closure_mismatch" in decision.reasons


def test_symlinked_source_and_mutated_policy_object_fail_closed(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    source = tmp_path / "sources/hard.sas"
    alternate = tmp_path / "alternate.sas"
    alternate.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(alternate)
    result = _evaluate(tmp_path, inventory)
    hard = next(item for item in result.decisions if item.workload_id == "WL-hard")
    assert "source_artifact_missing_or_unsafe" in hard.reasons
    assert result.disposition == "blocked"

    canonical = pilot_policy_from_dict(_policy())
    canonical.payload["cohort_size"] = 1
    with pytest.raises(ValueError, match="not canonical"):
        evaluate_pilot_selection(
            PilotSelectionRequest(
                inventory=_inventory(tmp_path / "second"),
                policy=canonical,
                inventory_root=tmp_path / "second",
                run_id="run-1",
                attempt_id="attempt-1",
            ),
            evaluated_at=datetime(2026, 9, 15, tzinfo=UTC),
        )


def test_policy_validity_interval_must_be_ordered() -> None:
    policy = _policy()
    policy["valid_until"] = policy["valid_from"]
    policy["policy_digest"] = policy_digest(policy)
    with pytest.raises(ValueError, match="validity interval"):
        pilot_policy_from_dict(policy)


def test_policy_yaml_rejects_duplicate_keys_before_digest_validation(tmp_path: Path) -> None:
    policy = _policy()
    path = tmp_path / "policy.yaml"
    path.write_text(
        __import__("yaml").safe_dump(policy, sort_keys=False) + "cohort_size: 1\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate pilot selection policy key"):
        load_pilot_policy(path)


def test_signed_inventory_and_caller_assertions_cannot_fail_open(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    inventory["candidates"][0]["approved"] = True
    _seal_inventory(inventory)
    with pytest.raises(ValueError, match="schema"):
        _evaluate(tmp_path, inventory)

    inventory = _inventory(tmp_path)
    inventory["proof"]["value"] = base64.b64encode(b"x" * 64).decode("ascii")
    with pytest.raises(ValueError, match="attestation"):
        _evaluate(tmp_path, inventory)

    inventory = _inventory(tmp_path)
    source = tmp_path / "sources/hard.sas"
    source.write_text("data x; password=secret-canary; run;\n", encoding="utf-8")
    candidate = inventory["candidates"][1]
    candidate["source_closure"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    candidate["source_closure"][0]["size_bytes"] = source.stat().st_size
    candidate["source_closure_digest"] = digest_value(
        [
            {
                key: candidate["source_closure"][0][key]
                for key in ("artifact_id", "logical_path", "sha256", "size_bytes")
            }
        ]
    )
    _seal_inventory(inventory)
    with pytest.raises(ValueError, match="secret-bearing") as failure:
        _evaluate(tmp_path, inventory)
    assert "secret-canary" not in str(failure.value)


def test_pilot_requires_governed_complexity_and_rejects_caller_projection(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    inventory["candidates"][0]["complexity"] = "complex"
    inventory["candidates"][0]["complexity_score"] = 999
    _seal_inventory(inventory)
    projected = _evaluate(tmp_path, inventory)
    easy = next(item for item in projected.decisions if item.workload_id == "WL-easy")
    assert easy.admission_state == "blocked"
    assert "assessment_projection_mismatch" in easy.reasons

    inventory = _inventory(tmp_path / "unsigned")
    candidate = inventory["candidates"][0]
    assessment_path = tmp_path / "unsigned" / candidate["assessment"]["uri"]
    assessment = json.loads(assessment_path.read_text())
    assessment["proof"] = None
    candidate["assessment"]["digest"] = _write_json(assessment_path, assessment)
    _seal_inventory(inventory)
    unsigned = _evaluate(tmp_path / "unsigned", inventory)
    easy = next(item for item in unsigned.decisions if item.workload_id == "WL-easy")
    assert easy.admission_state == "blocked"
    assert "assessment_attestation_invalid" in easy.reasons


def test_expired_complexity_policy_blocks_pilot_with_distinct_reason(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    complexity = complexity_policy()
    complexity["valid_until"] = "2026-09-15T00:00:00+00:00"
    complexity["policy_digest"] = workload_policy_digest(complexity)
    _write_json(tmp_path / "assessments/complexity-policy.json", complexity)
    for candidate in inventory["candidates"]:
        assessment_path = tmp_path / candidate["assessment"]["uri"]
        assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
        assessment["policy_digest"] = complexity["policy_digest"]
        assessment["result_digest"] = workload_result_digest(assessment)
        assessment = sign_workload_complexity_result(
            assessment,
            authority="assessment-service",
            key_id="complexity-key",
            private_key=COMPLEXITY_KEY,
        )
        candidate["assessment"]["policy_digest"] = complexity["policy_digest"]
        candidate["assessment"]["result_digest"] = assessment["result_digest"]
        candidate["assessment"]["digest"] = _write_json(assessment_path, assessment)
    _seal_inventory(inventory)
    selection_policy = _policy()
    selection_policy["approval_policy"]["workload_complexity_policy_digests"] = [
        complexity["policy_digest"]
    ]
    selection_policy["policy_digest"] = policy_digest(selection_policy)

    result = _evaluate(
        tmp_path,
        inventory,
        selection_policy,
        evaluated_at=datetime(2026, 9, 16, tzinfo=UTC),
    )

    assert result.disposition == "blocked"
    assert all("assessment_policy_expired" in decision.reasons for decision in result.decisions)


@pytest.mark.parametrize("artifact", ["discovery", "assessment"])
def test_referenced_evidence_secret_canaries_are_rejected_before_persistence(
    tmp_path: Path, artifact: str
) -> None:
    inventory = _inventory(tmp_path)
    if artifact == "discovery":
        path = tmp_path / "discovery.json"
        payload = json.loads(path.read_text())
        payload["client_secret"] = "referenced-evidence-canary"
        inventory["discovery_snapshot"]["digest"] = _write_json(path, payload)
        inventory["discovery_snapshot"]["content_digest"] = digest_value(payload)
    else:
        path = tmp_path / inventory["candidates"][0]["assessment"]["uri"]
        payload = json.loads(path.read_text())
        payload["access_token"] = "referenced-evidence-canary"
        inventory["candidates"][0]["assessment"]["digest"] = _write_json(path, payload)
    _seal_inventory(inventory)

    with pytest.raises(ValueError, match="secret-bearing") as failure:
        _evaluate(tmp_path, inventory)
    assert "referenced-evidence-canary" not in str(failure.value)


def test_pending_and_denied_are_distinct_and_never_qualified(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    for candidate, state in zip(inventory["candidates"], ("pending", "denied"), strict=True):
        candidate["prerequisites"] = [
            {
                "prerequisite_id": "owner-approval",
                "state": state,
                "owner": f"{state}-owner",
                "evidence_run_id": None,
                "evidence_attempt_id": None,
                "readiness_manifest_uri": None,
                "readiness_manifest_digest": None,
            }
        ]
    policy = _policy()
    policy["required_prerequisites"] = ["owner-approval"]
    policy["policy_digest"] = policy_digest(policy)
    _seal_inventory(inventory)
    result = _evaluate(tmp_path, inventory, policy)
    states = {item.workload_id: item.admission_state for item in result.decisions}
    assert states == {"WL-easy": "pending", "WL-hard": "denied"}
    assert result.disposition == "blocked"

    inventory = _inventory(tmp_path / "pending-only")
    for candidate in inventory["candidates"]:
        candidate["prerequisites"] = [
            {
                "prerequisite_id": "owner-approval",
                "state": "pending",
                "owner": "approval-owner",
                "evidence_run_id": None,
                "evidence_attempt_id": None,
                "readiness_manifest_uri": None,
                "readiness_manifest_digest": None,
            }
        ]
    _seal_inventory(inventory)
    pending_only = _evaluate(tmp_path / "pending-only", inventory, policy)
    assert pending_only.disposition == "human_required"


def test_append_only_replay_telemetry_recovery_and_downstream_binding(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    inventory = _inventory(evidence_root)
    result = _evaluate(evidence_root, inventory)
    path = write_manifest(tmp_path / "out", result, inventory_root=evidence_root)
    telemetry = path.with_name("selection.telemetry.json")
    telemetry.unlink()
    same = write_manifest(tmp_path / "out", result, inventory_root=evidence_root)
    assert same == path and telemetry.is_file()
    decision = verify_selected_workload(
        path,
        inventory_root=evidence_root,
        workload_id="WL-hard",
        boundary_id="WB-hard",
        source_closure_digest=next(
            item.source_closure_digest for item in result.decisions if item.workload_id == "WL-hard"
        ),
        run_id="run-1",
        attempt_id="attempt-1",
    )
    assert decision["admission_state"] == "eligible"
    with pytest.raises(ValueError, match="source closure changed"):
        verify_selected_workload(
            path,
            inventory_root=evidence_root,
            workload_id="WL-hard",
            boundary_id="WB-hard",
            source_closure_digest="f" * 64,
            run_id="run-1",
            attempt_id="attempt-1",
        )

    path.with_name("policy.snapshot.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="snapshot.json binding mismatch"):
        verify_selected_workload(
            path,
            inventory_root=evidence_root,
            workload_id="WL-hard",
            boundary_id="WB-hard",
            source_closure_digest=decision["source_closure_digest"],
            run_id="run-1",
            attempt_id="attempt-1",
        )


def test_attempt_identity_cannot_be_reused_with_changed_inventory(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    inventory = _inventory(evidence_root)
    result = _evaluate(evidence_root, inventory)
    write_manifest(tmp_path / "out", result, inventory_root=evidence_root)
    changed = deepcopy(inventory)
    changed["inventory_version"] = "2.0"
    _seal_inventory(changed)
    changed_result = _evaluate(evidence_root, changed)
    assert changed_result.selection_id == result.selection_id
    with pytest.raises(FileExistsError, match="different bytes"):
        write_manifest(tmp_path / "out", changed_result, inventory_root=evidence_root)


def test_one_candidate_failure_does_not_corrupt_other_decision(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path)
    inventory["candidates"][0]["prerequisites"] = [
        {
            "prerequisite_id": "owner-approval",
            "state": "denied",
            "owner": "humana-owner",
            "evidence_run_id": None,
            "evidence_attempt_id": None,
            "readiness_manifest_uri": None,
            "readiness_manifest_digest": None,
        }
    ]
    policy = _policy()
    policy["required_prerequisites"] = ["owner-approval"]
    policy["policy_digest"] = policy_digest(policy)
    _seal_inventory(inventory)
    result = _evaluate(tmp_path, inventory, policy)
    states = {item.workload_id: item.admission_state for item in result.decisions}
    assert states == {"WL-easy": "denied", "WL-hard": "blocked"}
    assert result.disposition == "blocked"
