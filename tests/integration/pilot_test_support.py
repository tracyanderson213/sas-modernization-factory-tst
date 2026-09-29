"""Synthetic pilot-selection builders shared by integration tests."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.workload_complexity_support import (
    MACRO_STRATEGY_DIGEST,
    attach_governed_assessments,
    complexity_policy,
)

from smf.pilot import (
    PilotSelectionRequest,
    evaluate_pilot_selection,
    inventory_digest,
    pilot_policy_from_dict,
    policy_digest,
)
from smf.pilot.models import PilotSelectionResult
from smf.readiness.policy import digest_value

_INVENTORY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_INVENTORY_PUBLIC = base64.b64encode(
    _INVENTORY_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode("ascii")


def _write_json(path: Path, payload: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seal_inventory(raw: dict[str, Any]) -> None:
    raw["inventory_digest"] = inventory_digest(raw)
    raw["proof"] = {
        "algorithm": "ed25519",
        "key_id": "inventory-key-1",
        "value": base64.b64encode(
            _INVENTORY_KEY.sign(bytes.fromhex(raw["inventory_digest"]))
        ).decode("ascii"),
    }


def build_policy(size: int = 2) -> dict[str, Any]:
    raw: dict[str, Any] = {
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
    return (
        {
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
        },
        discovered,
    )


def build_inventory(root: Path) -> dict[str, Any]:
    hard, discovered_hard = _candidate(root, "hard", complex_workload=True)
    easy, discovered_easy = _candidate(root, "easy", complex_workload=False)
    discovery = {"provider": "filesystem", "workloads": [discovered_easy, discovered_hard]}
    attach_governed_assessments(root, discovery, [easy, hard])
    snapshot_digest = _write_json(root / "discovery.json", discovery)
    raw: dict[str, Any] = {
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


def evaluate_selection(root: Path, inventory: dict[str, Any] | None = None) -> PilotSelectionResult:
    return evaluate_pilot_selection(
        PilotSelectionRequest(
            inventory=inventory or build_inventory(root),
            policy=pilot_policy_from_dict(build_policy()),
            inventory_root=root,
            run_id="run-1",
            attempt_id="attempt-1",
        ),
        evaluated_at=datetime(2026, 9, 15, tzinfo=UTC),
    )
