from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.upstream.crypto import sign_payload
from smf.upstream.policy import load_upstream_inventory, load_upstream_policy
from smf.workload.identity import stable_id


def _key(root: Path, key_id: str) -> tuple[Path, str]:
    private = Ed25519PrivateKey.generate()
    path = root / f"{key_id}.pem"
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return path, base64.b64encode(public).decode("ascii")


def _record(path: Path, root: Path, artifact_type: str) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "relative_path": path.relative_to(root).as_posix(),
        "artifact_type": artifact_type,
        "byte_count": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def build_upstream_fixture(tmp_path: Path) -> dict[str, Any]:
    evidence = tmp_path / "evidence"
    output = tmp_path / "out"
    (evidence / "artifacts").mkdir(parents=True)
    (evidence / "licenses").mkdir()
    (evidence / "receipts").mkdir()
    (evidence / "prerequisites").mkdir()
    (evidence / "runtime").mkdir()
    artifact_path = evidence / "artifacts" / "demo.tar"
    license_path = evidence / "licenses" / "LICENSE"
    artifact_path.write_bytes(b"immutable upstream source bytes")
    license_path.write_text("MIT License\n", encoding="utf-8")
    keys = {}
    public = {}
    for key_id in (
        "acquisition-key",
        "observer-key",
        "supporting-key",
        "qualification-key",
        "prereq-key",
    ):
        keys[key_id], public[key_id] = _key(tmp_path, key_id)
    policy_payload = {
        "schema_version": "1.0",
        "policy_id": "upstream-policy",
        "policy_version": "1",
        "scope_kind": "global_program",
        "activity_freshness": {
            "max_age_seconds": 86400,
            "max_future_skew_seconds": 300,
        },
        "acquisition_provenance": {
            "authorities": ["artifact-custodian"],
            "key_ids": ["acquisition-key"],
        },
        "observer_provenance": {
            "authorities": ["upstream-observer"],
            "key_ids": ["observer-key"],
        },
        "supporting_evidence_provenance": {
            "authorities": ["evidence-service"],
            "key_ids": ["supporting-key"],
        },
        "qualification_provenance": {
            "authorities": ["qualification-service"],
            "key_ids": ["qualification-key"],
        },
        "prerequisite_provenance": {
            "authorities": ["project-auditor"],
            "key_ids": ["prereq-key"],
        },
        "verification_keys": public,
        "prerequisite": {
            "prerequisite_id": "SEC-03",
            "evidence_path": "prerequisites/sec-03.json",
            "acceptance_digest": "d" * 64,
        },
    }
    inventory_payload = {
        "schema_version": "1.0",
        "inventory_id": "test-inventory",
        "inventory_version": "1",
        "source_report": "synthetic contract fixture only",
        "upstreams": [
            {
                "upstream_id": "demo",
                "canonical_origin": "https://example.invalid/demo",
                "revision": "a" * 40,
                "revision_type": "git_commit",
                "artifact_class": "source_tree",
                "license_evidence": [{"evidence_id": "license", "license_id": "MIT"}],
                "capabilities": [
                    {"capability_id": "read", "description": "Synthetic read capability"}
                ],
                "limitations": [
                    {"limitation_id": "synthetic-only", "description": "Not external proof"}
                ],
                "activity_source": "https://example.invalid/demo/activity",
                "permitted_use": ["provider_wrapper"],
                "disposition": "wrap",
            }
        ],
    }
    policy_path = tmp_path / "policy.json"
    inventory_path = tmp_path / "inventory.json"
    policy_path.write_text(json.dumps(policy_payload), encoding="utf-8")
    inventory_path.write_text(json.dumps(inventory_payload), encoding="utf-8")
    policy = load_upstream_policy(policy_path)
    inventory = load_upstream_inventory(inventory_path)
    artifact = _record(artifact_path, evidence, "source_tree_archive")
    license_record = {
        **_record(license_path, evidence, "license"),
        "evidence_id": "license",
        "license_id": "MIT",
    }
    supporting_paths = {
        "execution_evidence": evidence / "runtime" / "execution.json",
        "environment_evidence": evidence / "runtime" / "environment.json",
        "output_evidence": evidence / "runtime" / "output.txt",
        "negative_case_evidence": evidence / "runtime" / "negative-case.json",
        "compatibility_evidence": evidence / "runtime" / "compatibility.json",
    }
    common_evidence_identity = {
        "upstream_id": "demo",
        "revision": "a" * 40,
        "scope_id": "program",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
    }

    def write_supporting(
        name: str, evidence_id: str, evidence_class: str, payload: dict[str, Any]
    ) -> None:
        record = {
            "schema_version": "1.0",
            "record_id": stable_id(
                "UPQE",
                {
                    **common_evidence_identity,
                    "evidence_id": evidence_id,
                    "evidence_class": evidence_class,
                    "authority": "evidence-service",
                    "payload": payload,
                },
            ),
            "evidence_id": evidence_id,
            "evidence_class": evidence_class,
            **common_evidence_identity,
            "authority": "evidence-service",
            "payload": payload,
            "proof": {},
        }
        sign_payload(record, private_key_path=keys["supporting-key"], key_id="supporting-key")
        supporting_paths[name].write_text(json.dumps(record), encoding="utf-8")

    write_supporting(
        "execution_evidence",
        "test-read",
        "execution_record",
        {
            "command": ["pytest", "test_reader.py"],
            "expected_outcome": "pass",
            "actual_outcome": "pass",
            "exit_status": 0,
            "execution_state": "executed",
        },
    )
    write_supporting(
        "environment_evidence",
        "test-read-environment",
        "environment_manifest",
        {"python": "3.12", "fixture": "synthetic"},
    )
    write_supporting(
        "output_evidence",
        "test-read-output",
        "command_output",
        {"summary": "1 passed"},
    )
    write_supporting(
        "negative_case_evidence",
        "test-read-negative",
        "negative_case_record",
        {"case": "invalid-input", "outcome": "rejected"},
    )
    execution_evidence = _record(
        supporting_paths["execution_evidence"], evidence, "execution_record"
    )
    environment_evidence = _record(
        supporting_paths["environment_evidence"], evidence, "environment_manifest"
    )
    output_evidence = _record(supporting_paths["output_evidence"], evidence, "command_output")
    negative_case_evidence = _record(
        supporting_paths["negative_case_evidence"], evidence, "negative_case_record"
    )
    write_supporting(
        "compatibility_evidence",
        "compat-1",
        "compatibility_record",
        {"state": "compatible", "environment_digest": environment_evidence["sha256"]},
    )
    compatibility_evidence = _record(
        supporting_paths["compatibility_evidence"], evidence, "compatibility_record"
    )
    acquisition = {
        "acquisition_id": stable_id(
            "UPQA",
            {
                "upstream_id": "demo",
                "revision": "a" * 40,
                "artifact_sha256": artifact["sha256"],
                "authority": "artifact-custodian",
            },
        ),
        "upstream_id": "demo",
        "canonical_origin": "https://example.invalid/demo",
        "revision": "a" * 40,
        "revision_type": "git_commit",
        "artifact": artifact,
        "authority": "artifact-custodian",
        "acquired_at": "2026-09-18T12:00:00Z",
        "proof": {},
    }
    sign_payload(acquisition, private_key_path=keys["acquisition-key"], key_id="acquisition-key")
    receipt = {
        "schema_version": "1.0",
        "receipt_id": stable_id(
            "UPQR",
            {
                "upstream_id": "demo",
                "canonical_origin": "https://example.invalid/demo",
                "revision": "a" * 40,
                "revision_type": "git_commit",
                "artifact_class": "source_tree",
                "scope_id": "program",
                "run_id": "run-1",
                "attempt_id": "attempt-1",
                "policy_digest": policy.policy_digest,
                "inventory_digest": inventory.inventory_digest,
                "disposition": "wrap",
                "permitted_use": ["provider_wrapper"],
                "artifact_sha256": artifact["sha256"],
                "observer_authority": "upstream-observer",
            },
        ),
        "upstream_id": "demo",
        "canonical_origin": "https://example.invalid/demo",
        "revision": "a" * 40,
        "revision_type": "git_commit",
        "artifact_class": "source_tree",
        "scope_id": "program",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "policy_digest": policy.policy_digest,
        "inventory_digest": inventory.inventory_digest,
        "artifact": artifact,
        "acquisition": acquisition,
        "license_evidence": [license_record],
        "activity": {
            "source": "https://example.invalid/demo/activity",
            "revision": "a" * 40,
            "observed_at": "2026-09-18T12:00:00Z",
        },
        "capability_evidence": [
            {
                "capability_id": "read",
                "evidence_id": "test-read",
                "evidence_type": "test",
                "command": ["pytest", "test_reader.py"],
                "expected_outcome": "pass",
                "actual_outcome": "pass",
                "exit_status": 0,
                "execution_state": "executed",
                "environment_digest": environment_evidence["sha256"],
                "output_digest": output_evidence["sha256"],
                "execution_evidence": execution_evidence,
                "environment_evidence": environment_evidence,
                "output_evidence": output_evidence,
                "negative_case_evidence": negative_case_evidence,
                "mocked": False,
                "generated_only": False,
            }
        ],
        "observed_limitation_ids": ["synthetic-only"],
        "compatibility": {
            "state": "compatible",
            "environment_digest": environment_evidence["sha256"],
            "evidence_id": "compat-1",
            "evidence": compatibility_evidence,
        },
        "disposition": "wrap",
        "permitted_use": ["provider_wrapper"],
        "observer_authority": "upstream-observer",
        "proof": {},
    }
    receipt_path = evidence / "receipts" / "demo.json"
    sign_payload(receipt, private_key_path=keys["observer-key"], key_id="observer-key")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    prerequisite_identity = {
        "prerequisite_id": "SEC-03",
        "acceptance_digest": "d" * 64,
        "scope_id": "program",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "authority": "project-auditor",
    }
    prerequisite = {
        "schema_version": "1.0",
        "prerequisite_id": "SEC-03",
        "scope_id": "program",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "status": "Done",
        "implementation_state": "Foundation Complete",
        "acceptance_digest": "d" * 64,
        "authority": "project-auditor",
        "decision_id": stable_id("PREREQ", prerequisite_identity),
        "decision_state": "current",
        "proof": {},
    }
    sign_payload(prerequisite, private_key_path=keys["prereq-key"], key_id="prereq-key")
    prereq_path = evidence / "prerequisites" / "sec-03.json"
    prereq_path.write_text(json.dumps(prerequisite), encoding="utf-8")
    return {
        "policy_path": policy_path,
        "inventory_path": inventory_path,
        "policy": policy,
        "inventory": inventory,
        "evidence": evidence,
        "output": output,
        "keys": keys,
        "artifact_path": artifact_path,
        "receipt_path": receipt_path,
        "prereq_path": prereq_path,
        "supporting_paths": supporting_paths,
    }


def resign_json(path: Path, key_path: Path, key_id: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["proof"] = {}
    sign_payload(payload, private_key_path=key_path, key_id=key_id)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload
