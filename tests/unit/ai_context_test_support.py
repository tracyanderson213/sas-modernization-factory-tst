from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.security.ai_admission import classification_digest, classification_payload
from smf.security.ai_models import AIContextRequest
from smf.security.ai_policy import AIContextPolicy, ai_digest, load_ai_context_policy

PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = base64.b64encode(
    PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode("ascii")


def write_policy(path: Path, *, status: str = "active") -> AIContextPolicy:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "policy_id": "offline-test-policy",
        "policy_version": "1.0",
        "status": status,
        "classification_policy_id": "classification-test-policy",
        "classification_policy_version": "1.0",
        "classification_policy_digest": "c" * 64,
        "classification_authority": "test-data-owner",
        "verification_keys": {"test-key": PUBLIC_KEY},
        "providers": [
            {
                "provider_id": "synthetic-provider",
                "model_ids": ["synthetic-model"],
                "endpoint_binding_ids": ["offline-endpoint"],
            }
        ],
        "allowed_artifact_kinds": ["sas_program", "sas_include", "sas_macro"],
        "allowed_fields": ["source"],
        "retention_policy_ref": "test-retention",
        "access_policy_ref": "test-access",
        "protected_data_in_prompt_allowed": False,
        "max_context_bytes": 100000,
    }
    payload["policy_digest"] = ai_digest(payload)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return load_ai_context_policy(path)


def make_case(
    tmp_path: Path,
) -> tuple[AIContextPolicy, AIContextRequest, dict[str, Any], dict[str, Any]]:
    policy = write_policy(tmp_path / "policy.yaml")
    source = tmp_path / "main.sas"
    source.write_text("data output; set input; run;\n", encoding="utf-8")
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    inventory = [
        {
            "artifact_id": "ART-main",
            "kind": "sas_program",
            "logical_path": "main.sas",
            "sha256": source_digest,
        }
    ]
    request = AIContextRequest(
        schema_version="1.0",
        client_id="synthetic-client",
        deployment_id="offline-deployment",
        environment_id="offline-environment",
        workload_id="WL-one",
        workload_digest="a" * 64,
        boundary_id="BOUND-one",
        subject_id="ART-main",
        source_closure_digest=ai_digest(inventory),
        run_id="run-one",
        attempt_id="attempt-one",
        consumer_id="aip-contract",
        consumer_contract_version="1.0",
        strategy_version="strategy-1",
        readiness_result_id="READY-one",
        readiness_manifest_digest="b" * 64,
        context_policy_id=policy.policy_id,
        context_policy_version=policy.policy_version,
        context_policy_digest=policy.policy_digest,
        classification_policy_id=policy.classification_policy_id,
        classification_policy_version=policy.classification_policy_version,
        classification_policy_digest=policy.classification_policy_digest,
        provider_id="synthetic-provider",
        model_id="synthetic-model",
        endpoint_binding_id="offline-endpoint",
        retention_policy_ref=policy.retention_policy_ref,
        access_policy_ref=policy.access_policy_ref,
        classification_evidence_id="CLASS-one",
        classification_evidence_digest="0" * 64,
        requested_artifact_ids=("ART-main",),
        requested_fields=("source",),
    )
    bindings = request.safe_bindings()
    bindings.pop("classification_evidence_id")
    bindings.pop("classification_evidence_digest")
    now = datetime.now(UTC)
    evidence: dict[str, Any] = {
        "schema_version": "1.0",
        "evidence_id": "CLASS-one",
        "state": "approved",
        "authority": policy.classification_authority,
        "purpose": request.decision_purpose,
        "decision_id": "classification-decision-one",
        "owner_assignment_ref": "owner-assignment-one",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "bindings": bindings,
        "artifacts": [
            {
                "artifact_id": "ART-main",
                "sha256": source_digest,
                "classification": "non_protected",
            }
        ],
        "fields": [{"field_id": "source", "classification": "permitted"}],
        "proof": {"algorithm": "ed25519", "key_id": "test-key", "value": "pending"},
    }
    evidence["proof"]["value"] = base64.b64encode(
        PRIVATE_KEY.sign(classification_payload(evidence))
    ).decode("ascii")
    request = replace(request, classification_evidence_digest=classification_digest(evidence))
    manifest = {
        "classification": "READY",
        "workload_id": request.workload_id,
        "workload_digest": request.workload_digest,
        "boundary_id": request.boundary_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "result_id": request.readiness_result_id,
        "content_digest": request.readiness_manifest_digest,
        "policy_snapshot": {
            "prerequisite_binding": {
                "client_id": request.client_id,
                "deployment_id": request.deployment_id,
                "environment_id": request.environment_id,
            }
        },
        "qualification_input": {
            "workload": {
                "artifacts": [
                    {
                        "artifact_id": "ART-main",
                        "kind": "sas_program",
                        "logical_path": "main.sas",
                        "checksum": source_digest,
                    }
                ],
                "boundaries": [{"boundary_id": request.boundary_id, "artifact_ids": ["ART-main"]}],
            }
        },
    }
    return policy, request, evidence, manifest


def resign(evidence: dict[str, Any]) -> None:
    evidence["proof"]["value"] = base64.b64encode(
        PRIVATE_KEY.sign(classification_payload(evidence))
    ).decode("ascii")
