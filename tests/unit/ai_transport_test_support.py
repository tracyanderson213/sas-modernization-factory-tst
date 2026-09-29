from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.ai_context_test_support import make_case

from smf.security.ai_admission import qualify_ai_context
from smf.security.ai_manifest import write_ai_context_result
from smf.security.ai_models import QualifiedAIContext
from smf.security.ai_policy import ai_digest, canonical_ai_json
from smf.security.ai_transport_attestation import attestation_digest, attestation_payload
from smf.security.ai_transport_models import AITransportRequest, TransientAIBytes

CONFIG_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
AUTHORITY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
EVIDENCE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))


def _signed_document(value: dict[str, Any], digest_field: str) -> dict[str, Any]:
    value[digest_field] = ai_digest(value)
    value["proof"] = {
        "algorithm": "ed25519",
        "key_id": "configuration-key",
        "value": base64.b64encode(CONFIG_KEY.sign(canonical_ai_json(value))).decode("ascii"),
    }
    return value


def _attestation(
    request: AITransportRequest, kind: str, evidence_id: str, *, state: str = "approved"
) -> dict[str, Any]:
    now = datetime.now(UTC)
    value: dict[str, Any] = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "state": state,
        "decision_id": f"{kind}-decision",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "bindings": request.evidence_bindings(kind),
        "proof": {"algorithm": "ed25519", "key_id": "authority-key", "value": "pending"},
    }
    if kind == "submission":
        value["authority"] = "submission-owner"
        value["purpose"] = "ai-prompt-submit"
    else:
        value["kind"] = kind
    value["proof"]["value"] = base64.b64encode(
        AUTHORITY_KEY.sign(attestation_payload(value))
    ).decode("ascii")
    return value


def make_transport_case(tmp_path: Path) -> dict[str, Any]:
    context_policy, context_request, classification, manifest = make_case(tmp_path)
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        outcome = qualify_ai_context(
            context_request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=context_policy,
            classification_evidence=classification,
        )
    assert outcome.context is not None
    sec02_path = write_ai_context_result(
        tmp_path / "sec02-evidence",
        outcome.result,
        signing_key=EVIDENCE_KEY,
        key_id="evidence-key",
    )
    policy_value = _signed_document(
        {
            "schema_version": "1.0",
            "policy_id": "transport-policy",
            "policy_version": "1.0",
            "status": "active",
            "redirect_policy": "reject",
            "allowed_methods": ["POST"],
            "allowed_media_types": ["application/json"],
            "providers": [
                {
                    "provider_id": context_request.provider_id,
                    "model_ids": [context_request.model_id],
                    "endpoint_binding_ids": [context_request.endpoint_binding_id],
                }
            ],
            "max_payload_bytes": 10000,
            "max_response_bytes": 10000,
            "max_retries": 2,
            "submission_authority": "submission-owner",
        },
        "policy_digest",
    )
    endpoint_value = _signed_document(
        {
            "schema_version": "1.0",
            "binding_id": context_request.endpoint_binding_id,
            "status": "active",
            "deployment_id": context_request.deployment_id,
            "environment_id": context_request.environment_id,
            "provider_id": context_request.provider_id,
            "model_id": context_request.model_id,
            "identity_binding_id": "identity-binding",
            "secret_binding_id": "credential-resolution",
            "tls_profile_ref": "tls-profile",
            "url": "https://approved.example.test/v1/messages",
            "evidence_ref": "evidence://configuration/endpoint-one",
        },
        "binding_digest",
    )
    policy_path = tmp_path / "transport-policy.json"
    endpoint_path = tmp_path / "endpoint.json"
    policy_path.write_text(json.dumps(policy_value), encoding="utf-8")
    endpoint_path.write_text(json.dumps(endpoint_value), encoding="utf-8")
    payload_bytes = b'{"task":"convert the qualified SAS source"}'
    request = AITransportRequest(
        schema_version="1.0",
        client_id=context_request.client_id,
        deployment_id=context_request.deployment_id,
        environment_id=context_request.environment_id,
        workload_id=context_request.workload_id,
        workload_digest=context_request.workload_digest,
        boundary_id=context_request.boundary_id,
        subject_id=context_request.subject_id,
        source_closure_digest=context_request.source_closure_digest,
        permitted_artifact_ids=outcome.result.permitted_artifact_ids,
        run_id=context_request.run_id,
        workflow_attempt_id=context_request.attempt_id,
        provider_request_id="provider-request-one",
        transport_attempt_id="transport-attempt-one",
        retry_ordinal=0,
        consumer_id="aip-boundary",
        consumer_contract_version="1.0",
        provider_id=context_request.provider_id,
        model_id=context_request.model_id,
        endpoint_binding_id=context_request.endpoint_binding_id,
        strategy_version=context_request.strategy_version,
        sec02_decision_id=outcome.result.decision_id,
        sec02_result_digest=outcome.result.content_digest,
        sec02_result_ref="evidence://sec02/context-one",
        context_digest=outcome.result.context_digest or "",
        context_byte_count=outcome.result.context_byte_count or 0,
        readiness_result_id=context_request.readiness_result_id,
        readiness_manifest_digest=context_request.readiness_manifest_digest,
        classification_evidence_id=context_request.classification_evidence_id,
        classification_decision_id=classification["decision_id"],
        transport_policy_id=policy_value["policy_id"],
        transport_policy_version=policy_value["policy_version"],
        transport_policy_digest=policy_value["policy_digest"],
        endpoint_binding_digest=endpoint_value["binding_digest"],
        endpoint_binding_ref=endpoint_value["evidence_ref"],
        identity_binding_id="identity-binding",
        identity_evidence_id="identity-evidence",
        identity_evidence_digest="0" * 64,
        credential_resolution_id="credential-resolution",
        credential_evidence_id="credential-evidence",
        credential_evidence_digest="0" * 64,
        payload_classification_evidence_id="payload-classification-evidence",
        payload_classification_evidence_digest="0" * 64,
        payload_digest=hashlib.sha256(payload_bytes).hexdigest(),
        payload_byte_count=len(payload_bytes),
        media_type="application/json",
        method="POST",
        submission_evidence_id="submission-evidence",
        submission_evidence_digest="0" * 64,
    )
    identity = _attestation(request, "identity_binding", request.identity_evidence_id)
    credential_evidence = _attestation(
        request, "credential_resolution", request.credential_evidence_id
    )
    payload_classification = _attestation(
        request,
        "payload_classification",
        request.payload_classification_evidence_id,
    )
    submission = _attestation(request, "submission", request.submission_evidence_id)
    request = replace(
        request,
        identity_evidence_digest=attestation_digest(identity),
        credential_evidence_digest=attestation_digest(credential_evidence),
        payload_classification_evidence_digest=attestation_digest(payload_classification),
        submission_evidence_digest=attestation_digest(submission),
    )
    return {
        "request": request,
        "payload_bytes": payload_bytes,
        "context_bytes": outcome.context.value,
        "policy_path": policy_path,
        "endpoint_path": endpoint_path,
        "sec02_path": sec02_path,
        "submission": submission,
        "identity": identity,
        "credential_evidence": credential_evidence,
        "payload_classification": payload_classification,
    }


def fresh_buffers(
    case: dict[str, Any],
) -> tuple[TransientAIBytes, QualifiedAIContext, TransientAIBytes]:
    request: AITransportRequest = case["request"]
    return (
        TransientAIBytes(case["payload_bytes"]),
        QualifiedAIContext(
            bytearray(case["context_bytes"]), request.sec02_decision_id, request.context_digest
        ),
        TransientAIBytes(b"synthetic-transient-credential"),
    )


def rebind_transport_attestations(case: dict[str, Any]) -> None:
    """Issue fixture-authority attestations for the case's current request bindings."""

    request: AITransportRequest = case["request"]
    identity = _attestation(request, "identity_binding", request.identity_evidence_id)
    credential = _attestation(request, "credential_resolution", request.credential_evidence_id)
    classification = _attestation(
        request,
        "payload_classification",
        request.payload_classification_evidence_id,
    )
    submission = _attestation(request, "submission", request.submission_evidence_id)
    case["request"] = replace(
        request,
        identity_evidence_digest=attestation_digest(identity),
        credential_evidence_digest=attestation_digest(credential),
        payload_classification_evidence_digest=attestation_digest(classification),
        submission_evidence_digest=attestation_digest(submission),
    )
    case.update(
        identity=identity,
        credential_evidence=credential,
        payload_classification=classification,
        submission=submission,
    )
