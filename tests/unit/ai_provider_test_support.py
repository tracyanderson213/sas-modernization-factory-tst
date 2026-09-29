from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.ai.models import (
    AIConfigurationState,
    AIOperation,
    AIProviderRequest,
    AITarget,
    TransientAIProviderBytes,
)
from smf.ai.prerequisites import AIProviderPrerequisites, AIProviderVerifierConfiguration
from smf.security.ai_manifest import write_ai_context_result
from smf.security.ai_models import AIAdmissionState, AIContextAdmissionResult, AIContextRequest
from smf.security.ai_policy import ai_digest, canonical_ai_json

CONTEXT = b"data eligible; set source; run;"
SEC02_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
AUTHORITY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
TRUSTED_VERIFIER_CONFIGURATION = AIProviderVerifierConfiguration(
    sec02_keys={"sec02-authority-key": SEC02_KEY.public_key()},
    authority_keys={"provider-authority-key": AUTHORITY_KEY.public_key()},
)


def _sec02_result(request: AIProviderRequest) -> AIContextAdmissionResult:
    context_request = AIContextRequest(
        schema_version="1.0",
        client_id=request.client_id,
        deployment_id=request.deployment_id,
        environment_id=request.environment_id,
        workload_id=request.workload_id,
        workload_digest=request.workload_digest,
        boundary_id=request.boundary_id,
        subject_id=request.subject_id,
        source_closure_digest=request.source_closure_digest,
        run_id=request.run_id,
        attempt_id=request.workflow_attempt_id,
        consumer_id=request.consumer_id,
        consumer_contract_version=request.consumer_contract_version,
        strategy_version=request.strategy_version,
        readiness_result_id="readiness-one",
        readiness_manifest_digest=hashlib.sha256(b"readiness").hexdigest(),
        context_policy_id="context-policy-one",
        context_policy_version="1.0",
        context_policy_digest=hashlib.sha256(b"context-policy").hexdigest(),
        classification_policy_id="classification-policy-one",
        classification_policy_version="1.0",
        classification_policy_digest=hashlib.sha256(b"classification-policy").hexdigest(),
        provider_id=request.provider_id,
        model_id=request.model_id,
        endpoint_binding_id=request.endpoint_binding_id,
        retention_policy_ref="retention-one",
        access_policy_ref="access-one",
        classification_evidence_id="classification-one",
        classification_evidence_digest=hashlib.sha256(b"classification").hexdigest(),
        requested_artifact_ids=request.source_artifact_ids,
        requested_fields=("source",),
    )
    decision_id = "ai-" + ai_digest(
        {"contract": "smf-ai-context-admission-v1", "request": context_request.safe_bindings()}
    )
    result = AIContextAdmissionResult(
        schema_version="1.0",
        decision_id=decision_id,
        request=context_request.safe_bindings(),
        state=AIAdmissionState.QUALIFIED_OFFLINE,
        blocker_codes=(),
        checks=(
            {"check_id": "readiness_replayed", "status": "pass"},
            {"check_id": "classification_verified", "status": "pass"},
            {"check_id": "source_bytes_reverified", "status": "pass"},
            {"check_id": "protected_data_scan", "status": "pass"},
            {"check_id": "allowlist_intersection", "status": "pass"},
        ),
        evidence_refs=(
            "readiness-one",
            "classification-one",
            "classification-decision-one",
        ),
        permitted_artifact_ids=request.source_artifact_ids,
        permitted_fields=("source",),
        context_digest=request.context_digest,
        context_byte_count=request.context_byte_count,
        terminal_disposition="context_qualified_offline",
        context_qualified=True,
    )
    unsigned = result.to_dict()
    unsigned["content_digest"] = ""
    return replace(result, content_digest=ai_digest(unsigned))


def make_provider_request(**changes: object) -> AIProviderRequest:
    digest = hashlib.sha256
    request = AIProviderRequest(
        schema_version="1.0",
        operation=AIOperation.CONVERT,
        client_id="client-one",
        deployment_id="deployment-one",
        environment_id="environment-one",
        workload_id="workload-one",
        workload_digest=digest(b"workload").hexdigest(),
        boundary_id="boundary-one",
        subject_id="main-sas",
        source_closure_digest=digest(b"source-closure").hexdigest(),
        source_artifact_ids=("main-sas",),
        run_id="run-one",
        workflow_attempt_id="workflow-attempt-one",
        provider_request_id="provider-request-one",
        provider_attempt_id="provider-attempt-one",
        retry_ordinal=0,
        target=AITarget.DATABRICKS_PYSPARK,
        consumer_id="conversion-engine",
        consumer_contract_version="1.0",
        strategy_id="strategy-one",
        strategy_version="1.0",
        strategy_digest=digest(b"strategy").hexdigest(),
        provider_id="mock",
        model_id="mock-model-v1",
        endpoint_binding_id="offline-no-network",
        sec02_decision_id="sec02-decision-one",
        sec02_result_ref="evidence://security/sec02/result-one",
        sec02_result_digest=digest(b"sec02-result").hexdigest(),
        context_digest=digest(CONTEXT).hexdigest(),
        context_byte_count=len(CONTEXT),
        prompt_policy_ref="evidence://prompt/policy-one",
        prompt_policy_digest=digest(b"prompt-policy").hexdigest(),
        prompt_template_ref="evidence://prompt/template-one",
        prompt_template_digest=digest(b"prompt-template").hexdigest(),
        transport_policy_ref="evidence://transport/policy-one",
        transport_policy_digest=digest(b"transport-policy").hexdigest(),
        configuration_ref="evidence://configuration/provider-one",
        configuration_digest=digest(b"configuration").hexdigest(),
        configuration_state=AIConfigurationState.VERIFIED,
        retention_policy_ref="evidence://governance/retention-one",
        retention_policy_digest=digest(b"retention-policy").hexdigest(),
        access_policy_ref="evidence://governance/access-one",
        access_policy_digest=digest(b"access-policy").hexdigest(),
    )
    request = replace(request, **changes)
    sec02 = _sec02_result(request)
    request = replace(
        request,
        sec02_decision_id=sec02.decision_id,
        sec02_result_digest=sec02.content_digest,
    )
    return request


def provider_input(value: bytes = CONTEXT) -> TransientAIProviderBytes:
    return TransientAIProviderBytes(value)


def write_trusted_prerequisites(
    root: Path,
    request: AIProviderRequest,
    *,
    sec02_key: Ed25519PrivateKey = SEC02_KEY,
    sec02_key_id: str = "sec02-authority-key",
    authority_key: Ed25519PrivateKey = AUTHORITY_KEY,
    authority_key_id: str = "provider-authority-key",
    states: dict[str, str] | None = None,
    expires_at: datetime | None = None,
) -> AIProviderPrerequisites:
    sec02 = _sec02_result(request)
    if (
        sec02.decision_id != request.sec02_decision_id
        or sec02.content_digest != request.sec02_result_digest
    ):
        raise ValueError("Test request is not bound to its SEC-02 fixture")
    sec02_path = write_ai_context_result(
        root / "sec02",
        sec02,
        signing_key=sec02_key,
        key_id=sec02_key_id,
    )
    slots = {
        "prompt_policy": (request.prompt_policy_ref, request.prompt_policy_digest),
        "prompt_template": (request.prompt_template_ref, request.prompt_template_digest),
        "transport_policy": (request.transport_policy_ref, request.transport_policy_digest),
        "configuration": (request.configuration_ref, request.configuration_digest),
        "retention_policy": (request.retention_policy_ref, request.retention_policy_digest),
        "access_policy": (request.access_policy_ref, request.access_policy_digest),
    }
    current = datetime.now(UTC)
    paths: dict[str, Path] = {}
    for kind, (evidence_ref, evidence_digest) in slots.items():
        payload = {
            "schema_version": "1.0",
            "kind": kind,
            "evidence_ref": evidence_ref,
            "evidence_digest": evidence_digest,
            "request_digest": request.request_digest,
            "state": (states or {}).get(kind, "active"),
            "issued_at": (current - timedelta(minutes=1)).isoformat(),
            "expires_at": (expires_at or current + timedelta(hours=1)).isoformat(),
        }
        payload["proof"] = {
            "algorithm": "ed25519",
            "key_id": authority_key_id,
            "value": base64.b64encode(authority_key.sign(canonical_ai_json(payload))).decode(
                "ascii"
            ),
        }
        path = root / "provider-prerequisites" / f"{kind}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        paths[kind] = path
    return AIProviderPrerequisites(
        sec02_result_path=sec02_path,
        evidence_paths=paths,
    )
