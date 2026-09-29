from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.ai_provider_test_support import (
    TRUSTED_VERIFIER_CONFIGURATION,
    make_provider_request,
    provider_input,
    write_trusted_prerequisites,
)

from smf.ai.manifest import (
    _execute_provider_attempt,
    execute_provider_attempt,
    provider_evidence_dir,
)
from smf.ai.mock import DeterministicMockAIProvider
from smf.ai.models import (
    AIEvidenceClass,
    AIFinishReason,
    AIProviderRequest,
    AIProviderResponse,
    AIProviderState,
)
from smf.ai.provider import AIProvider, _invoke_ai_provider, invoke_ai_provider

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEYS = {"test-key": KEY.public_key()}


def test_mock_contract_makes_no_network_call(tmp_path: Path) -> None:
    request = make_provider_request()
    with patch.object(socket, "socket", side_effect=AssertionError("network used")):
        outcome = _invoke_ai_provider(
            request,
            provider_input(),
            DeterministicMockAIProvider(),
            prerequisites=write_trusted_prerequisites(tmp_path / "trusted", request),
            verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
        )
    assert outcome.result.state is AIProviderState.SUCCEEDED
    assert outcome.result.evidence_class is AIEvidenceClass.SYNTHETIC_CONTRACT


class ProtectedResponseProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.SYNTHETIC_CONTRACT

    def invoke(self, request: AIProviderRequest, transient_input: bytes) -> AIProviderResponse:
        return AIProviderResponse(
            b"select 1; password=hunter2 patient@example.com",
            AIFinishReason.STOP,
            1,
            1,
        )


def test_protected_response_is_not_persisted_or_hashed(tmp_path: Path) -> None:
    request = make_provider_request()
    outcome = _execute_provider_attempt(
        request,
        provider_input(),
        ProtectedResponseProvider(),
        evidence_root=tmp_path,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
        prerequisites=write_trusted_prerequisites(tmp_path / "trusted", request),
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )
    assert outcome.result.state is AIProviderState.FAILED
    evidence = (provider_evidence_dir(tmp_path, request) / "result.json").read_text()
    canary = "patient@example.com"
    assert canary not in evidence
    assert hashlib.sha256(canary.encode()).hexdigest() not in evidence


def test_protected_input_creates_no_durable_provider_evidence(tmp_path: Path) -> None:
    context = b"data eligible; password=hunter2; run;"
    request = replace(
        make_provider_request(),
        context_digest=hashlib.sha256(context).hexdigest(),
        context_byte_count=len(context),
    )
    outcome = execute_provider_attempt(
        request,
        provider_input(context),
        DeterministicMockAIProvider(),
        evidence_root=tmp_path,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
    )
    assert outcome.result.blocker_codes == ("protected_data_detected",)
    assert not provider_evidence_dir(tmp_path, request).exists()


def test_cross_request_advice_and_provider_binding_fail_closed() -> None:
    request = replace(make_provider_request(), provider_id="other-provider")
    outcome = invoke_ai_provider(request, provider_input(), DeterministicMockAIProvider())
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert outcome.result.provider_invoked is False


def test_telemetry_keeps_provider_success_separate_from_generation_and_parity(
    tmp_path: Path,
) -> None:
    request = make_provider_request()
    _execute_provider_attempt(
        request,
        provider_input(),
        DeterministicMockAIProvider(),
        evidence_root=tmp_path,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
        prerequisites=write_trusted_prerequisites(tmp_path / "trusted", request),
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )
    event = json.loads((provider_evidence_dir(tmp_path, request) / "telemetry.json").read_text())
    assert event["outcome"] == "succeeded"
    assert event["evidence_class"] == "synthetic_contract"
    assert event["provider_invoked"] is True
    assert event["generated"] is False
    assert event["executed"] is False
    assert event["validated"] is False
    assert event["parity_passed"] is False
