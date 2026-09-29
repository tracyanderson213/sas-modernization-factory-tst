from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from tests.unit.ai_provider_test_support import (
    TRUSTED_VERIFIER_CONFIGURATION,
    make_provider_request,
    provider_input,
    write_trusted_prerequisites,
)

from smf.ai.mock import DeterministicMockAIProvider, MockScenario
from smf.ai.models import (
    AIConfigurationState,
    AIEvidenceClass,
    AIFinishReason,
    AIProviderOutcome,
    AIProviderRequest,
    AIProviderResponse,
    AIProviderState,
)
from smf.ai.provider import AIProvider, _invoke_ai_provider, invoke_ai_provider


def _invoke_trusted(
    tmp_path: Path,
    request: AIProviderRequest,
    provider: AIProvider,
    *,
    transient=None,  # type: ignore[no-untyped-def]
) -> AIProviderOutcome:
    return _invoke_ai_provider(
        request,
        transient or provider_input(),
        provider,
        prerequisites=write_trusted_prerequisites(tmp_path / "trusted", request),
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )


def test_mock_success_is_synthetic_and_never_asserts_downstream_lifecycle(
    tmp_path: Path,
) -> None:
    request = make_provider_request()
    outcome = _invoke_trusted(tmp_path, request, DeterministicMockAIProvider())
    assert outcome.result.state is AIProviderState.SUCCEEDED
    assert outcome.result.evidence_class is AIEvidenceClass.SYNTHETIC_CONTRACT
    assert outcome.output is not None
    assert not any(
        (
            outcome.result.generated,
            outcome.result.executed,
            outcome.result.validated,
            outcome.result.parity_passed,
            outcome.result.certified,
            outcome.result.human_approved,
        )
    )


@pytest.mark.parametrize(
    ("scenario", "state"),
    [
        (MockScenario.EMPTY, AIProviderState.FAILED),
        (MockScenario.MALFORMED, AIProviderState.FAILED),
        (MockScenario.TIMEOUT, AIProviderState.TIMED_OUT),
        (MockScenario.CANCELLED, AIProviderState.CANCELLED),
        (MockScenario.REFUSAL, AIProviderState.UNSUPPORTED),
        (MockScenario.UNSUPPORTED, AIProviderState.UNSUPPORTED),
        (MockScenario.HOSTILE, AIProviderState.FAILED),
    ],
)
def test_mock_negative_scenarios_fail_predictably(
    tmp_path: Path, scenario: MockScenario, state: AIProviderState
) -> None:
    request = make_provider_request()
    outcome = _invoke_trusted(tmp_path, request, DeterministicMockAIProvider(scenario))
    assert outcome.result.state is state
    assert outcome.output is None
    assert outcome.result.response_digest is None


@pytest.mark.parametrize(
    ("configuration", "state"),
    [
        (AIConfigurationState.MISSING, AIProviderState.BLOCKED_MISSING),
        (AIConfigurationState.PENDING, AIProviderState.BLOCKED_PENDING),
        (AIConfigurationState.DENIED, AIProviderState.DENIED),
    ],
)
def test_missing_pending_and_denied_are_distinct_without_invocation(
    configuration: AIConfigurationState, state: AIProviderState
) -> None:
    request = replace(make_provider_request(), configuration_state=configuration)
    outcome = invoke_ai_provider(request, provider_input(), DeterministicMockAIProvider())
    assert outcome.result.state is state
    assert outcome.result.provider_invoked is False


def test_mutated_or_wrong_context_is_rejected_before_invocation() -> None:
    outcome = invoke_ai_provider(
        make_provider_request(),
        provider_input(b"data changed; run;"),
        DeterministicMockAIProvider(),
    )
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert outcome.result.blocker_codes == ("context_binding_mismatch",)


def test_nonconvertible_context_cannot_succeed() -> None:
    context = b"/* configuration only */"
    request = replace(
        make_provider_request(),
        context_digest=hashlib.sha256(context).hexdigest(),
        context_byte_count=len(context),
    )
    outcome = invoke_ai_provider(request, provider_input(context), DeterministicMockAIProvider())
    assert outcome.result.state is AIProviderState.FAILED
    assert outcome.result.blocker_codes == ("nonconvertible_subject",)


@pytest.mark.parametrize(
    "context",
    [
        b"/* harmless note; data fake; run; */",
        b"* harmless note with proc sql;",
        b'%let note="data fake; run;";',
        b"   \n\t  ",
        b'%include "missing.sas";',
    ],
)
def test_nonexecutable_sas_text_cannot_invoke_provider(context: bytes) -> None:
    request = replace(
        make_provider_request(),
        context_digest=hashlib.sha256(context).hexdigest(),
        context_byte_count=len(context),
    )
    provider = CountingProvider()
    outcome = invoke_ai_provider(request, provider_input(context), provider)
    assert outcome.result.state is AIProviderState.FAILED
    assert outcome.result.blocker_codes == ("nonconvertible_subject",)
    assert provider.invocations == 0


class CountingProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.SYNTHETIC_CONTRACT

    def __init__(self) -> None:
        self.invocations = 0

    def invoke(self, request: object, transient_input: bytes) -> AIProviderResponse:
        self.invocations += 1
        return AIProviderResponse(b"select 1", AIFinishReason.STOP, 1, 1)


class UnexpectedFailureProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.SYNTHETIC_CONTRACT

    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def invoke(self, request: object, transient_input: bytes) -> AIProviderResponse:
        raise self.failure


@pytest.mark.parametrize("failure", [RuntimeError("sdk down"), OSError("socket closed")])
def test_unexpected_provider_exceptions_become_sanitized_terminal_failures(
    tmp_path: Path,
    failure: Exception,
) -> None:
    transient = provider_input()
    request = make_provider_request()
    outcome = _invoke_trusted(
        tmp_path,
        request,
        UnexpectedFailureProvider(failure),
        transient=transient,
    )
    assert outcome.result.state is AIProviderState.FAILED
    assert outcome.result.blocker_codes == ("provider_failure",)
    assert outcome.result.provider_invoked is True
    assert outcome.output is None
    assert set(transient.value) == {0}


class SelfAssertedOperationalProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.OPERATIONAL_VERIFIED

    def invoke(self, request: object, transient_input: bytes) -> AIProviderResponse:
        raise AssertionError("self-asserted operational provider must not be invoked")


def test_self_asserted_operational_evidence_cannot_manufacture_success() -> None:
    outcome = invoke_ai_provider(
        make_provider_request(), provider_input(), SelfAssertedOperationalProvider()
    )
    assert outcome.result.state is AIProviderState.BLOCKED_MISSING
    assert outcome.result.blocker_codes == ("operational_provider_verifier_unavailable",)


class UnknownFinishProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.SYNTHETIC_CONTRACT

    def invoke(self, request: object, transient_input: bytes) -> AIProviderResponse:
        return AIProviderResponse(b"select 1", "suceeded", 1, 1)  # type: ignore[arg-type]


def test_malformed_finish_reason_cannot_bypass_result_validation(tmp_path: Path) -> None:
    request = make_provider_request()
    outcome = _invoke_trusted(tmp_path, request, UnknownFinishProvider())
    assert outcome.result.state is AIProviderState.FAILED


def test_direct_invocation_without_trusted_prerequisites_is_blocked() -> None:
    outcome = invoke_ai_provider(
        make_provider_request(), provider_input(), DeterministicMockAIProvider()
    )
    assert outcome.result.state is AIProviderState.BLOCKED_MISSING
    assert outcome.result.provider_invoked is False


def test_response_model_rejects_negative_usage() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        AIProviderResponse(b"select 1", AIFinishReason.STOP, -1, 1)
