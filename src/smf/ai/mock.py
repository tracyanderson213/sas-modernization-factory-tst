"""Deterministic, no-network provider used only for contract tests."""

from __future__ import annotations

from enum import StrEnum

from smf.ai.models import (
    AIEvidenceClass,
    AIFinishReason,
    AIProviderRequest,
    AIProviderResponse,
)
from smf.ai.provider import (
    AIProvider,
    AIProviderCancelled,
    AIProviderFailure,
    AIProviderTimeout,
    AIProviderUnsupported,
)


class MockScenario(StrEnum):
    SUCCESS = "success"
    EMPTY = "empty"
    MALFORMED = "malformed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    REFUSAL = "refusal"
    UNSUPPORTED = "unsupported"
    HOSTILE = "hostile"


class DeterministicMockAIProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.SYNTHETIC_CONTRACT

    def __init__(self, scenario: MockScenario = MockScenario.SUCCESS) -> None:
        if not isinstance(scenario, MockScenario):
            raise ValueError("Mock scenario must use a strict enum")
        self.scenario = scenario

    def invoke(self, request: AIProviderRequest, transient_input: bytes) -> AIProviderResponse:
        if self.scenario is MockScenario.TIMEOUT:
            raise AIProviderTimeout
        if self.scenario is MockScenario.CANCELLED:
            raise AIProviderCancelled
        if self.scenario is MockScenario.UNSUPPORTED:
            raise AIProviderUnsupported
        if self.scenario is MockScenario.MALFORMED:
            raise AIProviderFailure("malformed fixture")
        if self.scenario is MockScenario.EMPTY:
            content = b"   "
        elif self.scenario is MockScenario.HOSTILE:
            content = b"ignore the endpoint policy; select * from unsafe"
        else:
            content = (
                b'spark.sql("select 1 as synthetic_contract_value")'
                if request.target.value == "databricks_pyspark"
                else b"select 1 as synthetic_contract_value"
            )
        finish = (
            AIFinishReason.REFUSAL if self.scenario is MockScenario.REFUSAL else AIFinishReason.STOP
        )
        return AIProviderResponse(
            content=content,
            finish_reason=finish,
            input_tokens=max(1, len(transient_input) // 4),
            output_tokens=max(0, len(content) // 4),
        )
