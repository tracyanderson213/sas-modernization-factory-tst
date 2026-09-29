from __future__ import annotations

from pathlib import Path

from smf.ai import AIProvider as CommonAIProvider
from smf.ai import AIProviderRequest, AIProviderResult
from smf.conversion.providers.base import ConversionProvider, ProviderResult


class AIProvider(ConversionProvider):
    """Base class for future enterprise-approved AI conversion providers."""

    def convert(self, source_file: Path, target: str) -> ProviderResult:
        raise NotImplementedError(
            f"{self.name} provider is scaffolded but not enabled in Conversion Engine v1"
        )


class AnthropicProvider(AIProvider):
    name = "anthropic"


class OpenAIProvider(AIProvider):
    name = "openai"


__all__ = [
    "AIProvider",
    "AIProviderRequest",
    "AIProviderResult",
    "AnthropicProvider",
    "CommonAIProvider",
    "OpenAIProvider",
]
