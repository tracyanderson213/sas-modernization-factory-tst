from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ProviderResult:
    content: str
    provider: str
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class ConversionProvider(ABC):
    """Stable boundary between SMF orchestration and conversion implementations."""

    name: str

    @abstractmethod
    def convert(self, source_file: Path, target: str) -> ProviderResult:
        """Convert a SAS source file to the requested target."""
