"""Provider boundary for automatic workload discovery."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from smf.workload.models import Workload


@dataclass(frozen=True)
class DiscoveryRequest:
    source: Path
    namespace: str = "default"
    logical_name: str | None = None
    source_locator: str | None = None


class DiscoveryProvider(ABC):
    """A source-specific adapter that produces the canonical workload model."""

    @abstractmethod
    def discover(self, request: DiscoveryRequest) -> tuple[Workload, ...]:
        """Discover candidate workloads and normalize them into canonical models."""
