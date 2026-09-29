"""Models describing a discovery acquisition run."""

from dataclasses import asdict, dataclass
from typing import Any

from smf.workload.models import Workload
from smf.workload.sanitization import sanitize_discovery_value


@dataclass(frozen=True)
class DiscoveryResult:
    provider: str
    source: str
    workloads: tuple[Workload, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", sanitize_discovery_value(self.source))

    @property
    def artifact_count(self) -> int:
        return sum(len(workload.artifacts) for workload in self.workloads)

    @property
    def dataset_count(self) -> int:
        return sum(len(workload.datasets) for workload in self.workloads)

    @property
    def relationship_count(self) -> int:
        return sum(len(workload.relationships) for workload in self.workloads)

    @property
    def unclassified_count(self) -> int:
        return sum(
            1
            for workload in self.workloads
            for artifact in workload.artifacts
            if artifact.kind.value == "other"
        )

    def to_dict(self) -> dict[str, Any]:
        sanitized = sanitize_discovery_value(asdict(self))
        assert isinstance(sanitized, dict)
        return sanitized
