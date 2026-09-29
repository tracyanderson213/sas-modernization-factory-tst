from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class DependencySummary:
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    macros_defined: list[str] = field(default_factory=list)
    macros_invoked: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScoreReason:
    points: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AssessmentResult:
    workload_id: str
    source_file: str
    complexity: str
    complexity_score: int
    automation_route: str
    confidence: float
    sas_constructs: list[str]
    dependencies: DependencySummary
    risk_factors: list[str]
    unsupported_constructs: list[str]
    recommended_validation_level: int
    score_breakdown: list[ScoreReason]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload
