from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

ValidationStatus = Literal["passed", "warning", "failed", "human_review"]
CheckStatus = Literal["pass", "warning", "fail", "not_applicable"]


@dataclass(frozen=True)
class ValidationRequest:
    source_file: Path
    generated_file: Path
    target: str
    output_dir: Path = Path("out")
    minimum_confidence: float = 0.85


@dataclass(frozen=True)
class ValidationCheck:
    check_id: str
    name: str
    status: CheckStatus
    message: str
    weight: int = 1
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    source_file: str
    generated_file: str
    target: str
    status: ValidationStatus
    confidence: float
    requires_human_review: bool
    checks: list[ValidationCheck] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    output_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["checks"] = [check.to_dict() for check in self.checks]
        return payload
