from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

ConversionTarget = Literal["pyspark", "sparksql"]
ConversionRoute = Literal["deterministic", "ai_assisted", "human_supervised"]


@dataclass(frozen=True)
class ConversionRequest:
    source_file: Path
    target: ConversionTarget = "pyspark"
    output_dir: Path = Path("out")
    provider: str = "auto"
    model: str | None = None
    workload_id: str | None = None
    source_artifact_id: str | None = None
    run_id: str | None = None
    readiness_attempt_id: str | None = None
    conversion_attempt_id: str | None = None
    readiness_manifest: Path | None = None
    readiness_policy_digest: str | None = None
    deployment_config: Path | None = None
    temporal_policy: Path | None = None
    value_compatibility_policy: Path | None = None


@dataclass
class ConversionResult:
    source_file: str
    target: str
    route: str
    provider: str
    status: str
    output_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
