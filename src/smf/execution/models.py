from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

ExecutionStatus = Literal["succeeded", "failed", "blocked", "submitted"]


@dataclass(frozen=True)
class ExecutionRequest:
    source_file: Path
    generated_file: Path
    target: str
    provider: str = "local"
    output_dir: Path = Path("out")
    timeout_seconds: int = 120
    allow_writes: bool = False
    run_id: str = "standalone"
    attempt_id: str = "1"
    workload_id: str | None = None


@dataclass
class ExecutionResult:
    source_file: str
    generated_file: str
    target: str
    provider: str
    status: ExecutionStatus
    duration_seconds: float
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    run_id: str | None = None
    workspace_host: str | None = None
    warnings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    output_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
