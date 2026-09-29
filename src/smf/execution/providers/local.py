from __future__ import annotations

import subprocess
import sys
import time

from smf.execution.models import ExecutionRequest, ExecutionResult, ExecutionStatus
from smf.execution.providers.base import ExecutionProvider


def _to_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


class LocalExecutionProvider(ExecutionProvider):
    """Local process execution for engineering tests only."""

    name = "local"

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if request.target.lower() not in {"pyspark", "python"}:
            return ExecutionResult(
                source_file=str(request.source_file),
                generated_file=str(request.generated_file),
                target=request.target,
                provider=self.name,
                status="blocked",
                duration_seconds=0.0,
                stderr="Local provider currently supports Python/PySpark artifacts only.",
                warnings=[
                    (
                        "Local execution is an engineering validation provider, "
                        "not production runtime."
                    )
                ],
            )

        started = time.perf_counter()
        try:
            completed = subprocess.run(
                [sys.executable, str(request.generated_file)],
                check=False,
                capture_output=True,
                text=True,
                timeout=request.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - started
            return ExecutionResult(
                source_file=str(request.source_file),
                generated_file=str(request.generated_file),
                target=request.target,
                provider=self.name,
                status="failed",
                duration_seconds=round(duration, 3),
                stdout=_to_text(exc.stdout),
                stderr=_to_text(exc.stderr) or "Execution timed out.",
                warnings=["Execution exceeded configured timeout."],
            )

        duration = time.perf_counter() - started

        status: ExecutionStatus
        status = "succeeded" if completed.returncode == 0 else "failed"

        return ExecutionResult(
            source_file=str(request.source_file),
            generated_file=str(request.generated_file),
            target=request.target,
            provider=self.name,
            status=status,
            duration_seconds=round(duration, 3),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            evidence={
                "command": [sys.executable, str(request.generated_file)],
                "timeout_seconds": request.timeout_seconds,
            },
            warnings=[
                (
                    "Local execution is for engineering validation only and does "
                    "not prove Databricks compatibility."
                )
            ],
        )
