from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GateResult:
    name: str
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def passed(self) -> bool:
        return self.returncode == 0


def run_gates(worktree: Path) -> tuple[GateResult, ...]:
    commands = (
        ("format", ["make", "format"]),
        ("verify", ["make", "verify"]),
        ("discovery-confidence", ["./scripts/test-discovery-confidence.sh"]),
    )
    results: list[GateResult] = []
    for name, command in commands:
        completed = subprocess.run(
            command, cwd=worktree, text=True, capture_output=True, check=False
        )
        results.append(GateResult(name, completed.returncode, completed.stdout, completed.stderr))
        if completed.returncode != 0:
            break
    return tuple(results)
