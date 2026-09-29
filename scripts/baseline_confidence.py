#!/usr/bin/env python3
"""Run the bounded BASE-01 confidence gate and emit revision-bound evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_TESTS = [
    path.relative_to(ROOT).as_posix()
    for path in sorted((ROOT / "tests" / "unit").glob("test_baseline_*.py"))
]
COMMANDS = [
    [sys.executable, "-m", "pytest", *BASELINE_TESTS],
    [sys.executable, "-m", "pytest", "tests/integration/test_cli_baseline_acquisition.py"],
    [sys.executable, "-m", "pytest", "tests/unit/test_readiness_engine.py"],
    [sys.executable, "-m", "pytest", "tests/unit/test_corpus_output_evidence.py"],
    [sys.executable, "-m", "pytest", "tests/unit/test_corpus_regression_evidence.py"],
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def public_corpus() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): digest(path)
        for path in sorted((ROOT / "tests" / "corpus").rglob("*"))
        if path.is_file()
    }


def main() -> int:
    before = public_corpus()
    results = []
    success = True
    for command in COMMANDS:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        results.append({"command": command, "return_code": completed.returncode})
        success = success and completed.returncode == 0
    after = public_corpus()
    corpus_unchanged = before == after
    success = success and corpus_unchanged
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    artifacts = {}
    for pattern in (
        "src/smf/baseline/*.py",
        "src/smf/schemas/baseline-*.json",
        "docs/BASELINE_ACQUISITION.md",
        "docs/BASE-01_ACCEPTANCE.md",
    ):
        for path in sorted(ROOT.glob(pattern)):
            artifacts[path.relative_to(ROOT).as_posix()] = digest(path)
    report = {
        "schema_version": "1.0",
        "gate": "BASE-01-baseline-confidence",
        "repository_revision": revision,
        "observed_at": datetime.now(UTC).isoformat(),
        "commands": results,
        "public_corpus_unchanged": corpus_unchanged,
        "artifacts": artifacts,
        "result": "passed" if success else "failed",
        "claims": {
            "contract_verified": success,
            "real_sas_access_verified": False,
            "validated": False,
            "parity_passed": False,
            "foundation_complete": False,
        },
    }
    destination = ROOT / "out" / "confidence" / "BASE-01.acceptance.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(destination), **report}, indent=2, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
