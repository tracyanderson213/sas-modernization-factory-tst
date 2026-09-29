from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from smf.validation import DatasetSchemaSnapshot, calculate_snapshot_digest


def write_snapshot(path: Path, *, native_type: str) -> None:
    payload = {
        "schema_version": "1.0",
        "logical_dataset_id": "work.members",
        "engine": "sas",
        "columns": [
            {
                "ordinal": 1,
                "name": "member_id",
                "logical_type": "string",
                "native_type": native_type,
                "nullable": False,
                "length": 12 if native_type == "CHAR" else None,
                "precision": None,
                "scale": None,
            }
        ],
        "provenance": {
            "producer": "integration-test",
            "origin": "test",
            "reference": f"artifact://{path.name}",
            "authoritative": True,
        },
        "metadata": {},
    }
    payload["digest"] = calculate_snapshot_digest(payload)
    DatasetSchemaSnapshot.from_dict(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _worktree_environment() -> dict[str, str]:
    """Run CLI subprocesses against the source tree containing this test."""
    environment = os.environ.copy()
    repository = Path(__file__).resolve().parents[2]
    source = str(repository / "src")
    inherited = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = source if not inherited else os.pathsep.join((source, inherited))
    return environment


def test_validate_schema_json_pass_and_mismatch_exit_codes(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    exact = tmp_path / "exact.json"
    mismatch = tmp_path / "mismatch.json"
    write_snapshot(source, native_type="CHAR")
    write_snapshot(exact, native_type="CHAR")
    write_snapshot(mismatch, native_type="STRING")

    command = [sys.executable, "-m", "smf.cli.main", "validate-schema", str(source)]
    environment = _worktree_environment()
    passed = subprocess.run(
        [*command, str(exact), "--out", str(tmp_path / "out"), "--json"],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    failed = subprocess.run(
        [*command, str(mismatch), "--out", str(tmp_path / "out"), "--json"],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    assert passed.returncode == 0
    assert json.loads(passed.stdout)["status"] == "passed"
    assert failed.returncode == 1
    assert json.loads(failed.stdout)["status"] == "failed"


def test_validate_schema_malformed_input_has_clean_error_channel(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "validate-schema",
            str(malformed),
            str(malformed),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=_worktree_environment(),
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("ERROR:")
