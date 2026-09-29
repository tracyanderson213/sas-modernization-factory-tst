import json
import subprocess
import sys
from pathlib import Path


def test_cli_assess_json() -> None:
    source = Path("examples/simple/example.sas")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "assess",
            str(source),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0

    payload = json.loads(result.stdout)

    assert payload["workload_id"].startswith("SMF-")
    assert payload["complexity"] == "simple"
    assert payload["automation_route"] == "deterministic"
    assert payload["dependencies"]["inputs"] == ["work.transactions"]


def test_cli_explain() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "assess",
            "examples/simple/example.sas",
            "--explain",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Assessment Explanation" in result.stdout
    assert "Score:" in result.stdout
    assert "Risk Factors:" in result.stdout


def test_cli_missing_file_returns_error() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "assess",
            "does-not-exist.sas",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "ERROR:" in result.stderr
