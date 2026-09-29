import json
import os
import subprocess
import sys
from pathlib import Path


def _worktree_env() -> dict[str, str]:
    env = os.environ.copy()
    src = str(Path(__file__).resolve().parents[2] / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not existing else f"{src}{os.pathsep}{existing}"
    return env


def test_cli_discover_json(tmp_path: Path) -> None:
    source = tmp_path / "estate"
    source.mkdir()
    (source / "claims.sas").write_text("data work.claims; run;\n")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "discover",
            str(source),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=_worktree_env(),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["provider"] == "filesystem"
    assert len(payload["workloads"]) == 1
    assert payload["workloads"][0]["artifacts"][0]["kind"] == "sas_program"
    graph = payload["workloads"][0]["dependency_graph"]
    assert graph["metadata"]["complete_enterprise_graph"] is False
    assert graph["nodes"]


def test_cli_discover_can_write_model(tmp_path: Path) -> None:
    source = tmp_path / "estate"
    source.mkdir()
    (source / "claims.sas").write_text("data work.claims; run;\n")
    output = tmp_path / "discovery.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "discover",
            str(source),
            "--out",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=_worktree_env(),
    )

    assert result.returncode == 0
    assert output.exists()
    assert "Artifacts:" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert (
        payload["workloads"][0]["dependency_graph"]["metadata"]["basis"]
        == "canonical_relationship_projection"
    )


def test_cli_discover_publication_is_idempotent_and_collision_rejecting(tmp_path: Path) -> None:
    source = tmp_path / "estate"
    source.mkdir()
    sas = source / "claims.sas"
    sas.write_text("data work.claims; run;\n", encoding="utf-8")
    output = tmp_path / "discovery.json"
    command = [
        sys.executable,
        "-m",
        "smf.cli.main",
        "discover",
        str(source),
        "--out",
        str(output),
    ]

    first = subprocess.run(
        command, capture_output=True, text=True, check=False, env=_worktree_env()
    )
    canonical = output.read_bytes()
    retry = subprocess.run(
        command, capture_output=True, text=True, check=False, env=_worktree_env()
    )
    assert first.returncode == retry.returncode == 0
    assert output.read_bytes() == canonical

    sas.write_text("data work.changed; run;\n", encoding="utf-8")
    conflict = subprocess.run(
        command, capture_output=True, text=True, check=False, env=_worktree_env()
    )
    assert conflict.returncode == 1
    assert "different content" in conflict.stderr
    assert output.read_bytes() == canonical


def test_cli_discover_sanitizes_stdout_and_persisted_json(tmp_path: Path) -> None:
    source = tmp_path / "estate"
    source.mkdir()
    (source / "claims.sas").write_text("data work.claims; run;\n")
    (source / "schedule.jil").write_text(
        "insert_job: CLAIMS job_type: c\n"
        "command: DB_PASSWORD=cli-canary sas -sysin claims.sas "
        "--api-key output-canary\n"
    )
    output = tmp_path / "discovery.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "discover",
            str(source),
            "--json",
            "--out",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=_worktree_env(),
    )

    persisted = output.read_text()
    assert result.returncode == 0
    assert "cli-canary" not in result.stdout
    assert "output-canary" not in result.stdout
    assert "cli-canary" not in persisted
    assert "output-canary" not in persisted
    assert "claims.sas" in result.stdout
    assert "<redacted>" in persisted
