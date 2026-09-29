from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from smf.discovery import discover_source


def test_architecture_review_cli_publishes_blocked_offline_packet(tmp_path: Path) -> None:
    root = Path.cwd()
    discovery = discover_source(Path("examples/simple"), provider="filesystem").to_dict()
    discovery_path = tmp_path / "discovery.json"
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    workload = discovery["workloads"][0]
    entry = next(item for item in workload["artifacts"] if item["kind"] == "sas_program")
    boundary = next(
        item for item in workload["boundaries"] if entry["artifact_id"] in item["artifact_ids"]
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "architecture-review",
            "assemble",
            str(root / "examples/simple/example.sas"),
            "--discovery-manifest",
            str(discovery_path),
            "--repo-root",
            "/",
            "--factory-config",
            str(root / "deployments/humana/factory.yaml"),
            "--threat-model",
            str(root / "docs/architecture/security-threat-model.yaml"),
            "--requirements",
            str(root / "competition/requirements.yaml"),
            "--workload-id",
            workload["workload_id"],
            "--subject-id",
            entry["artifact_id"],
            "--boundary-id",
            boundary["boundary_id"],
            "--run-id",
            "run-1",
            "--attempt-id",
            "attempt-1",
            "--assessed-revision",
            "rev-1",
            "--out",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["terminal_disposition"] == "blocked"
    assert payload["authorizes_execution"] is False
    assert payload["shared_projection_published"] is False
    assert Path(payload["packet_path"]).is_file()


def test_architecture_review_cli_rejects_ambiguous_caller_identity(tmp_path: Path) -> None:
    root = Path.cwd()
    discovery = discover_source(Path("examples/simple"), provider="filesystem").to_dict()
    discovery_path = tmp_path / "discovery.json"
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "architecture-review",
            "assemble",
            str(root / "examples/simple/example.sas"),
            "--discovery-manifest",
            str(discovery_path),
            "--repo-root",
            "/",
            "--factory-config",
            str(root / "deployments/humana/factory.yaml"),
            "--threat-model",
            str(root / "docs/architecture/security-threat-model.yaml"),
            "--requirements",
            str(root / "competition/requirements.yaml"),
            "--workload-id",
            "caller-invented",
            "--subject-id",
            "caller-invented",
            "--boundary-id",
            "caller-invented",
            "--run-id",
            "run-1",
            "--attempt-id",
            "attempt-1",
            "--assessed-revision",
            "rev-1",
            "--out",
            str(tmp_path / "out"),
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    assert result.returncode == 1
    assert "Canonical workload identity" in result.stderr


def test_architecture_review_schemas_are_packaged_byte_for_byte() -> None:
    from importlib.resources import files

    for name in (
        "architecture-review-packet.schema.json",
        "architecture-review-projection.schema.json",
    ):
        assert (Path("schemas") / name).read_bytes() == files("smf.schemas").joinpath(
            name
        ).read_bytes()
