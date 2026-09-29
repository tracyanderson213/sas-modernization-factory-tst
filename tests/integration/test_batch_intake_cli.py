from __future__ import annotations

import json
from pathlib import Path

from tests.unit.batch_intake_support import make_manifest, make_policy

from smf.cli.main import main


def test_batch_intake_cli_publishes_recoverable_result(tmp_path: Path, monkeypatch, capsys) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    manifest_path = tmp_path / "manifest.json"
    policy_path = tmp_path / "policy.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    policy_path.write_text(json.dumps(policy.payload), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "smf",
            "intake-batch",
            str(manifest_path),
            "--policy",
            str(policy_path),
            "--source-root",
            str(source),
            "--run-id",
            "run-1",
            "--attempt-id",
            "attempt-1",
            "--out",
            str(tmp_path / "out"),
            "--json",
        ],
    )
    assert main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["disposition"] == "admitted"
    assert output["authorizes_execution"] is False
    assert Path(output["result_path"]).is_file()
