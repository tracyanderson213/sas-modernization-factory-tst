from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml
from pilot_test_support import build_inventory, build_policy

from smf.pilot import policy_digest


def test_select_pilot_cli_persists_qualified_contract(tmp_path: Path) -> None:
    inventory = build_inventory(tmp_path)
    policy = build_policy()
    policy["policy_digest"] = policy_digest(policy)
    inventory_path = tmp_path / "inventory.json"
    policy_path = tmp_path / "policy.yaml"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "select-pilot",
            str(inventory_path),
            "--policy",
            str(policy_path),
            "--run-id",
            "run-1",
            "--attempt-id",
            "attempt-1",
            "--out",
            str(tmp_path / "out"),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["disposition"] == "qualified"
    assert payload["parity_passed"] is False
    manifest = next((tmp_path / "out").rglob("selection.manifest.json"))
    assert manifest.is_file()


def test_select_pilot_cli_returns_two_for_unmet_coverage(tmp_path: Path) -> None:
    inventory = build_inventory(tmp_path)
    policy = build_policy(size=1)
    policy["criteria"].append(
        {
            "criterion_id": "complexity-simple",
            "dimension": "complexity",
            "value": "simple",
            "minimum_count": 1,
        }
    )
    policy["policy_digest"] = policy_digest(policy)
    inventory_path = tmp_path / "inventory.json"
    policy_path = tmp_path / "policy.yaml"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "select-pilot",
            str(inventory_path),
            "--policy",
            str(policy_path),
            "--run-id",
            "run-1",
            "--attempt-id",
            "attempt-1",
            "--out",
            str(tmp_path / "out"),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert completed.returncode == 2, completed.stderr
    assert json.loads(completed.stdout)["disposition"] == "blocked"


def test_select_pilot_cli_rejects_ambiguous_duplicate_policy_key(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    policy_path = tmp_path / "policy.yaml"
    inventory_path.write_text(json.dumps(build_inventory(tmp_path)), encoding="utf-8")
    policy_path.write_text(
        yaml.safe_dump(build_policy(), sort_keys=False) + "cohort_size: 1\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "select-pilot",
            str(inventory_path),
            "--policy",
            str(policy_path),
            "--run-id",
            "run-1",
            "--attempt-id",
            "attempt-1",
            "--out",
            str(tmp_path / "out"),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert completed.returncode == 1
    assert "Duplicate pilot selection policy key" in completed.stderr
    assert not (tmp_path / "out").exists()
