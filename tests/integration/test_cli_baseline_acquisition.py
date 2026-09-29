from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml
from tests.unit.baseline_test_support import build_baseline_case


def test_acquire_baseline_cli_persists_verified_export(tmp_path: Path) -> None:
    case = build_baseline_case(tmp_path)
    request = case["request"]
    intake_policy_path = tmp_path / "intake-policy.yaml"
    intake_policy_path.write_text(yaml.safe_dump(request.intake_policy.payload), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = "src:."
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "acquire-baseline",
            "--acquisition-id",
            request.acquisition_id,
            "--policy",
            str(request.policy_path),
            "--intake-result",
            str(request.intake_result_path),
            "--intake-policy",
            str(intake_policy_path),
            "--package-root",
            str(request.package_root),
            "--receipt",
            str(request.receipt_path),
            "--approval",
            str(request.approval_path),
            "--workload-id",
            request.workload_id,
            "--workload-revision-id",
            request.workload_revision_id,
            "--closure-digest",
            request.closure_digest,
            "--boundary-id",
            request.boundary_id,
            "--run-id",
            request.run_id,
            "--attempt-id",
            request.attempt_id,
            "--out",
            str(request.output_root),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["disposition"] == "acquired"
    assert payload["baseline_acquired"] is True
    assert payload["executed"] is False
    assert payload["validated"] is False
    assert payload["parity_passed"] is False
    assert Path(payload["result_path"]).is_file()
