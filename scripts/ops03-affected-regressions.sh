#!/usr/bin/env bash
set -euo pipefail

selectors=(
  "tests/unit/test_engineering_agent.py"
  "tests/unit/test_acceptance_sync.py"
  "tests/unit/test_databricks_auth_boundary.py"
  "tests/unit/test_databricks_auth_manifest.py"
  "tests/unit/test_baseline_acquisition.py"
  "tests/unit/test_batch_intake.py"
  "tests/integration/test_cli.py"
  "tests/integration/test_cli_execute.py"
  "tests/integration/test_execution_schema.py"
)

python -m pytest -q "${selectors[@]}"
