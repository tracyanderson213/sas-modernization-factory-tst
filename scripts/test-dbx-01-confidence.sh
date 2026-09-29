#!/usr/bin/env bash
set -euo pipefail

cmp schemas/databricks-remote-plan.schema.json \
  src/smf/schemas/databricks-remote-plan.schema.json
python -m pytest -q tests/unit/test_dbx01_remote_execution.py \
  tests/unit/test_execution_databricks.py
