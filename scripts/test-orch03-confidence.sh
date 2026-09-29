#!/usr/bin/env bash
set -euo pipefail

python -m pytest -q tests/integration/test_orch03_restart.py
cmp schemas/restart-plan-result.schema.json \
  src/smf/schemas/restart-plan-result.schema.json
cmp schemas/restart-plan-telemetry.schema.json \
  src/smf/schemas/restart-plan-telemetry.schema.json
