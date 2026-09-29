#!/usr/bin/env bash
set -euo pipefail

python -m pytest -q tests/integration/test_orch01_lifecycle.py
cmp schemas/workload-lifecycle-result.schema.json \
  src/smf/schemas/workload-lifecycle-result.schema.json
cmp schemas/workload-lifecycle-telemetry.schema.json \
  src/smf/schemas/workload-lifecycle-telemetry.schema.json
