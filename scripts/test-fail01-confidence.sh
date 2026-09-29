#!/usr/bin/env bash
set -euo pipefail

cmp schemas/failure-classification-result.schema.json \
  src/smf/schemas/failure-classification-result.schema.json
cmp schemas/failure-classification-telemetry.schema.json \
  src/smf/schemas/failure-classification-telemetry.schema.json
python -m pytest -q tests/integration/test_fail01_failure_taxonomy.py
