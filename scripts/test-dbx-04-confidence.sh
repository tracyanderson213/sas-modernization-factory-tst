#!/usr/bin/env bash
set -euo pipefail

python -m pytest -q \
  tests/unit/test_dbx04_runtime_evidence.py \
  tests/integration/test_dbx04_dbx01_chain.py
cmp schemas/databricks-runtime-evidence.schema.json \
  src/smf/schemas/databricks-runtime-evidence.schema.json
python -m json.tool schemas/databricks-runtime-evidence.schema.json >/dev/null
