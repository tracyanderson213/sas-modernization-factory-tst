#!/usr/bin/env bash
set -euo pipefail

python -m pytest -p no:cacheprovider \
  tests/unit/test_execution_databricks.py \
  tests/unit/test_databricks_auth_models.py \
  tests/unit/test_databricks_auth_boundary.py \
  tests/unit/test_databricks_auth_manifest.py \
  tests/integration/test_databricks_auth_guardrails.py \
  tests/integration/test_secret_provider_admission.py \
  tests/integration/test_cli_execute.py \
  tests/integration/test_execution_schema.py -q

cmp schemas/databricks-authentication-request.schema.json \
  src/smf/schemas/databricks-authentication-request.schema.json
cmp schemas/databricks-authentication-result.schema.json \
  src/smf/schemas/databricks-authentication-result.schema.json
