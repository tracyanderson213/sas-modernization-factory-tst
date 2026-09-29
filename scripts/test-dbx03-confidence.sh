#!/usr/bin/env bash
set -euo pipefail

python -m pytest -p no:cacheprovider \
  tests/unit/test_databricks_compute.py \
  tests/unit/test_dbx03_candidate_manifest.py \
  tests/unit/test_execution_databricks.py \
  tests/unit/test_deployment_configuration.py -q

cmp schemas/databricks-compute-availability.schema.json \
  src/smf/schemas/databricks-compute-availability.schema.json
cmp schemas/databricks-compute-policy.schema.json \
  src/smf/schemas/databricks-compute-policy.schema.json
cmp schemas/databricks-compute-request.schema.json \
  src/smf/schemas/databricks-compute-request.schema.json
cmp schemas/databricks-compute-result.schema.json \
  src/smf/schemas/databricks-compute-result.schema.json
cmp schemas/github-issue-readback-receipt.schema.json \
  src/smf/schemas/github-issue-readback-receipt.schema.json
cmp deployments/humana/compute-policy.yaml \
  src/smf/deployment/templates/humana/compute-policy.yaml
