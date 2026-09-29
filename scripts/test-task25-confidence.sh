#!/usr/bin/env bash
set -euo pipefail

cmp schemas/certification-policy.schema.json src/smf/schemas/certification-policy.schema.json
cmp schemas/certification-evidence.schema.json src/smf/schemas/certification-evidence.schema.json
cmp schemas/certification-bundle-result.schema.json \
  src/smf/schemas/certification-bundle-result.schema.json
python -m pytest -q tests/integration/test_task25_certification_bundle.py
