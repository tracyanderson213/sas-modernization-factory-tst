#!/usr/bin/env bash
set -euo pipefail

cmp schemas/unity-catalog-validation-result.schema.json \
  src/smf/schemas/unity-catalog-validation-result.schema.json
python -m pytest -q tests/unit/test_dbpkg01_unity_catalog_validation.py
