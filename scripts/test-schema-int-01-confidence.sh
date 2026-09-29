#!/usr/bin/env bash
set -euo pipefail

python -m pytest -q tests/unit/test_schema_integration.py

SMF_REQUIRE_SCHEMAINT=1 \
SMF_SCALE01_PYTEST_TARGET=tests/integration/test_schema_integration_actual.py \
  "$(dirname "$0")/test-scale01-confidence.sh"
