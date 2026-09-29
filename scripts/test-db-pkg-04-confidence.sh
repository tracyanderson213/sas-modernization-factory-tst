#!/usr/bin/env bash
set -euo pipefail

SMF_REQUIRE_DBPKG04=1 \
SMF_SCALE01_PYTEST_TARGET=tests/integration/test_dbpkg04_restartable_ingestion.py \
  "$(dirname "$0")/test-scale01-confidence.sh"
