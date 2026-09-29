#!/usr/bin/env bash
set -euo pipefail

SMF_REQUIRE_BASE10=1 \
SMF_SCALE01_PYTEST_TARGET=tests/integration/test_base10_target_mapping_actual.py \
  "$(dirname "$0")/test-scale01-confidence.sh"
