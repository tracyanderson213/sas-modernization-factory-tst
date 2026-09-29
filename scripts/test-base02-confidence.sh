#!/usr/bin/env bash
set -euo pipefail

SMF_REQUIRE_BASE02=1 \
SMF_SCALE01_PYTEST_TARGET=tests/integration/test_base02_semantic_mapping.py \
  "$(dirname "$0")/test-scale01-confidence.sh"
