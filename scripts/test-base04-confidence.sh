#!/usr/bin/env bash
set -euo pipefail

SMF_REQUIRE_BASE04=1 \
SMF_SCALE01_PYTEST_TARGET=tests/integration/test_base04_canonical_descriptor.py \
  "$(dirname "$0")/test-scale01-confidence.sh"
