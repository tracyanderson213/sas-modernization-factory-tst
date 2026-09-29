#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python -m pytest -q \
  tests/unit/test_corpus_regression_evidence.py \
  tests/unit/test_cv03_golden_regression.py \
  tests/unit/test_ad04_human_review.py \
  tests/integration/test_corpus_regression.py
