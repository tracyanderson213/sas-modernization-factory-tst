#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

git diff --exit-code -- tests/corpus/workloads/public
python -m pytest -q -p no:cacheprovider \
  tests/unit/test_provenance_chain.py \
  tests/integration/test_provenance_schema_packaging.py \
  tests/unit/test_run_lineage.py \
  tests/unit/test_batch_intake.py \
  tests/unit/test_conversion_rule_registry.py \
  tests/unit/test_cv03_golden_regression.py \
  tests/unit/test_execution_local.py \
  tests/unit/test_validation_engine.py \
  tests/unit/test_readiness_conversion_guard.py \
  tests/unit/test_private_corpus_isolation.py
git diff --check
git diff --exit-code -- tests/corpus/workloads/public
