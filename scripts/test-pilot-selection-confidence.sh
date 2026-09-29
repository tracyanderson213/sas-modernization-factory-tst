#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

git diff --exit-code -- tests/corpus/workloads/public
python -m pytest -q -p no:cacheprovider \
  tests/unit/test_pilot_selection.py \
  tests/integration/test_cli_pilot_selection.py \
  tests/integration/test_pilot_readiness_binding.py \
  tests/integration/test_pilot_schema_packaging.py \
  tests/unit/test_private_corpus_isolation.py
git diff --exit-code -- tests/corpus/workloads/public
