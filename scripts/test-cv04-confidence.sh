#!/usr/bin/env bash
set -euo pipefail

python -c "from importlib.metadata import version; assert version('sas2databricks') == '0.4.0'"
SMF_REQUIRE_CV04=1 python -m pytest -q tests/integration/test_cv04_provider_package.py
