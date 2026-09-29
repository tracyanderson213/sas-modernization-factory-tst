#!/usr/bin/env bash
set -euo pipefail

python -c "import importlib.metadata as m; assert m.version('sas2databricks') == '0.4.0'"
python -m pytest -q tests/integration/test_spike02_conversion_coverage.py
python scripts/run-spike02-coverage.py
