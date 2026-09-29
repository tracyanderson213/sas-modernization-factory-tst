#!/usr/bin/env bash
set -euo pipefail

python -c "from importlib.metadata import version; assert version('sas2databricks') == '0.4.0'"
SMF_REQUIRE_AIREP01=1 python -m pytest -q tests/integration/test_airep01_repair_controller.py
