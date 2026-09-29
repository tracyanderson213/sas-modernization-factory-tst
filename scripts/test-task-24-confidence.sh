#!/usr/bin/env bash
set -euo pipefail
python -m pytest -q tests/integration/test_fail01_failure_taxonomy.py tests/integration/test_task24_exception_lifecycle.py
