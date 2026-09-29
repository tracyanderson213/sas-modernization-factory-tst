#!/usr/bin/env bash
set -euo pipefail

python -m pytest -q tests/unit/test_row_count_tolerance.py
