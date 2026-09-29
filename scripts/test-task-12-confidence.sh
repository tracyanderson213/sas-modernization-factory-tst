#!/usr/bin/env bash
set -euo pipefail
python -m pytest -q tests/unit/test_aggregate_tolerance.py
