#!/usr/bin/env bash
set -euo pipefail
python -m pytest -q tests/unit/test_dp04_profiles.py tests/unit/test_structural_parity.py
