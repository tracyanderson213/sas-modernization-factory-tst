#!/usr/bin/env bash
set -euo pipefail
python -m pytest -q tests/unit/test_dp05_deterministic_sample.py
