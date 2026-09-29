#!/usr/bin/env bash
set -euo pipefail

python -m pytest -q tests/unit/test_ai_governance.py tests/unit/test_ai_provider_models.py
