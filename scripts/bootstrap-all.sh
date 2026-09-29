#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3.12}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "ERROR: ${PYTHON_BIN} is required."
  exit 1
fi

[ -d ".venv" ] || "${PYTHON_BIN}" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev,conversion,azure,databricks,ai,api]"
pre-commit install

echo "Full developer/tooling environment installed."
