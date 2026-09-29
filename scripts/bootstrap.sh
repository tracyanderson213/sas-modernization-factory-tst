#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3.12}"

echo "==> SAS Modernization Factory developer bootstrap"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "ERROR: ${PYTHON_BIN} is required but was not found."
  echo "macOS/Homebrew: brew install python@3.12"
  exit 1
fi

echo "==> Using $(${PYTHON_BIN} --version)"

if [ -d ".venv" ]; then
  echo "==> Existing .venv found"
else
  echo "==> Creating .venv"
  "${PYTHON_BIN}" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Upgrading packaging tools"
python -m pip install --upgrade pip setuptools wheel

echo "==> Installing core + developer dependencies"
python -m pip install -e ".[dev]"

echo "==> Installing pre-commit hooks"
pre-commit install

echo
echo "Bootstrap complete."
echo
echo "Activate the environment with:"
echo "  source .venv/bin/activate"
echo
echo "Then verify with:"
echo "  make verify"
echo
echo "Optional feature sets:"
echo "  pip install -e \".[conversion]\""
echo "  pip install -e \".[azure]\""
echo "  pip install -e \".[databricks]\""
echo "  pip install -e \".[ai]\""
echo "  pip install -e \".[api]\""
echo "  pip install -e \".[dev,conversion,azure,databricks,ai,api]\""
