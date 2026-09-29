#!/usr/bin/env bash
set -euo pipefail

python -m pytest -q tests/unit/test_val01_certification.py

if [[ "${SMF_REQUIRE_VAL01_RUNTIME:-0}" == "1" ]]; then
  if [[ -z "${SMF_VAL01_READER_PYTHON:-}" || ! -x "${SMF_VAL01_READER_PYTHON}" ]]; then
    echo "SMF_VAL01_READER_PYTHON must name the qualified executable Stage A reader" >&2
    exit 2
  fi
  if [[ -z "${SMF_VAL01_READER_SUPPORT_PATH:-}" ]]; then
    common_git="$(git rev-parse --git-common-dir)"
    canonical_root="$(dirname "${common_git}")"
    SMF_VAL01_READER_SUPPORT_PATH="${canonical_root}/.venv/lib/python3.12/site-packages"
    export SMF_VAL01_READER_SUPPORT_PATH
  fi
  if [[ ! -d "${SMF_VAL01_READER_SUPPORT_PATH}/setuptools" ]]; then
    echo "Qualified Stage A setuptools support path is unavailable" >&2
    exit 2
  fi
  PYTHONPATH="${SMF_VAL01_READER_SUPPORT_PATH}" "${SMF_VAL01_READER_PYTHON}" -c \
    'import hashlib, importlib.metadata, pathlib; d=importlib.metadata.distribution("setuptools"); r=next(p for p in d.files or () if str(p).endswith(".dist-info/RECORD")); p=pathlib.Path(str(d.locate_file(r))); print("Stage A setuptools RECORD sha256:" + hashlib.sha256(p.read_bytes()).hexdigest())'
  # Spark/DataComPy can retain JVM/cache state between comparisons. Run every
  # governed case in a fresh process so a prior comparison cannot influence it.
  export SMF_VAL01_STAGE_A_ROOT
  SMF_VAL01_STAGE_A_ROOT="$(mktemp -d "/private/tmp/smf-val01-confidence.XXXXXX")"
  echo "VAL-01 immutable Stage A qualification evidence: ${SMF_VAL01_STAGE_A_ROOT}"
  python scripts/run-val01-runtime-cases.py
fi
