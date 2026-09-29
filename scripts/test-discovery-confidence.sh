#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failures=0
run_gate() {
  local label="$1"
  shift
  printf '\n============================================================\n'
  printf '%s\n' "$label"
  printf '============================================================\n'
  if "$@"; then
    printf 'GATE RESULT: PASS - %s\n' "$label"
  else
    printf 'GATE RESULT: FAIL - %s\n' "$label"
    failures=$((failures + 1))
  fi
}

run_gate "Gate A: controlled end-to-end acceptance" \
  python -m pytest -q tests/integration/test_discovery_e2e_smoke.py

run_gate "Gate B: adversarial discovery torture test" \
  python -m pytest -q tests/integration/test_discovery_adversarial.py

run_gate "Gate C: untouched public SAS corpus" \
  python -m pytest -q tests/integration/test_discovery_public_corpus_blind.py

printf '\n============================================================\n'
if (( failures == 0 )); then
  printf 'DISCOVERY CONFIDENCE RESULT: ALL THREE GATES PASSED\n'
  exit 0
fi
printf 'DISCOVERY CONFIDENCE RESULT: %d GATE(S) FAILED\n' "$failures"
printf '%s\n' 'A failure is evidence to investigate. Do not weaken an assertion merely to make this green.'
exit 1
