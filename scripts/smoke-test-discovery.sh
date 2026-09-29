#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$ROOT/tests/fixtures/e2e/sample-sas-estate"
OUT_DIR="$ROOT/out/smoke"
OUT="$OUT_DIR/discovery.json"

mkdir -p "$OUT_DIR"
rm -f "$OUT"

printf '%s\n' "==> Running end-to-end discovery against synthetic SAS estate"
PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python -m smf.cli.main discover "$FIXTURE" --provider filesystem --namespace smoke --out "$OUT"
printf '\n%s\n' "==> Validating discovered graph"
python "$ROOT/scripts/validate-discovery-smoke.py" "$OUT"
printf '\n%s\n' "Discovery model: $OUT"
