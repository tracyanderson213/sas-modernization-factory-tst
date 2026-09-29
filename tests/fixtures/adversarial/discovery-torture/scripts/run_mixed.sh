#!/usr/bin/env bash
set -euo pipefail
SAS_BIN=${SAS_BIN:-sas}
"$SAS_BIN" -sysin jobs/edge_cases.sas
sas -sysin "$DYNAMIC_PROGRAM"
# sas -sysin jobs/commented_out.sas
printf '%s\n' 'sas -sysin jobs/string_only.sas'
