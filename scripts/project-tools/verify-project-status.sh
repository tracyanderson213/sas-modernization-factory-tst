#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=project-common.sh
source "$SCRIPT_DIR/project-common.sh"

smf_require_repo_root
smf_require_tools
smf_load_project_items

echo "==> Project status summary"
jq '[.items[].status] | group_by(.) | map({status: .[0], count: length})' <<<"$SMF_PROJECT_ITEMS_JSON"

echo
echo "==> Implementation State summary"
jq '[.items[] | (.["implementation State"] // .["Implementation State"] // "Unspecified")] | group_by(.) | map({implementation_state: .[0], count: length})' <<<"$SMF_PROJECT_ITEMS_JSON"
