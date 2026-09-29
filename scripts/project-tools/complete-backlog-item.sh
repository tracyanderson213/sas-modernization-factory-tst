#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=project-common.sh
source "$SCRIPT_DIR/project-common.sh"
KEY="${1:-}"
shift || true
COMMENT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --comment) [[ $# -ge 2 ]] || smf_die "--comment requires text."; COMMENT="$2"; shift 2 ;;
    *) smf_die "Usage: $0 <BACKLOG-KEY> [--comment <text>]" ;;
  esac
done
[[ -n "$KEY" ]] || smf_die "Usage: $0 <BACKLOG-KEY> [--comment <text>]"
smf_require_repo_root
smf_require_tools

[[ -z "$(git status --porcelain)" ]] || smf_die "Working tree is not clean. Commit or discard changes before completing $KEY."
BRANCH="$(git branch --show-current)"
[[ -n "$BRANCH" ]] || smf_die "Detached HEAD is not supported for completion."
git fetch --quiet origin "$BRANCH"
LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/$BRANCH")"
[[ "$LOCAL_SHA" == "$REMOTE_SHA" ]] || smf_die "Local HEAD is not identical to origin/$BRANCH. Push verified work before completing $KEY."

smf_load_project_metadata
smf_find_item_by_key "$KEY"
[[ -n "$SMF_ISSUE_NUMBER" ]] || smf_die "$KEY is not a repository Issue. Start it before completing it."

if [[ -z "$COMMENT" ]]; then
  COMMENT="$KEY foundation complete. Repository verification completed before governance closeout."
fi
STATE="$(gh issue view "$SMF_ISSUE_NUMBER" --repo "$SMF_REPO_OWNER/$SMF_REPO" --json state --jq '.state')"
if [[ "$STATE" == OPEN ]]; then
  gh issue close "$SMF_ISSUE_NUMBER" --repo "$SMF_REPO_OWNER/$SMF_REPO" --comment "$COMMENT" >/dev/null
fi
smf_set_option "$SMF_IMPLEMENTATION_FIELD_ID" "$SMF_IMPL_COMPLETE_ID"
smf_set_option "$SMF_STATUS_FIELD_ID" "$SMF_STATUS_DONE_ID"
smf_verify_state "$KEY" "Done" "Foundation Complete"
STATE="$(gh issue view "$SMF_ISSUE_NUMBER" --repo "$SMF_REPO_OWNER/$SMF_REPO" --json state --jq '.state')"
[[ "$STATE" == CLOSED ]] || smf_die "Issue #$SMF_ISSUE_NUMBER is '$STATE'; expected CLOSED."

printf '%s\n' "$KEY completed successfully." "" "Issue:                  #$SMF_ISSUE_NUMBER" "Status:                 Done" "Implementation State:   Foundation Complete" "Repository:             origin/$BRANCH @ ${LOCAL_SHA:0:12}"
