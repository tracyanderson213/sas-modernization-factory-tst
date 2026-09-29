#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=project-common.sh
source "$SCRIPT_DIR/project-common.sh"
KEY="${1:-}"
[[ -n "$KEY" ]] || smf_die "Usage: $0 <BACKLOG-KEY>"
smf_require_repo_root
smf_require_tools
smf_load_project_metadata
smf_find_item_by_key "$KEY"

if [[ -z "$SMF_ISSUE_NUMBER" ]]; then
  REPOSITORY_ID="$(gh repo view "$SMF_REPO_OWNER/$SMF_REPO" --json id --jq '.id')"
  [[ -n "$REPOSITORY_ID" && "$REPOSITORY_ID" != null ]] || smf_die "Could not resolve repository node ID."
  gh api graphql -f query='mutation($item:ID!,$repository:ID!){convertProjectV2DraftIssueItemToIssue(input:{itemId:$item,repositoryId:$repository}){item{content{... on Issue{number url}}}}}' -F item="$SMF_ITEM_ID" -F repository="$REPOSITORY_ID" >/dev/null
  smf_refresh_item "$KEY"
fi

[[ -n "$SMF_ISSUE_NUMBER" ]] || smf_die "$KEY was not resolved to a repository Issue after promotion."
smf_set_option "$SMF_IMPLEMENTATION_FIELD_ID" "$SMF_IMPL_PARTIAL_ID"
smf_set_option "$SMF_STATUS_FIELD_ID" "$SMF_STATUS_IN_PROGRESS_ID"
smf_verify_state "$KEY" "In Progress" "Partial"

ISSUE_URL="$(gh issue view "$SMF_ISSUE_NUMBER" --repo "$SMF_REPO_OWNER/$SMF_REPO" --json url --jq '.url')"
printf '%s\n' "$KEY started successfully." "" "Issue:                  #$SMF_ISSUE_NUMBER" "URL:                    $ISSUE_URL" "Status:                 In Progress" "Implementation State:   Partial"
