#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=project-common.sh
source "$SCRIPT_DIR/project-common.sh"

KEY="${1:-}"
MODE="${2:-apply}"
[[ -n "$KEY" ]] || smf_die "Usage: $0 <EPIC-BACKLOG-KEY> [dry-run|apply]"
[[ "$MODE" == "dry-run" || "$MODE" == "apply" ]] || smf_die "Usage: $0 <EPIC-BACKLOG-KEY> [dry-run|apply]"

smf_require_repo_root
smf_require_tools
smf_load_project_metadata

smf_load_project_items
ITEMS="$SMF_PROJECT_ITEMS_JSON"
EPIC_COUNT="$(jq --arg key "$KEY" '[.items[] | select((.["backlog Key"] // .["Backlog Key"] // "") == $key)] | length' <<<"$ITEMS")"
[[ "$EPIC_COUNT" == 1 ]] || smf_die "Expected exactly one Project item for epic '$KEY'; found $EPIC_COUNT."

EPIC_JSON="$(jq -c --arg key "$KEY" '.items[] | select((.["backlog Key"] // .["Backlog Key"] // "") == $key)' <<<"$ITEMS")"
WORK_TYPE="$(jq -r '.["work Type"] // .["Work Type"] // ""' <<<"$EPIC_JSON")"
[[ "$WORK_TYPE" == "Epic" ]] || smf_die "$KEY Work Type is '$WORK_TYPE'; expected 'Epic'."

CHILD_ROWS="$(
  jq -r --arg key "$KEY" '
    .items[]
    | select((.parent // .Parent // "") == $key)
    | [
        (.["backlog Key"] // .["Backlog Key"] // "<no-key>"),
        (.status // ""),
        (.["implementation State"] // .["Implementation State"] // "")
      ]
    | @tsv
  ' <<<"$ITEMS"
)"
[[ -n "$CHILD_ROWS" ]] || smf_die "$KEY has no Project children linked through the Parent field."

TOTAL="$(printf '%s\n' "$CHILD_ROWS" | awk 'NF { count++ } END { print count + 0 }')"
COMPLETE=0
PARTIAL=0
NOT_STARTED=0
NEEDS_REVIEW=0
INVALID=0

while IFS=$'\t' read -r CHILD_KEY CHILD_STATUS CHILD_IMPL; do
  [[ -n "$CHILD_KEY" ]] || continue
  case "$CHILD_IMPL" in
    "Foundation Complete") COMPLETE=$((COMPLETE + 1)) ;;
    "Partial") PARTIAL=$((PARTIAL + 1)) ;;
    "Not Started"|"") NOT_STARTED=$((NOT_STARTED + 1)) ;;
    "Needs Review") NEEDS_REVIEW=$((NEEDS_REVIEW + 1)) ;;
    *)
      echo "WARN: $CHILD_KEY has unsupported Implementation State '$CHILD_IMPL'." >&2
      INVALID=$((INVALID + 1))
      ;;
  esac

done <<<"$CHILD_ROWS"
[[ "$INVALID" == 0 ]] || smf_die "$KEY contains child states that cannot be reconciled safely."

if [[ "$COMPLETE" == "$TOTAL" ]]; then
  TARGET_IMPL="Foundation Complete"
  TARGET_STATUS="Done"
  TARGET_IMPL_ID="$SMF_IMPL_COMPLETE_ID"
  TARGET_STATUS_ID="$SMF_STATUS_DONE_ID"
elif [[ "$PARTIAL" -gt 0 || "$COMPLETE" -gt 0 ]]; then
  TARGET_IMPL="Partial"
  TARGET_STATUS="In Progress"
  TARGET_IMPL_ID="$SMF_IMPL_PARTIAL_ID"
  TARGET_STATUS_ID="$SMF_STATUS_IN_PROGRESS_ID"
elif [[ "$NEEDS_REVIEW" -gt 0 ]]; then
  TARGET_IMPL="Needs Review"
  TARGET_STATUS="Todo"
  TARGET_IMPL_ID="${SMF_IMPL_NEEDS_REVIEW_ID:-}"
  TARGET_STATUS_ID="$SMF_STATUS_TODO_ID"
  [[ -n "$TARGET_IMPL_ID" ]] || smf_die "Could not resolve Needs Review option ID."
else
  TARGET_IMPL="Not Started"
  TARGET_STATUS="Todo"
  TARGET_IMPL_ID="${SMF_IMPL_NOT_STARTED_ID:-}"
  TARGET_STATUS_ID="$SMF_STATUS_TODO_ID"
  [[ -n "$TARGET_IMPL_ID" ]] || smf_die "Could not resolve Not Started option ID."
fi

CURRENT_STATUS="$(jq -r '.status // ""' <<<"$EPIC_JSON")"
CURRENT_IMPL="$(jq -r '.["implementation State"] // .["Implementation State"] // ""' <<<"$EPIC_JSON")"

echo "$KEY epic reconciliation"
echo
echo "Children:               $TOTAL"
echo "Foundation Complete:    $COMPLETE"
echo "Partial:                $PARTIAL"
echo "Not Started:            $NOT_STARTED"
echo "Needs Review:           $NEEDS_REVIEW"
echo
echo "Current Status:         ${CURRENT_STATUS:-<blank>}"
echo "Current Impl State:     ${CURRENT_IMPL:-<blank>}"
echo "Derived Status:         $TARGET_STATUS"
echo "Derived Impl State:     $TARGET_IMPL"
echo "Mode:                   $MODE"

if [[ "$MODE" == "dry-run" ]]; then
  exit 0
fi

SMF_ITEM_ID="$(jq -r '.id' <<<"$EPIC_JSON")"
smf_set_option "$SMF_IMPLEMENTATION_FIELD_ID" "$TARGET_IMPL_ID"
smf_set_option "$SMF_STATUS_FIELD_ID" "$TARGET_STATUS_ID"
smf_verify_state "$KEY" "$TARGET_STATUS" "$TARGET_IMPL"

echo
echo "$KEY reconciled successfully."
