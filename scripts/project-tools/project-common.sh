#!/usr/bin/env bash
# Shared helpers for SMF GitHub Project lifecycle tools.

SMF_PROJECT_OWNER="${SMF_PROJECT_OWNER:-@me}"
SMF_REPO_OWNER="${SMF_REPO_OWNER:-tbarry3c}"
SMF_REPO="${SMF_REPO:-sas-modernization-factory}"
SMF_PROJECT_NUMBER="${SMF_PROJECT_NUMBER:-2}"

smf_die() { echo "ERROR: $*" >&2; exit 1; }

smf_require_repo_root() {
  [[ -d .git && -f pyproject.toml ]] || smf_die "Run this from the sas-modernization-factory repository root."
}

smf_require_tools() {
  local cmd
  for cmd in gh jq; do command -v "$cmd" >/dev/null 2>&1 || smf_die "'$cmd' is required."; done
  gh auth status >/dev/null 2>&1 || smf_die "GitHub CLI is not authenticated."
}

smf_load_project_metadata() {
  local response fields
  response="$(gh api graphql -f query='query($number:Int!){viewer{projectV2(number:$number){id fields(first:100){nodes{... on ProjectV2SingleSelectField{id name options{id name}}}}}}}' -F number="$SMF_PROJECT_NUMBER")"
  SMF_PROJECT_ID="$(jq -r '.data.viewer.projectV2.id // empty' <<<"$response")"
  fields="$(jq -c '.data.viewer.projectV2.fields.nodes' <<<"$response")"
  SMF_STATUS_FIELD_ID="$(jq -r '.[] | select(.name == "Status") | .id' <<<"$fields")"
  SMF_IMPLEMENTATION_FIELD_ID="$(jq -r '.[] | select(.name == "Implementation State") | .id' <<<"$fields")"
  SMF_STATUS_TODO_ID="$(jq -r '.[] | select(.name == "Status") | .options[]? | select(.name == "Todo") | .id' <<<"$fields")"
  SMF_STATUS_IN_PROGRESS_ID="$(jq -r '.[] | select(.name == "Status") | .options[]? | select(.name == "In Progress") | .id' <<<"$fields")"
  SMF_STATUS_DONE_ID="$(jq -r '.[] | select(.name == "Status") | .options[]? | select(.name == "Done") | .id' <<<"$fields")"
  SMF_IMPL_PARTIAL_ID="$(jq -r '.[] | select(.name == "Implementation State") | .options[]? | select(.name == "Partial") | .id' <<<"$fields")"
  SMF_IMPL_NOT_STARTED_ID="$(jq -r '.[] | select(.name == "Implementation State") | .options[]? | select(.name == "Not Started") | .id' <<<"$fields")"
  SMF_IMPL_NEEDS_REVIEW_ID="$(jq -r '.[] | select(.name == "Implementation State") | .options[]? | select(.name == "Needs Review") | .id' <<<"$fields")"
  SMF_IMPL_COMPLETE_ID="$(jq -r '.[] | select(.name == "Implementation State") | .options[]? | select(.name == "Foundation Complete") | .id' <<<"$fields")"
  local value
  for value in SMF_PROJECT_ID SMF_STATUS_FIELD_ID SMF_IMPLEMENTATION_FIELD_ID SMF_STATUS_TODO_ID SMF_STATUS_IN_PROGRESS_ID SMF_STATUS_DONE_ID SMF_IMPL_PARTIAL_ID SMF_IMPL_NOT_STARTED_ID SMF_IMPL_NEEDS_REVIEW_ID SMF_IMPL_COMPLETE_ID; do
    [[ -n "${!value:-}" && "${!value}" != null ]] || smf_die "Could not resolve ${value}."
  done
}

smf_load_project_items() {
  [[ -z "${SMF_PROJECT_ITEMS_JSON:-}" ]] || return 0

  local cursor="" has_next="true" response page
  SMF_PROJECT_ITEMS_JSON='{"items":[]}'
  while [[ "$has_next" == "true" ]]; do
    local -a args
    args=(api graphql -f query='query($number:Int!,$after:String){viewer{projectV2(number:$number){items(first:100,after:$after){pageInfo{hasNextPage endCursor} nodes{id content{__typename ... on Issue{number title} ... on DraftIssue{title}} fieldValues(first:30){nodes{... on ProjectV2ItemFieldTextValue{text field{... on ProjectV2FieldCommon{name}}} ... on ProjectV2ItemFieldSingleSelectValue{name field{... on ProjectV2FieldCommon{name}}}}}}}}}}' -F number="$SMF_PROJECT_NUMBER")
    [[ -z "$cursor" ]] || args+=(-f after="$cursor")
    response="$(gh "${args[@]}")"
    page="$(jq -c '[.data.viewer.projectV2.items.nodes[] | {
      id,
      title: (.content.title // ""),
      content: {type: (.content.__typename // ""), number: (.content.number // null)},
      status: ([.fieldValues.nodes[]? | select(.field.name == "Status") | .name][0] // ""),
      "implementation State": ([.fieldValues.nodes[]? | select(.field.name == "Implementation State") | .name][0] // ""),
      "backlog Key": ([.fieldValues.nodes[]? | select(.field.name == "Backlog Key") | .text][0] // ""),
      "work Type": ([.fieldValues.nodes[]? | select(.field.name == "Work Type") | .name][0] // ""),
      parent: ([.fieldValues.nodes[]? | select(.field.name == "Parent") | .text][0] // "")
    }]' <<<"$response")"
    SMF_PROJECT_ITEMS_JSON="$(jq -cn --argjson existing "$SMF_PROJECT_ITEMS_JSON" --argjson page "$page" '{items: ($existing.items + $page)}')"
    has_next="$(jq -r '.data.viewer.projectV2.items.pageInfo.hasNextPage' <<<"$response")"
    cursor="$(jq -r '.data.viewer.projectV2.items.pageInfo.endCursor // empty' <<<"$response")"
  done
}

smf_find_item_by_key() {
  local key="$1" items count
  smf_load_project_items
  items="$SMF_PROJECT_ITEMS_JSON"
  count="$(jq --arg key "$key" '[.items[] | select((.["backlog Key"] // .["Backlog Key"] // "") == $key)] | length' <<<"$items")"
  [[ "$count" == 1 ]] || smf_die "Expected exactly one Project item for Backlog Key '$key'; found $count."
  SMF_ITEM_JSON="$(jq -c --arg key "$key" '.items[] | select((.["backlog Key"] // .["Backlog Key"] // "") == $key)' <<<"$items")"
  SMF_ITEM_ID="$(jq -r '.id' <<<"$SMF_ITEM_JSON")"
  SMF_ITEM_TITLE="$(jq -r '.title' <<<"$SMF_ITEM_JSON")"
  SMF_CONTENT_TYPE="$(jq -r '.content.type // ""' <<<"$SMF_ITEM_JSON")"
  SMF_ISSUE_NUMBER="$(jq -r '.content.number // empty' <<<"$SMF_ITEM_JSON")"
}

smf_set_option() {
  gh project item-edit --id "$SMF_ITEM_ID" --project-id "$SMF_PROJECT_ID" --field-id "$1" --single-select-option-id "$2" >/dev/null
}

smf_refresh_item() {
  SMF_PROJECT_ITEMS_JSON=""
  smf_find_item_by_key "$1"
}

smf_read_item_state() {
  local response
  response="$(gh api graphql -f query='query($item:ID!){node(id:$item){... on ProjectV2Item{fieldValues(first:50){nodes{... on ProjectV2ItemFieldSingleSelectValue{name field{... on ProjectV2SingleSelectField{name}}}}}}}}' -F item="$SMF_ITEM_ID")"
  SMF_ACTUAL_STATUS="$(jq -r '[.data.node.fieldValues.nodes[]? | select(.field.name == "Status") | .name][0] // ""' <<<"$response")"
  SMF_ACTUAL_IMPL="$(jq -r '[.data.node.fieldValues.nodes[]? | select(.field.name == "Implementation State") | .name][0] // ""' <<<"$response")"
}

smf_verify_state() {
  local key="$1" expected_status="$2" expected_impl="$3"
  smf_read_item_state
  local actual_status="$SMF_ACTUAL_STATUS" actual_impl="$SMF_ACTUAL_IMPL"
  [[ "$actual_status" == "$expected_status" ]] || smf_die "$key Status is '$actual_status'; expected '$expected_status'."
  [[ "$actual_impl" == "$expected_impl" ]] || smf_die "$key Implementation State is '$actual_impl'; expected '$expected_impl'."
}
