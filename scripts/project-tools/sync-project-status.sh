#!/usr/bin/env bash
set -euo pipefail

OWNER="tbarry3c"
PROJECT_NUMBER="2"
SLEEP_SECONDS="2.5"
MODE="${1:-apply}"

if [[ "${MODE}" != "apply" && "${MODE}" != "dry-run" ]]; then
    echo "Usage: $0 [dry-run|apply]"
    exit 1
fi

if [[ ! -d ".git" || ! -f "pyproject.toml" ]]; then
    echo "ERROR: Run this from the sas-modernization-factory repository root."
    exit 1
fi

for cmd in gh jq; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: '${cmd}' is required."
        exit 1
    fi
done

if ! gh auth status >/dev/null 2>&1; then
    echo "ERROR: GitHub CLI is not authenticated."
    exit 1
fi

PROJECT_ID="$(gh project view "${PROJECT_NUMBER}" --owner "${OWNER}" --format json --jq '.id')"

FIELDS_JSON="$(mktemp)"
ITEMS_JSON="$(mktemp)"
trap 'rm -f "${FIELDS_JSON}" "${ITEMS_JSON}"' EXIT

gh project field-list "${PROJECT_NUMBER}" --owner "${OWNER}" --format json > "${FIELDS_JSON}"
gh project item-list "${PROJECT_NUMBER}" --owner "${OWNER}" --limit 1000 --format json > "${ITEMS_JSON}"

STATUS_FIELD_ID="$(jq -r '.fields[] | select(.name == "Status") | .id' "${FIELDS_JSON}")"
TODO_ID="$(jq -r '.fields[] | select(.name == "Status") | .options[]? | select(.name == "Todo") | .id' "${FIELDS_JSON}")"
IN_PROGRESS_ID="$(jq -r '.fields[] | select(.name == "Status") | .options[]? | select(.name == "In Progress") | .id' "${FIELDS_JSON}")"
DONE_ID="$(jq -r '.fields[] | select(.name == "Status") | .options[]? | select(.name == "Done") | .id' "${FIELDS_JSON}")"

for value in PROJECT_ID STATUS_FIELD_ID TODO_ID IN_PROGRESS_ID DONE_ID; do
    if [[ -z "${!value:-}" || "${!value}" == "null" ]]; then
        echo "ERROR: Could not resolve ${value}."
        exit 1
    fi
done

TOTAL="$(jq '.items | length' "${ITEMS_JSON}")"

echo "=================================================="
echo " SMF GitHub Project Status Synchronization"
echo "=================================================="
echo "Mode:    ${MODE}"
echo "Project: #${PROJECT_NUMBER}"
echo "Items:   ${TOTAL}"
echo

CHANGED=0
SKIPPED=0
UNKNOWN=0

while IFS=$'\t' read -r ITEM_ID KEY TITLE IMPLEMENTATION_STATE CURRENT_STATUS; do
    case "${IMPLEMENTATION_STATE}" in
        "Foundation Complete")
            TARGET_STATUS="Done"
            TARGET_OPTION_ID="${DONE_ID}"
            ;;
        "Partial")
            TARGET_STATUS="In Progress"
            TARGET_OPTION_ID="${IN_PROGRESS_ID}"
            ;;
        "Not Started"|"Needs Review"|"")
            TARGET_STATUS="Todo"
            TARGET_OPTION_ID="${TODO_ID}"
            ;;
        *)
            echo "WARN   ${KEY:-<no-key>}: unknown Implementation State '${IMPLEMENTATION_STATE}'"
            UNKNOWN=$((UNKNOWN + 1))
            continue
            ;;
    esac

    if [[ "${CURRENT_STATUS}" == "${TARGET_STATUS}" ]]; then
        echo "SKIP   ${KEY:-<no-key>}: ${CURRENT_STATUS}"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    echo "UPDATE ${KEY:-<no-key>}: ${CURRENT_STATUS:-<blank>} -> ${TARGET_STATUS} | ${TITLE}"
    CHANGED=$((CHANGED + 1))

    if [[ "${MODE}" == "apply" ]]; then
        gh project item-edit \
            --id "${ITEM_ID}" \
            --project-id "${PROJECT_ID}" \
            --field-id "${STATUS_FIELD_ID}" \
            --single-select-option-id "${TARGET_OPTION_ID}" \
            >/dev/null
        sleep "${SLEEP_SECONDS}"
    fi
done < <(
    jq -r '
      .items[] |
      [
        .id,
        (.["backlog Key"] // .["Backlog Key"] // ""),
        .title,
        (.["implementation State"] // .["Implementation State"] // ""),
        (.status // "")
      ] | @tsv
    ' "${ITEMS_JSON}"
)

echo
echo "========================================"
echo "Synchronization complete"
echo "========================================"
echo "Mode:     ${MODE}"
echo "Changed:  ${CHANGED}"
echo "Skipped:  ${SKIPPED}"
echo "Unknown:  ${UNKNOWN}"
