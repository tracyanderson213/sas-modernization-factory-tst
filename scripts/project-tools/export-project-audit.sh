#!/usr/bin/env bash
set -euo pipefail

OWNER="@me"
PROJECT_NUMBER="2"
AUDIT_DIR=".project-audit"
ZIP_FILE="${AUDIT_DIR}/smf-project-audit.zip"

if [[ ! -d ".git" || ! -f "pyproject.toml" ]]; then
    echo "ERROR: Run this from the sas-modernization-factory repository root."
    exit 1
fi

if [[ ! -d "${AUDIT_DIR}" ]]; then
    echo "ERROR: ${AUDIT_DIR} does not exist."
    echo "Create it once with: mkdir -p ${AUDIT_DIR}"
    exit 1
fi

for cmd in gh jq zip; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: '${cmd}' is required."
        exit 1
    fi
done

if ! gh auth status >/dev/null 2>&1; then
    echo "ERROR: GitHub CLI is not authenticated."
    exit 1
fi

echo "==> Exporting GitHub Project #${PROJECT_NUMBER}"

gh project view "${PROJECT_NUMBER}" --owner "${OWNER}" --format json > "${AUDIT_DIR}/project.json"
gh project field-list "${PROJECT_NUMBER}" --owner "${OWNER}" --format json > "${AUDIT_DIR}/fields.json"
gh project item-list "${PROJECT_NUMBER}" --owner "${OWNER}" --limit 1000 --format json > "${AUDIT_DIR}/items.json"

ITEM_COUNT="$(jq '.items | length' "${AUDIT_DIR}/items.json")"
FIELD_COUNT="$(jq '.fields | length' "${AUDIT_DIR}/fields.json")"

cat > "${AUDIT_DIR}/summary.txt" <<SUMMARY
SAS Modernization Factory - GitHub Project Audit
Generated: $(date)
Owner: ${OWNER}
Project Number: ${PROJECT_NUMBER}
Project Items: ${ITEM_COUNT}
Project Fields: ${FIELD_COUNT}
SUMMARY

rm -f "${ZIP_FILE}"
(
    cd "${AUDIT_DIR}"
    zip -q smf-project-audit.zip project.json fields.json items.json summary.txt
)

echo
echo "========================================"
echo "Export complete"
echo "========================================"
echo "Items:  ${ITEM_COUNT}"
echo "Fields: ${FIELD_COUNT}"
echo "Upload: ${ZIP_FILE}"
