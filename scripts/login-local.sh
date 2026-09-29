#!/usr/bin/env bash
# Restore the local SMF development session without storing credentials.
#
# Source this file so .venv remains active in the current shell:
#   source scripts/login-local.sh
#
# Optional configuration:
#   SMF_AZURE_TENANT_ID=<tenant-id>
#   SMF_AZURE_SUBSCRIPTION=<subscription-name-or-id>
#   SMF_DATABRICKS_PROFILE=<profile-name>   # defaults to DEFAULT
#   SMF_DATABRICKS_HOST=<workspace-url>     # optional
#
# Options:
#   --force          Re-run every interactive login even when the session is valid.
#   --skip-azure     Do not validate or log in to Azure.
#   --skip-databricks
#   --skip-github

_smf_login_sourced=false
if [[ -n "${ZSH_EVAL_CONTEXT:-}" && "${ZSH_EVAL_CONTEXT}" == *:file ]]; then
  _smf_login_sourced=true
elif [[ -n "${BASH_VERSION:-}" && "${BASH_SOURCE[0]}" != "$0" ]]; then
  _smf_login_sourced=true
fi

if [[ "${_smf_login_sourced}" != true ]]; then
  echo "Run this script with: source scripts/login-local.sh" >&2
  echo "Sourcing is required so the virtual environment stays active." >&2
  exit 2
fi

_smf_force=false
_smf_skip_azure=false
_smf_skip_databricks=false
_smf_skip_github=false

while (($#)); do
  case "$1" in
    --force) _smf_force=true ;;
    --skip-azure) _smf_skip_azure=true ;;
    --skip-databricks) _smf_skip_databricks=true ;;
    --skip-github) _smf_skip_github=true ;;
    -h|--help)
      echo "Usage: source scripts/login-local.sh [--force] [--skip-azure] [--skip-databricks] [--skip-github]"
      return 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      return 2
      ;;
  esac
  shift
done

if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: git is required." >&2
  return 1
fi

_smf_repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: Run this command from inside the SMF repository." >&2
  return 1
}

if [[ ! -f "${_smf_repo_root}/.venv/bin/activate" ]]; then
  echo "ERROR: ${_smf_repo_root}/.venv does not exist." >&2
  echo "Create it with the repository bootstrap process before logging in." >&2
  return 1
fi

# shellcheck disable=SC1091
source "${_smf_repo_root}/.venv/bin/activate"
cd "${_smf_repo_root}" || return 1

echo "SMF environment"
echo "  Repository: ${_smf_repo_root}"
echo "  Python:     $(python --version 2>&1)"
echo "  Executable: $(command -v python)"

if ! python -c 'import smf' >/dev/null 2>&1; then
  echo "ERROR: The active environment cannot import smf." >&2
  return 1
fi
echo "  SMF import: OK"

if [[ "${_smf_skip_azure}" != true ]]; then
  if ! command -v az >/dev/null 2>&1; then
    echo "ERROR: Azure CLI (az) is not installed." >&2
    return 1
  fi

  if [[ "${_smf_force}" == true ]] || ! az account get-access-token --resource https://management.azure.com/ --output none >/dev/null 2>&1; then
    echo
    echo "Azure login"
    _smf_az_login=(az login)
    if [[ -n "${SMF_AZURE_TENANT_ID:-}" ]]; then
      _smf_az_login+=(--tenant "${SMF_AZURE_TENANT_ID}")
    fi
    "${_smf_az_login[@]}" --output none || return 1
  fi

  if [[ -n "${SMF_AZURE_SUBSCRIPTION:-}" ]]; then
    az account set --subscription "${SMF_AZURE_SUBSCRIPTION}" || return 1
  fi

  az account get-access-token --resource https://management.azure.com/ --output none >/dev/null || return 1
  _smf_az_name="$(az account show --query name --output tsv)" || return 1
  _smf_az_id="$(az account show --query id --output tsv)" || return 1
  echo "Azure:      authenticated (${_smf_az_name}, ${_smf_az_id})"
fi

if [[ "${_smf_skip_databricks}" != true ]]; then
  if ! command -v databricks >/dev/null 2>&1; then
    echo "ERROR: Databricks CLI is not installed." >&2
    return 1
  fi

  _smf_db_profile="${SMF_DATABRICKS_PROFILE:-DEFAULT}"
  if [[ "${_smf_force}" == true ]] || ! databricks current-user me --profile "${_smf_db_profile}" >/dev/null 2>&1; then
    echo
    echo "Databricks login (profile: ${_smf_db_profile})"
    _smf_db_login=(databricks auth login --profile "${_smf_db_profile}")
    if [[ -n "${SMF_DATABRICKS_HOST:-}" ]]; then
      _smf_db_login+=(--host "${SMF_DATABRICKS_HOST}")
    fi
    "${_smf_db_login[@]}" || return 1
  fi

  databricks auth describe --profile "${_smf_db_profile}" >/dev/null || return 1
  databricks current-user me --profile "${_smf_db_profile}" >/dev/null || return 1
  export DATABRICKS_CONFIG_PROFILE="${_smf_db_profile}"
  echo "Databricks: authenticated (profile: ${DATABRICKS_CONFIG_PROFILE})"
fi

if [[ "${_smf_skip_github}" != true ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "ERROR: GitHub CLI (gh) is not installed." >&2
    return 1
  fi

  if [[ "${_smf_force}" == true ]] || ! gh auth status --hostname github.com >/dev/null 2>&1; then
    echo
    echo "GitHub login"
    gh auth login --hostname github.com --git-protocol https --web || return 1
  fi
  gh auth status --hostname github.com >/dev/null || return 1
  echo "GitHub:     authenticated"
fi

echo
echo "Local SMF session is ready. The repository .venv is active in this terminal."

unset _smf_force _smf_skip_azure _smf_skip_databricks _smf_skip_github
unset _smf_repo_root _smf_az_login _smf_az_name _smf_az_id
unset _smf_db_profile _smf_db_login _smf_login_sourced
