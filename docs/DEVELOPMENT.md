# Developer Setup

This document is the canonical local-development guide for the SAS Modernization Factory.

## Supported Local Environment

Initial supported developer environment:

- macOS or Linux
- Git
- Python 3.12
- Bash
- VS Code recommended
- GitHub access to the private repository

The project declares Python `>=3.11,<3.13`. Python 3.12 is the recommended and tested local version.

## 1. Clone the Repository

```bash
git clone <REPOSITORY_URL>
cd sas-modernization-factory
```

Do not clone client data into the repository.

## 2. Confirm Python

```bash
python3.12 --version
```

Expected:

```text
Python 3.12.x
```

On macOS with Homebrew:

```bash
brew install python@3.12
```

## 3. Bootstrap the Development Environment

Run:

```bash
./scripts/bootstrap.sh
```

This creates `.venv`, installs the project in editable mode, installs developer tooling, and configures pre-commit hooks.

Activate the environment:

```bash
source .venv/bin/activate
```

Verify the CLI:

```bash
smf --help
```

## 4. Optional Feature Sets

The base developer environment intentionally does not install every cloud/provider dependency.

Install only what you are developing:

### Conversion engine integration

```bash
pip install -e ".[conversion]"
```

This installs the pinned-compatible `sas2databricks` integration dependency.

### Azure control plane

```bash
pip install -e ".[azure]"
```

### Databricks integration

```bash
pip install -e ".[databricks]"
```

### AI integration

```bash
pip install -e ".[ai]"
```

### Factory API

```bash
pip install -e ".[api]"
```

### Everything

```bash
pip install -e ".[dev,conversion,azure,databricks,ai,api]"
```

or:

```bash
./scripts/bootstrap-all.sh
```

## 5. Development Commands

Use the Makefile so local and CI commands remain consistent.

```bash
make help
make test
make test-cov
make lint
make format
make typecheck
make security
make verify
```

Before opening a pull request:

```bash
make verify
```

## 6. Run the Current Factory CLI

Example:

```bash
smf assess examples/simple/example.sas
```

Machine-readable output:

```bash
smf assess examples/simple/example.sas --json
```

## 7. Engineering and Git Workflow

Never work directly on `main` for normal implementation.

For backlog-driven work, prefer the supervised engineering agent:

```bash
python -m smf.engineering_agent plan <BACKLOG-KEY>
python -m smf.engineering_agent work <BACKLOG-KEY>
```

The agent creates an isolated `agent/<backlog-key>` worktree, runs bounded Architect/Developer/Reviewer stages and deterministic gates, and stops for human integration. It does not commit, push, close issues, or mark Project items complete.

See `docs/BACKLOG_ENGINEERING_WORKFLOW.md` for the complete lifecycle, including Project start,
continuation eligibility, human review, integration into `main`, Project completion, and worktree
cleanup.

For work outside that workflow, use a short-lived manual branch:

```bash
git checkout main
git pull --ff-only
git checkout -b feature/<short-description>
```

Before integration:

```bash
make verify
git diff --check
git status
git diff
```

See `docs/GIT_WORKFLOW.md` and `scripts/engineering-agent/README.md`.

## 8. Pre-Commit Hooks

Hooks install automatically during bootstrap.

Run them against all files manually:

```bash
pre-commit run --all-files
```

Never bypass hooks simply to force broken code into the repository.

## 9. Dependency Management

Dependencies are declared in `pyproject.toml`.

Do not instruct developers to manually install undeclared packages such as:

```bash
pip install pytest
```

Instead, add the dependency to the appropriate project extra and reinstall:

```bash
pip install -e ".[dev]"
```

Runtime dependencies belong under `[project].dependencies`.

Developer-only dependencies belong under `[project.optional-dependencies].dev`.

Provider dependencies should remain isolated in feature extras such as `azure`, `databricks`, `ai`, or `conversion`.

## 10. Third-Party Conversion Engine

`sas2databricks` is an accelerator and provider implementation, not the factory's architectural boundary.

The factory should integrate it behind an internal adapter.

Current external package expectations:

- package: `sas2databricks`
- supported integration range: `>=0.4,<0.5`
- upstream license: MIT
- upstream Python support includes Python 3.10 through 3.12

Do not import `sas2databricks` throughout the codebase. Keep the dependency isolated under the conversion-provider implementation.

## 11. Secrets and Client Data

Never commit:

- passwords
- API keys
- access tokens
- Azure credentials
- Databricks PATs
- connection strings
- `.env` files
- Terraform state
- production SAS datasets
- PHI
- PII
- Humana production source/data artifacts

Use synthetic examples in `examples/` and `tests/`.

Local protected artifacts belong only in paths ignored by Git.

## 12. VS Code

Select the repository virtual environment as the Python interpreter:

```text
.venv/bin/python
```

Recommended extensions:

- Python
- Pylance
- Ruff
- GitHub Pull Requests
- YAML
- Terraform
- Databricks, when Databricks development begins

## 13. Reset Local Environment

If the Python environment becomes corrupted:

```bash
deactivate 2>/dev/null || true
rm -rf .venv
./scripts/bootstrap.sh
source .venv/bin/activate
```

## 14. Definition of Ready for a Pull Request

A code change should normally have:

- implementation
- automated tests
- updated schema if a contract changed
- updated documentation if behavior changed
- an ADR if an architectural decision changed
- no secrets or client data
- passing `make verify`
