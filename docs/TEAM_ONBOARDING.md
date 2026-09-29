# SMF team onboarding

This guide is the shared starting point for human engineers and the autonomous engineering agent.
`origin/main` is the only completed baseline. The live GitHub Project is the authority for record
state, assignment, dependencies, and acceptance; repository docs summarize but do not replace it.

## What is proven now

- A licensed real `.sas7bdat` fixture runs locally through `pyreadstat 1.3.6`, Spark 3.5.8,
  Arrow 25.0.1, delta-rs 1.6.4, DataComPy 1.0.4, and immutable replay/mutation evidence.
- A source-built `spark-sas7bdat`/Parso path reads and reconciles 18,638 rows across three Spark
  partitions without collecting the complete table locally.
- Pinned `sas2databricks 0.4.0` supplies deterministic SAS-code package mechanics with explicit
  packaged, review-required, unsupported, and blocked outcomes.
- Canonical descriptor/type mapping, restartable local Delta ingestion, offline Unity Catalog and
  Databricks execution plans, provider-neutral AI Gateway preflight, bounded deterministic-first AI
  control, attempt/restart evidence, and exception/certification contracts exist at their documented
  offline boundaries.

These foundations do **not** prove Humana data or semantics, live SAS baselines, AI Gateway
connectivity, provider-generated repair, Azure Databricks or Unity Catalog execution, distributed
cell-level parity, production readiness, certification, promotion, or migration completion.

## Repository map

| Path | Ownership boundary |
| --- | --- |
| `src/smf/` | reusable implementation; prefer a record-specific submodule |
| `src/smf/validation/` | validation contracts and engines; coordinate through the DP/VAL train |
| `schemas/`, `src/smf/schemas/` | public and packaged schemas; keep byte parity where required |
| `tests/` | unit/integration/corpus/adversarial evidence owned with the changed module |
| `competition/generated/` | validated plan/spec artifacts; do not hand-edit inconsistently |
| `competition/ACTIVE-OWNERSHIP.yaml` | current non-overlapping work ownership snapshot |
| `deployments/` | deployment bindings; no customer secret or environment claim |
| `docs/` | current capability, CLI, architecture, onboarding and operations truth |
| `scripts/project-tools/` | GitHub lifecycle, acceptance and repository hygiene tooling |
| `scripts/engineering-agent/` | deterministic agent configuration and role policy |

## Clean setup with Python 3.12

```bash
git clone https://github.com/tbarry3c/sas-modernization-factory.git
cd sas-modernization-factory
git switch main
git pull --ff-only origin main
python3.12 -m venv .venv
source .venv/bin/activate
python --version
python -m pip install -e ".[dev,conversion]"
python -c "import smf; print(smf.__file__)"
```

Do not reuse another engineer's mutable environment. For customer/offline installation, use only an
approved, hash-locked wheel/JAR/native bundle. A source-only profile works only when every native/JVM
dependency is already approved and present. Otherwise preflight must identify the missing offline
artifact and block. Runtime public downloads are prohibited.

### Restore an existing local authenticated session

After the repository environment and the Azure, Databricks, and GitHub CLIs are installed, source the
helper from the repository root:

```bash
source scripts/login-local.sh
```

The helper activates the existing repository `.venv`, validates `smf` import, checks the current CLI
sessions, and invokes the CLIs' normal interactive login flows only when their sessions are invalid.
It does not accept, store, or print access tokens. Authentication remains owned by `az`, `databricks`,
and `gh` and their existing credential stores. Optional variables select an Azure tenant/subscription
or a Databricks profile/host; they are identifiers and configuration, not credential values.

Use `--force` to renew all three sessions, or `--skip-azure`, `--skip-databricks`, and
`--skip-github` for tools that are not needed. The script must be sourced so activation remains in
the current Bash or Zsh session. Never commit CLI credential files, token output, local Databricks
profiles, or environment-specific `.azure` state.

## Exact tests

During development, run the record's focused tests and affected confidence target. At an integration
boundary run:

```bash
source .venv/bin/activate
export PYTHONPATH=src
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src
python -m pytest
python -m pip check
python -m pip_audit --local --skip-editable --progress-spinner off
python scripts/check-documentation-consistency.py
git diff --check
```

Important Day 1 confidence gates include:

```bash
make vs01-confidence
make scale01-confidence
make cv04-confidence
make base02-confidence
make dbpkg04-confidence
make dbpkg01-confidence
make dbx01-confidence
make dbx04-confidence
```

## Current CLI truth

Actual parser-backed product commands are:

```text
smf migrate {convert,modernize,status,resume,exceptions,approve,promote}
smf ai-gateway preflight
smf upstream qualify
smf architecture-review assemble
smf deployment-config {init,preflight,plan}
smf discover
smf intake-batch
smf acquire-baseline
smf assess
smf convert
smf ready
smf select-pilot
smf validate
smf validate-schema
smf execute
smf verify-provenance
```

The nested `migrate` operations are non-operational scaffolds and return blocked exit `2` for valid
inputs. `ai-gateway preflight` is offline. `execute --provider local` is local only; Databricks
submission remains default-deny. See [CLI.md](CLI.md) and [the runbook](operations/runbook.md) for
exact options, outputs, and non-obvious exit behavior.

## Day 1 critical path

```text
DP-02
  -> DP-03 + DP-04 + DP-05
  -> VAL-01
  -> PROV-02
       +-> READY-02 -----+
       +-> PKG-QUAL-01 --+-> MIGCLI-01
  -> MIGOPS-01
  -> ORCH-02
  -> rehearsals
```

The local reader/code/Delta foundations are already merged. Do not restart them. Customer inputs
block only live/customer claims, not safe offline development.

## Ownership and conflict avoidance

Before writing code:

1. Read back the live Project record and exact managed acceptance body.
2. Confirm dependencies are canonically complete, not merely locally reviewed.
3. Add/update one entry in `competition/ACTIVE-OWNERSHIP.yaml` with assignee, backlog key,
   modules/files, dependencies, state, branch/worktree, and integration target.
4. Reject overlapping ownership or a second active lane for the same record.
5. Create a clean record-specific worktree from fresh `origin/main` or the explicitly designated
   integration base. Never use the dirty primary checkout.

If blocked, preserve the commit/worktree/evidence and report the exact missing dependency, owner,
prohibited claim, and next permitted action. Check the live Project and ownership map before
starting replacement work; do not duplicate another engineer's lane.

## Branch and integration-train policy

- One backlog record per feature branch/worktree and one traceable commit/evidence package per record.
- Human feature branches and autonomous-agent commits target one active competition integration train.
- Combine about 3–6 compatible, dependency-safe reviewed records, or one meaningful milestone.
- Keep at most one release PR from the integration train to `main`; isolate only materially different
  security/protected-path risk or an unavoidable dependency conflict.
- Run focused tests per record; run the full suite, audit and remote CI once on the combined tree.
- Require fresh rebase/read-back and independent review. Close only records included in the exact
  merged reviewed tree.
- Do not stack unrelated branches, retain obsolete duplicate lanes, or open one PR per record.

## Evidence and acceptance

Every record maps each acceptance criterion to concrete tests/review/runtime evidence, exact source
and configuration revisions, expected and actual outcomes, immutable references, and prohibited
claims. Generated, executed, validated, parity-passed, certified, human-approved and promoted are
separate claims. Missing authority or evidence remains blocked; mocks and filenames cannot satisfy a
real-runtime criterion.

Never commit secrets, PHI/PII, customer data, Terraform state, local Databricks profiles, or
protected evidence. Do not claim live Humana, SAS, Azure, Databricks, Unity Catalog, Vault, AI
Gateway, model-provider, parity, readiness, certification, or migration success without the exact
authorized executed receipts.
