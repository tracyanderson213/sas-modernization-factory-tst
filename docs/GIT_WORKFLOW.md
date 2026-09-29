# Git and GitHub Workflow

## Integration branch

`origin/main` is the only authoritative completed baseline. The local `main` in a dirty or stale
checkout is not a team baseline.

For competition work, maintain exactly one active milestone integration branch and at most one
release PR from that branch to `main`. Human feature branches and autonomous-agent record commits
target this shared train. Do not open one release PR per backlog record.

Before a feature branch starts, record the assignee, canonical backlog key, non-overlapping files or
modules, dependencies, lifecycle state, and integration target in the live Project and
[`../competition/ACTIVE-OWNERSHIP.yaml`](../competition/ACTIVE-OWNERSHIP.yaml). Refresh/rebase and
read back the ownership/state immediately before accepting the commit.

Do not use a long-lived client branch to carry product capabilities that belong in the reusable factory.

## Preferred engineering workflow

For backlog-driven implementation, use the supervised engineering agent. It creates an isolated `agent/<backlog-key>` worktree and leaves final integration to a human.

The canonical start, execution, continuation, integration, Project closeout, epic
reconciliation, and cleanup sequence is documented in
[`BACKLOG_ENGINEERING_WORKFLOW.md`](BACKLOG_ENGINEERING_WORKFLOW.md).

```bash
python -m smf.engineering_agent plan <BACKLOG-KEY>
python -m smf.engineering_agent work <BACKLOG-KEY>
```

If a stopped run is explicitly approved for another bounded repair window:

```bash
python -m smf.engineering_agent continue <BACKLOG-KEY>
```

The orchestrator does not commit, push, close issues, or mark Project items complete. Run
`complete-backlog-item.sh` only from a clean, current `main` checkout after the approved change is
present on `origin/main`; the script verifies the current branch against its remote but does not
itself prove that the branch is `main`.

The explicit exception is `smf-agent drain`: after the same gates and independent Reviewer pass, it
creates local sequential commits only. It never pushes, merges, or changes Issue/Project state.

See [`../scripts/engineering-agent/README.md`](../scripts/engineering-agent/README.md).

## Manual branches

Use a normal short-lived branch when work is not being executed by the engineering-agent workflow.

Recommended prefixes:

- `feature/`
- `fix/`
- `docs/`
- `refactor/`
- `test/`
- `infra/`
- `chore/`

Example:

```bash
git checkout main
git pull --ff-only
git checkout -b docs/repository-hygiene
```

## Before committing

```bash
make verify
git diff --check
git status
git diff
```

Run capability-specific gates in addition to `make verify` when relevant. Discovery changes must also satisfy:

```bash
./scripts/test-discovery-confidence.sh
```

Never weaken or bypass a gate merely to force a change through.

## Commit messages

Use clear imperative or conventional descriptions that identify the behavior changed.

Examples:

```text
feat: add scheduler dependency reconciliation
fix: preserve dynamic dataset direction
docs: synchronize implementation status
test: add adversarial macro resolution coverage
```

## Pull requests and human integration

Keep a separate commit and evidence package for each backlog record, but normally combine about
3–6 compatible reviewed records (or one meaningful dependency milestone) into the active
integration train. Run focused tests on record branches. Run the full repository suite, governed
vulnerability audit and remote CI once on the combined candidate. Isolate a PR only for materially
different security/protected-path risk, an unavoidable dependency conflict, or a record that must
ship independently.

A pull request or equivalent human integration review should explain:

- what changed;
- why it changed;
- how it was tested;
- architecture/schema impact;
- deployment impact;
- known limitations and unresolved evidence.

When using an engineering-agent worktree, review its final diff and run records before integrating. Human approval remains the final authority.

## Protected information

Never commit client production data, secrets, credentials, PHI, PII, or protected workload artifacts.

If sensitive content is committed accidentally, removing it in a later commit is not sufficient. Treat it as an incident because Git history may retain the content.

## Architecture and schema changes

Create or update an ADR when a change alters a significant architectural decision.

Schema changes require tests and should consider backward compatibility.

## Transformation-rule changes

New reusable conversion rules require regression fixtures, applicability conditions, target behavior, limitations, and provenance metadata.

## Deployment-specific behavior

Keep client-specific policy/configuration under `deployments/<deployment>/`. Promote behavior into reusable core only when it is genuinely product-level.
