# Contributing

Start with [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) and [`docs/GIT_WORKFLOW.md`](docs/GIT_WORKFLOW.md).
New team members must also read [`docs/TEAM_ONBOARDING.md`](docs/TEAM_ONBOARDING.md) and the current
[`competition/ACTIVE-OWNERSHIP.yaml`](competition/ACTIVE-OWNERSHIP.yaml).

## Shared baseline and integration train

- `origin/main` is the only completed baseline; refresh it before creating a worktree.
- Record the backlog key, assignee, exact file/module boundary, dependencies, state, and integration
  target before implementation. Overlapping or duplicate active ownership is a blocker.
- Keep one record per feature worktree and one traceable reviewed commit/evidence package per record.
- Target the single active competition integration train. Combine approximately 3–6 compatible
  dependency-safe records, or one meaningful milestone, and keep at most one release PR to `main`.
- Run focused gates per record and the complete suite/security audit/remote CI once on the combined
  train. Require fresh rebase/read-back before acceptance.
- Do not stack unrelated branches, create duplicate implementation lanes, or use another engineer's
  worktree. Preserve blocked work and report it through the ownership map instead of restarting it.

## Required before human integration

```bash
source .venv/bin/activate
make verify
git diff --check
```

Run capability-specific confidence gates in addition to the repository gate. Discovery changes must also pass:

```bash
./scripts/test-discovery-confidence.sh
```

## Backlog-driven engineering

The preferred implementation workflow is the supervised engineering agent:

```bash
python -m smf.engineering_agent plan <BACKLOG-KEY>
python -m smf.engineering_agent work <BACKLOG-KEY>
```

It operates in isolated worktrees and does not perform final commit, push, issue closure, or Project completion. Human integration remains mandatory.

See [`scripts/engineering-agent/README.md`](scripts/engineering-agent/README.md).
Use [`docs/BACKLOG_ENGINEERING_WORKFLOW.md`](docs/BACKLOG_ENGINEERING_WORKFLOW.md) for the complete
Project start, supervised run, human integration, completion, and cleanup sequence.

## Engineering principles

Changes should preserve:

1. deterministic transformation before AI-assisted transformation;
2. structured outputs before free-form agent output;
3. evidence-based confidence;
4. validation as a first-class capability;
5. bounded agent autonomy;
6. complete provenance;
7. human review for unresolved or high-risk exceptions;
8. reusable rules rather than repeated one-off fixes;
9. bounded task context separated from durable estate-wide intelligence.

## Dependency changes

Declare dependencies in `pyproject.toml`. Do not rely on undocumented `pip install <package>` instructions.

## Architecture changes

Create or update an ADR for material architectural decisions.

## Transformation rules

New deterministic rules require a rule ID, applicability conditions, target behavior, provenance, limitations, and regression tests.

## Client-specific configuration

Keep deployment-specific behavior under `deployments/<deployment>/` unless it represents a genuinely reusable core capability.

## Repository hygiene

Do not commit temporary repair bundles, generated reconciliation payloads, local run evidence, caches, snapshots, or duplicated GitHub issue bodies merely for convenience. Durable deployment decisions belong under `deployments/<deployment>/docs/`; detailed execution state belongs in GitHub.

## Security

Never commit secrets, production client data, PHI, PII, Terraform state, or protected workload artifacts.
