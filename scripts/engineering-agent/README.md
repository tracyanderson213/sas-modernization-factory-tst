# SMF Engineering Agent

Bounded engineering orchestration for the SAS Modernization Factory, including a local-only
autonomous Humana competition drain.

## Safety boundary

The orchestrator may recommend work, create an isolated Git worktree, invoke
architect/developer/reviewer agents, and run deterministic gates. `work` and `continue` leave the
candidate uncommitted for human approval. The explicitly invoked `drain` mode may commit a passing
candidate locally, but no mode pushes, merges, closes GitHub issues, marks Project items complete,
or performs deployment/external actions.

## Commands

```bash
smf-agent next
smf-agent next --offline
smf-agent next --focus EPIC-CORPUS
smf-agent plan CORPUS-02
smf-agent work CORPUS-02 --runner '<agent-runner-command>'
smf-agent continue CORPUS-02 --max-repairs 2
python -m smf.engineering_agent drain
```

The installed entry point and `python -m smf.engineering_agent` are equivalent. Do not use
`python -m smf.engineering_agent.cli`; that module does not invoke `main()` directly.

`work` and `continue` default to two repair attempts after the first Developer attempt. The intended
value for `--max-repairs` is a non-negative integer; the current parser does not reject negative
values, so operators must not supply them.

Live planning uses a narrow paginated GraphQL projection. `--offline` uses the existing
`.project-audit/items.json` snapshot and performs no GitHub calls. An offline snapshot may be stale
or omit newer backlog items. Prefer live state before beginning or continuing engineering work;
reserve offline execution for a snapshot whose generation time and issue content were just verified.

## Agent runner contract

Set `SMF_AGENT_RUNNER` or pass `--runner`. The command is invoked with the role (`architect`, `developer`, or `reviewer`) as its final argument, receives the role prompt on stdin, and runs with the isolated worktree as its current directory.

Example adapter shape:

```text
my-agent-runner architect < prompt
my-agent-runner developer < prompt
my-agent-runner reviewer < prompt
```

Provider-specific adapters can be added without coupling backlog planning or engineering policy to one model vendor.

## Readiness

The planner never invents dependencies. Explicit dependencies live in `config.yaml`. Active non-epic work is preferred over opening new work, then P0, P1, and P2 priority are applied. Completed work and blocked work are excluded from recommendation.

## Mandatory developer gates

1. `make format`
2. `make verify`
3. `./scripts/test-discovery-confidence.sh`

The workflow stops on the first failing gate. Reviewer execution occurs only after the developer gates pass.

### Focused epic planning

Use `--focus EPIC-KEY` to constrain `next` to children of an explicit epic. Focus does not bypass explicit dependencies and does not treat historical `In Progress` / `Partial` state as proof that an item is currently being executed.

```bash
PYTHONPATH=src python -m smf.engineering_agent next --focus EPIC-CORPUS
```

Without `--focus`, planning remains global and deterministic across ready non-epic work.

## Supervised worker execution

`work` creates an isolated `agent/<backlog-key>` worktree and a durable local run record under `.smf-agent/runs/<key>/<run-id>/`. Architect and reviewer roles are write-restricted to their own `agent-artifacts` files. Developer changes are blocked from untouched public evidence, private-corpus locations, and quality-control files. Deterministic gate failures and reviewer rejections may enter a bounded developer repair loop. The terminal successful state is `READY FOR HUMAN APPROVAL`; `work` and `continue` never commit, push, close issues, or change GitHub Project state.

`drain` uses the governed competition-critical queue and the same role, gate, review, repair, and
protected-path controls. It commits each passing candidate locally and chains the commit into the
next candidate. It never pushes, merges, promotes drafts, closes issues, changes Project state, or
performs deployment/external actions. See the canonical workflow for its exact stop conditions.

The authoritative candidate worktree is created at
`../.smf-agent-worktrees/<lowercase-backlog-key>/` on branch
`agent/<lowercase-backlog-key>`. Existing worktree or branch names cause a new `work` command to
fail; inspect them before performing any cleanup.

## Continuation boundary

`continue` creates a new run record linked to the latest stopped run and reuses that run's existing
worktree. It does not rerun Architect. Continuation requires a stopped run, an existing worktree,
and nonempty Reviewer findings with recoverable review-scope evidence. It is therefore a bounded
review-closure continuation, not a general resume mechanism for Architect, Developer, or pre-review
gate failures.

Inspect the stopped run's `final-report.md`, `run.json`, latest `reviewer-final-*.md`, and latest
`review-scope-*.json` before a human authorizes another window.

## Human integration and Project closeout

At `READY FOR HUMAN APPROVAL`, review the candidate diff and run evidence, then commit, push, and
merge through the normal human-controlled workflow. After the approved change is present on
`origin/main`, update a clean local `main` and run `complete-backlog-item.sh`. Do not complete a
Project item from a pushed agent branch: the completion script compares the current branch with its
remote but does not enforce that the branch is `main`.

See [`../../docs/BACKLOG_ENGINEERING_WORKFLOW.md`](../../docs/BACKLOG_ENGINEERING_WORKFLOW.md) for
the complete start-through-cleanup sequence.


## Codex runtime

Codex is the default Stage-1 runtime. The orchestrator invokes each role in a fresh,
ephemeral Codex execution:

- Architect: `read-only`
- Developer: `workspace-write`
- Reviewer: `workspace-write` inside an SMF-owned disposable candidate snapshot

All roles use approval policy `never`. No role uses `danger-full-access` or bypass flags.
Architect and Reviewer return their artifacts through Codex's final-message output. Architect runs read-only against the authoritative worktree. Reviewer runs with workspace-write only inside an SMF-owned disposable Git snapshot; the trusted orchestrator writes the final review artifact back to the authoritative worktree after verifying its implementation fingerprint did not change.

Set `SMF_AGENT_RUNNER` or pass `--runner` only to use an alternate provider adapter.

## Reviewer feedback and repair convergence

Reviewer rejection is treated as durable engineering evidence rather than disposable prose. Each
review is normalized into a machine-readable defect packet under the run directory. The first
review is `DISCOVERY`; its first failure establishes the complete blocking set. Every later review
in that run or continuation is `CLOSURE`. Repair attempts receive the complete unresolved blocking
set and the durable adversarial review-pattern catalog.

The Architect, Developer, and Reviewer all receive the same reusable adversarial patterns from
`review-patterns.yaml`. The catalog includes fail-open optional attestations, unbound evidence,
malformed-enum bypass, empty/non-convertible success, mutable-input TOCTOU, assertion-only evidence,
denial-vs-pending state semantics, duplicate identity, skipped-as-success, and boundary escape.

For reviewer-driven repair the required protocol is: reproduce the finding, add a regression that
fails before the fix, repair the underlying defect class, rerun the focused regression, then rerun
all deterministic gates. Closure review cannot recursively broaden the current item: only an
unresolved established blocker, deterministic-gate failure, or explicit acceptance-criteria
regression can consume another repair attempt. New sibling manifestations and hardening ideas are
persisted as deferred, non-blocking learning for future items. Continuations carry only unresolved
blockers; closed historical findings stay closed. Run records persist review mode, structured
finding packets, blocking and deferred scope, repair briefs, closure disposition, and reviewer
escape analyses.

### Cross-item learning

Reviewer findings are also recorded in `.smf-agent/review-learning.json`, which is intentionally
local and Git-ignored. Findings that match a curated static defect class increment that class's
observations. Genuinely novel findings receive a stable learned ID derived from their normalized
title. A bounded, severity-first set of novel lessons is injected into future Architect, Developer,
and Reviewer prompts across backlog items. The registry records first/last seen time, occurrence
count, backlog keys, source runs, and a conservative escape analysis.

The durable prompt remains bounded: the static catalog is curated in Git, while only the highest
value learned novel patterns are injected. The raw reviewer history remains in run records rather
than being copied wholesale into every future prompt.
