# Backlog Engineering Workflow

This is the canonical operator sequence for GitHub Project lifecycle changes and supervised
engineering-agent execution. Run commands from the primary repository checkout unless a step
explicitly names the agent worktree.

## 1. Prepare the authoritative branch

```bash
source .venv/bin/activate
git checkout main
git pull --ff-only
git status --short
```

Resolve unexpected local changes before creating an agent worktree. `work` branches from local
`main`, not directly from `origin/main`.

## 2. Select and inspect work

For the ten-week, 1,000-script Humana competition, first use the reconciled
[delivery plan](../competition/COMPETITION-PLAN.md) and phase-scoped read-only queue:

```bash
python -m smf.engineering_agent.competition_plan --validate-only
python -m smf.engineering_agent.competition_plan
```

The queue excludes Phase 2/later work, unactivated conditional work, epics, duplicate task packets
and completed foundations. Eligibility checks live contract dependencies, not client or launch
approval. Ordinary `next` below still uses live Project priorities, not local competition phases.
Before launching, reconcile the intended phase/priority, synchronize and verify acceptance, resolve
parent/task discrepancies and obtain approval for the bounded increment. Readiness does not prove
actual SAS baseline acquisition, Databricks execution or parity.

Completion uses the same canonical rule in both queues: `Status = Done` **and**
`Implementation State = Foundation Complete`. Closing an issue is not implementation evidence.
Contradictory lifecycle fields or a closed-but-incomplete issue remain explicit reconciliation
blockers in the competition queue, including when encountered on a dependency.

```bash
python -m smf.engineering_agent next
python -m smf.engineering_agent plan <BACKLOG-KEY>
```

Live mode reads GitHub Project #2. `plan` returns zero even when its report contains blockers, so
operators and automation must inspect `readiness` and `blockers`.

Use `--offline` only with a deliberately refreshed `.project-audit/items.json`. The snapshot is
not automatically refreshed and may omit newer items or issue-body changes.

## 3. Start a new backlog item when required

If the item is still a Project draft or `Todo / Not Started`, start it before engineering:

```bash
./scripts/project-tools/start-backlog-item.sh <BACKLOG-KEY>
```

The command promotes a draft to a repository Issue when necessary and verifies
`In Progress / Partial`. Do not rerun it merely because an already-active item is being resumed.

Before execution, confirm that the live Issue body contains concrete, item-specific acceptance
criteria. The engineering-agent prompt uses that body as its acceptance context.

For keys in `competition/generated/replan.yaml`, review and publish the local spec with
`bash scripts/project-tools/sync-acceptance-specs.sh dry-run`, inspect the generated report, then
apply only explicitly approved keys. Run `verify --key <BACKLOG-KEY>` to check the read-back.
See the project-tools README for the exact apply syntax and failure recovery. Draft publication
does not promote/start the item. Completed items are blocked pending separate follow-up review.

`work` and `continue` require a current managed live section matching both the local specification
and shared policy for competition keys. `--offline` cannot establish that match. Local changes
invalidate the match automatically; publishing alone does not authorize execution or completion.

## 4. Run supervised engineering

```bash
python -m smf.engineering_agent work <BACKLOG-KEY>
```

The installed equivalent is `smf-agent work <BACKLOG-KEY>`. Do not invoke
`python -m smf.engineering_agent.cli`.

The command creates:

- branch `agent/<lowercase-backlog-key>`;
- worktree `../.smf-agent-worktrees/<lowercase-backlog-key>/`;
- run evidence `.smf-agent/runs/<BACKLOG-KEY>/<UTC-RUN-ID>/`.

The default run performs Architect, Developer, deterministic gates, and Reviewer stages. One
initial Developer attempt and up to two repair attempts are permitted by default.

### Autonomous Humana competition drain

After the competition plan and live acceptance have been reconciled, an operator may authorize a
local-only continuous drain from a clean, current `main` checkout:

```bash
git checkout main
git pull --ff-only
git status --short
source .venv/bin/activate
python -m smf.engineering_agent drain
```

If the package entry points are installed, `smf-agent drain` is equivalent.

`drain` repeatedly selects the first eligible `competition-critical` item from the governed
competition queue. Each item runs the same Architect, Developer, deterministic gates, independent
Reviewer, and bounded repair workflow as `work`. A passing candidate is committed locally as
`feat: implement <BACKLOG-KEY>`. Its commit becomes the immutable base for the next item, allowing
dependencies completed during this invocation to become eligible without claiming that GitHub or
the Project has been updated.

Immediately before each commit, the drain refreshes the live Project and requires the selected
record, acceptance body, lifecycle fields, identity, and dependency eligibility to match the
snapshot used to launch the item. Any drift stops before commit. The final successful item's
`agent/<lowercase-backlog-key>` branch contains the complete ordered commit chain.

The drain never pushes, opens or merges a pull request, promotes a draft, starts or closes an Issue,
changes Project fields, reconciles an epic, deploys, or performs another external/destructive action.
It records durable local state under `.smf-agent/drains/<UTC-RUN-ID>/drain.json` and preserves every
item worktree and run record for review.

For an explicitly approved bounded wave on a clean review branch, repeat `--scope-key KEY` for
every authorized record and pass the exact branch with `--base-branch`. The default remains a clean
`main` exactly matching `origin/main`. `--continue-external-blockers` records an unpromoted draft as
blocked and continues with another scoped runnable item; it never promotes the draft or widens the
scope. The exact scope and base are preserved in the drain directory's `scope.json`.

The drain stops for stale or contradictory acceptance/lifecycle state, a draft or other required
external action, protected-path changes, exhausted gates or unresolved Reviewer rejection,
contractual/business ambiguity surfaced by the governed acceptance boundary, a commit failure, or
an unexpected/systemic orchestration conflict. An isolated Architect/Developer/Reviewer process
failure is recorded as a technical blocker and skipped; its dependent items remain blocked. This
skip rule does not apply to a substantive Reviewer rejection or a failing deterministic gate.

## 5. Handle a stopped run

Read the printed run directory, especially:

- `final-report.md`;
- `run.json`;
- `gates-*.json`;
- `reviewer-final-*.md`;
- `review-findings-*.json`;
- `review-scope-*.json`.

When the stopped run has reviewer findings, its worktree still exists, and a human authorizes a new
bounded closure window, run:

```bash
python -m smf.engineering_agent continue <BACKLOG-KEY>
```

`continue` reuses the worktree, creates a linked run record, skips Architect, and carries only the
unresolved blocking scope into a new repair window. It cannot generally resume a failure that
occurred before Reviewer produced findings.

## 6. Review and integrate

For `work` and `continue`, `READY FOR HUMAN APPROVAL` means the candidate passed the orchestrated
gates and bounded review; it is still uncommitted. In `drain`, the operator has authorized the
additional local commit step only. It still does not mean the change was pushed, merged, or marked
complete.

Inspect the candidate worktree:

```bash
git -C ../.smf-agent-worktrees/<lowercase-backlog-key> status --short
git -C ../.smf-agent-worktrees/<lowercase-backlog-key> diff --check
git -C ../.smf-agent-worktrees/<lowercase-backlog-key> diff
```

Review the run evidence and deferred findings. Then commit, push, open/review the pull request, and
merge using the repository's normal human-controlled process.

## 7. Complete Project governance

Only after the approved commit is present on `origin/main`:

```bash
git checkout main
git pull --ff-only
git status --short
./scripts/project-tools/complete-backlog-item.sh <BACKLOG-KEY> --comment "<verification and approval summary>"
```

The completion command closes the Issue and verifies `Done / Foundation Complete`. Run it from
`main`; its current safety check proves only that the current branch equals the corresponding remote
branch.

For an item with a parent epic, inspect and then apply derived epic state:

```bash
./scripts/project-tools/reconcile-epic-state.sh <EPIC-KEY> dry-run
./scripts/project-tools/reconcile-epic-state.sh <EPIC-KEY> apply
```

Select the next item from live state:

```bash
python -m smf.engineering_agent next
```

## 8. Cleanup

Remove the worktree and branch only after integration and only after confirming that the worktree is
clean and the branch is merged. Resolve the exact path with `git worktree list`; do not delete the
directory directly.

```bash
git worktree list
git worktree remove ../.smf-agent-worktrees/<lowercase-backlog-key>
git branch -d agent/<lowercase-backlog-key>
```

Run records and cross-item reviewer learning under `.smf-agent/` are local evidence. Preserve them
for audit and future-agent learning according to the repository's retention policy.
