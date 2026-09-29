# SMF Project Management Tools

These are the supported repository utilities for keeping GitHub Project #2 aligned with engineering state. The GitHub Project is the source of truth for mutable implementation state; repository scripts should provide repeatable operations, not preserve one-time migration or reconciliation history.

## Operating model

```text
Planning backlog
Project draft / Not Started / Todo
              |
              | engineering begins
              v
Repository Issue / Partial / In Progress
              |
              | verified foundation complete
              v
Closed Issue / Foundation Complete / Done
```

## Supported utilities

### `sync-acceptance-specs.sh`

Publishes reviewed competition acceptance text, **not lifecycle fields**. Specs and the replan
under `competition/generated/` are narrowly unignored for version control; other generated output
and `.project-audit/` stay ignored. Add the intended documents to a reviewed commit to preserve them.

From the primary checkout with its virtual environment active:

```bash
bash scripts/project-tools/sync-acceptance-specs.sh dry-run
bash scripts/project-tools/sync-acceptance-specs.sh verify --key AIP-01
```

Dry-run reads the viewer-owned Project specified in `competition/generated/replan.yaml`, matches
by exact Backlog Key and exports timestamped JSON under `.project-audit/acceptance-sync/`. Each
record includes update/unchanged/blocked disposition, before/after bodies for publishable records,
warnings, resolved IDs and source/remote hashes. No issue or Project mutation occurs. `verify`
returns nonzero for missing/stale/blocked selected records and never publishes or grants approval.

Reports also show delivery phase, dependencies and live-to-planned priority differences from the
reconciled [ten-week competition plan](../../competition/COMPETITION-PLAN.md). These are proposals:
body apply does **not** update Project priority or phase fields. Such field changes need a separate
reviewed operation with fresh identity/metadata checks and read-back. Regenerate the dry-run after
any spec, policy or replan change; do not reuse older reports or run a broad replan apply as a shortcut.

Review the exact before/after text, including existing scope outside the proposed section. After
explicit approval, select keys individually (repeat `--key` for multiple approved records):

```bash
bash scripts/project-tools/sync-acceptance-specs.sh apply \
  --report .project-audit/acceptance-sync/dry-run-<timestamp>.json --key AIP-01
```

An unmanaged body that is already an exact copy of its reviewed local issue specification can be
adopted without retaining a duplicate prefix. This path is opt-in and requires explicit unique key
selection during the dry run:

```bash
bash scripts/project-tools/sync-acceptance-specs.sh dry-run \
  --exact-source-adoption --key DBENV-01 --key DBENV-02 --key DBENV-03
bash scripts/project-tools/sync-acceptance-specs.sh apply \
  --report .project-audit/acceptance-sync/dry-run-<timestamp>.json \
  --key DBENV-01 --key DBENV-02 --key DBENV-03
```

Exact-source adoption is available only when the complete live body matches the raw local source,
allowing only GitHub's removal of one terminal newline, and no managed marker is present. The
proposed body is one canonical managed block containing one source and one shared policy. Any extra
prefix/suffix, whitespace/content change, CRLF/carriage return, duplicate source, reserved or
malformed marker, stale report, changed identity/metadata, or apply-key mismatch fails closed. The
generated block must contain exactly one correct source-fingerprint marker. The dry-run records byte
counts and hashes for the before/after bodies, raw source, policy and managed block; it never changes
Project fields or lifecycle state. A second dry run after adoption must report `unchanged`.

Apply accepts only an unchanged reviewed report and unchanged local/remote inputs. It replaces a
single marked acceptance section or appends one while retaining existing text except the narrowly
reported legacy priority-line correction described below, and embeds the
full shared policy so local Markdown links are not required by the agent. It updates an existing
repository Issue body or Project DraftIssue body; it never creates/promotes/reopens/closes items,
changes titles, or changes status/priority/parent fields. Completed records require separate
follow-up review and are blocked from bulk publication. Missing/duplicate keys, foreign-repository
items, stale planned issue numbers, malformed markers and credential-bearing content fail closed.

If the unmanaged body contains exactly one `- Competition Priority: P0`-style line, dry-run proposes
changing only its priority value to the local competition horizon. The `unmanaged_priority_edit`
field records the exact old/new line; the full before/after body remains the approval input. This
does not change the Project Priority field. Multiple matching legacy labels block publication;
other prose is never rewritten automatically. An approved apply uses the existing identity, drift,
intent and read-back safeguards for the complete proposed body.

Records marked `reconcile-task-with-completed-parent` are blocked from publication and from
`work`/`continue`, even if a managed acceptance section already matches. Review their criterion-level
evidence, obtain an explicit disposition, and update the local review marker before a fresh dry-run.
The marker is not a substitute for live Project status and does not close or reopen a task.

Publication records intent before each write, then re-reads the body and captured metadata and
records verification only on an exact match. A partial failure stops the batch; successful earlier
writes remain. Inspect intent/verification files and generate a new dry-run before resuming. There
is no automatic rollback or blind retry. Immediate pre-write checks reduce concurrent-edit risk,
but GitHub body updates are not an atomic compare-and-swap: avoid concurrent editing during apply.
This tool cannot promise to prevent an edit racing between the final read and the remote write.

`work` and `continue` now compare the complete local spec plus shared policy with the managed live
acceptance section for competition keys. Stale/missing text or `--offline` blocks the launch before
worktree creation/continuation. This is content freshness verification, not an authenticated human
approval attestation. Other live issue text remains acceptance context and must be reviewed for
contradictions. Deferred priorities, required readiness checks and final human approval still apply.

Reports are local snapshots and can contain existing issue text: handle them according to client
policy. Publication lint rejects explicit credential patterns rather than exporting them, but cannot
classify every kind of PHI/PII. No live private-client material should be copied into shared specs.

### `verify-project-status.sh`

Prints separate aggregate GitHub Project Status and Implementation State counts. It is a summary,
not a pairwise consistency check for each item. Lifecycle mutation commands perform targeted
post-mutation verification for the item they changed.

```bash
./scripts/project-tools/verify-project-status.sh
```

### `export-project-audit.sh`

Exports current Project metadata into the gitignored `.project-audit/` directory and packages the evidence as `smf-project-audit.zip`.

```bash
mkdir -p .project-audit
./scripts/project-tools/export-project-audit.sh
```

### `sync-project-status.sh`

Maps an already-correct Implementation State to the corresponding GitHub Status:

```text
Foundation Complete -> Done
Partial             -> In Progress
Not Started         -> Todo
Needs Review        -> Todo
```

It does **not** infer Implementation State from repository code, tests, issue state, or documentation.

Use a dry run first:

```bash
./scripts/project-tools/sync-project-status.sh dry-run
```

Apply only after reviewing the proposed changes:

```bash
./scripts/project-tools/sync-project-status.sh apply
```

The script currently defaults to `apply` when no mode is supplied. Always pass `dry-run` or `apply`
explicitly.

## Repository hygiene

Do not add per-work-item `start-*`, `complete-*`, historical reconciliation, or Project bootstrap scripts to the supported toolset. Those are transient engineering operations and belong in Git history, not the long-lived collaborator-facing repository.

If a Project operation becomes repeatable across work items, implement it as a generic utility with documented inputs and safety checks.

`.project-audit/` is generated local evidence and remains gitignored.

### `start-backlog-item.sh`

Starts a backlog item using its stable `Backlog Key`. The tool dynamically resolves Project metadata, promotes a draft item to a repository Issue when necessary, sets `Implementation State = Partial` and `Status = In Progress`, then re-queries GitHub and fails if the expected state is not observed.

```bash
./scripts/project-tools/start-backlog-item.sh MOD-04
```

### `complete-backlog-item.sh`

Completes an already-started backlog item. The tool fails closed unless the Git working tree is clean and local `HEAD` exactly matches the current branch on `origin`. It closes the Issue, sets `Implementation State = Foundation Complete` and `Status = Done`, then verifies both the Project state and closed Issue state.

```bash
./scripts/project-tools/complete-backlog-item.sh MOD-04 \
  --comment "MOD-04 foundation complete. Verification summary..."
```

Both lifecycle tools resolve Project item IDs, field IDs, option IDs, repository node IDs, and Issue numbers at runtime. Do not hard-code those mutable identifiers into engineering workflows.

Run `complete-backlog-item.sh` from a clean, updated `main` checkout only after the approved change
is present on `origin/main`. The implementation verifies that the current branch matches its remote,
but does not itself require the branch name to be `main`.

### `reconcile-epic-state.sh`

Derives an epic's Project state from the `Implementation State` values of items whose `Parent` field points to that epic. It does not infer engineering completion from source code, issue bodies, or documentation.

```text
all children Foundation Complete        -> Foundation Complete / Done
any child Partial or Foundation Complete -> Partial / In Progress
otherwise any child Needs Review        -> Needs Review / Todo
otherwise                               -> Not Started / Todo
```

Always review a dry run first:

```bash
./scripts/project-tools/reconcile-epic-state.sh EPIC-MOD dry-run
```

Then apply:

```bash
./scripts/project-tools/reconcile-epic-state.sh EPIC-MOD apply
```

The script currently defaults to `apply` when no mode is supplied. Always specify the mode.

The epic may remain a Project draft item. Reconciliation changes only the Project's mutable governance fields and does not create or close repository Issues.

## GraphQL quota discipline

ProjectV2 item enumeration is expensive. Lifecycle commands load the Project item collection at most once per process and reuse that snapshot for lookups and summaries. Post-mutation state verification uses a targeted GraphQL query against the known ProjectV2 item ID instead of enumerating the full Project again. Repository Issue reads and writes continue to use `gh issue`/REST-backed operations where possible.

Do not add repeated `gh project item-list --limit 1000` calls to a lifecycle command. If a mutation changes DraftIssue/Issue identity and a refresh is required, explicitly invalidate the in-process snapshot before reloading it.

### GraphQL efficiency

The shared lifecycle helpers used by start, complete, verify, and epic reconciliation use
purpose-built GraphQL projections. Project item pagination requests only lifecycle fields and is
cached for the life of the process. Single-item post-mutation verification queries the known item
node directly. The bulk export and synchronization utilities still use `gh project item-list` and
`gh project field-list`; treat those as deliberate bulk operations.

The shared lifecycle tools honor `SMF_PROJECT_OWNER`, `SMF_REPO_OWNER`, `SMF_REPO`, and
`SMF_PROJECT_NUMBER`. The current export and synchronization scripts retain their own fixed
owner/project defaults.

## OSS-first recovery backlog integrity

After materializing the accepted recovery report locally, generate a fresh read-only acceptance
report and validate it against the current plan and the pre-materialization baseline:

```bash
python -m smf.engineering_agent.acceptance_sync dry-run
python scripts/project-tools/validate-recovery-backlog.py \
  --acceptance-report .project-audit/acceptance-sync/dry-run-<UTC>.json \
  --baseline-ref main \
  --output .project-audit/recovery-backlog-integrity-<UTC>.json
```

The validator makes no GitHub writes. It proves identifier/dependency integrity, cycle freedom,
unfinished-dependency priority, completed-record immutability, exact generated-surface agreement,
the seven initially runnable roots, and downstream dependency blocking. Missing live items are
accepted only when they are exactly the 19 explicitly unpublished recovery records. Completed
items remain protected, and update rows are publication diff—not publication authorization.
