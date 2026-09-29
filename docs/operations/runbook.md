# Operator and Incident Runbook

This is the canonical operator entry point for the repository's current product CLI,
engineering-agent, and GitHub Project procedures. It describes a bounded offline foundation. It is
not a production orchestration guide, a live Humana procedure, or evidence of execution, parity,
certification, or production readiness.

## Current competition workflow boundary

The real local SAS data proof is an acceptance harness, not yet a unified migration command:

```bash
make vs01-confidence
make scale01-confidence
make cv04-confidence
```

`make vs01-confidence` proves the exact licensed `.sas7bdat -> pyreadstat -> Spark -> local Delta ->
DataComPy reconciliation -> immutable evidence` path. `make scale01-confidence` proves bounded
partitioned reading without whole-table collection. `make cv04-confidence` proves deterministic
`sas2databricks` package mechanics. None contacts live Humana, Databricks, Unity Catalog, AI Gateway,
or a model provider.

`smf migrate convert`, `modernize`, `status`, `resume`, `exceptions`, `approve`, and `promote` are
scaffolds: a valid invocation writes non-authorizing evidence and exits `2`. Operators must not use
them as evidence that a migration ran. The complete option-accurate examples and availability matrix
are in [CLI.md](../CLI.md).

## Multi-engineer integration control

- `origin/main` is the only completed baseline. Start from a fresh read-back, never from a dirty
  checkout or another engineer's feature branch.
- Maintain one active `competition/integration-<milestone>` train and at most one release PR from
  that train to `main`.
- Before implementation, record one assignee, one backlog key, non-overlapping modules/files,
  dependencies, current lifecycle state, and the integration target in the Project/ownership map.
- Human and autonomous feature branches target the same integration train. Each backlog record keeps
  a separate commit, focused evidence package, and independent local review.
- Rebase/read back immediately before acceptance. Do not stack unrelated branches, reuse another
  record's worktree, or create a duplicate implementation lane.
- Full suite, governed vulnerability audit, remote CI, and GitHub approval run once on the combined
  train at a meaningful 3–6-record milestone. Canonically close only records present in that exact
  reviewed tree.
- A blocker report names the record, owner, dependency/evidence missing, preserved commit/worktree,
  prohibited claims, and next permitted action. Check the ownership map before starting replacement
  work.

See [TEAM_ONBOARDING.md](../TEAM_ONBOARDING.md) for setup and ownership details.

## Safety contract

Stop before acting when identity, source bytes, policy, authority, or outcome is missing, malformed,
stale, conflicting, unsupported, or ambiguous. Never delete or rewrite canonical evidence to clear a
failure. Preserve the applicable client/deployment, workload, subject/artifact, source digest,
policy/configuration version, authority, run, attempt, and decision identity. Rehash or reload
qualified bytes before downstream use.

Treat `generated`, `authenticated`, `submitted`, `executed`, `validated`, `parity-passed`,
`certified`, and `human-approved` as separate evidence-backed claims. No claim implies another claim.
An exit code, caller-authored `passed`/`approved` value, signature label, or prose assertion is not
authority. Empty or comment-only SAS, a workload without an eligible entry point, unknown enum/type
values, duplicate or case-colliding identities, boundary escapes, incomplete source closure, and
cross-workload evidence are non-success.

The following commands are unsupported boundaries, not aliases: `smf run` does not exist and
`smf-agent supervised-run` does not exist. The repository provides no production control-plane
orchestration and no automatic Databricks retry. Do not invent live Humana contacts, endpoints,
credentials, tolerances, retention rules, or incident claims.

## Authority domains

### Product CLI authority

`smf` reads local inputs and emits stage-specific artifacts. Its status/disposition fields and
canonical manifests govern the result; the process exit code alone never authorizes downstream work.
It does not change GitHub state or approve a workload.

### Engineering-agent authority

`smf-agent` selects repository backlog work, creates or reuses isolated worktrees, invokes bounded
roles, and writes durable run records. `READY FOR HUMAN APPROVAL` is not a
commit, push, merge, issue closure, Project completion, deployment, execution, parity result,
certification, or human approval of any of those actions.

### GitHub Project authority

Project tools mutate issue text or lifecycle fields only through their documented, separately
approved operations. Acceptance publication, Priority changes, lifecycle completion, and epic
reconciliation are different authority decisions. A closed issue, `Done`, or `Foundation Complete`
alone is insufficient: completion is exactly Issue closed plus Project `Status == Done` and
`Implementation State == Foundation Complete`, after the approved commit is on `origin/main`.

## Exit and outcome rules

- `0` means only that the command reached its documented return path. Inspect the emitted canonical
  status, disposition, blockers, and bound evidence before proceeding.
- `1` generally means malformed input, operational failure, failed validation/execution, no ready
  engineering candidate, or a stopped engineering run. Preserve artifacts and diagnose.
- `2` is used by governed admission/qualification commands for a valid non-success disposition.
  It is not a shell/transport crash and must not be converted to success.
- `smf validate --json` may exit `0` when `status` is `failed`; automation must inspect `status`.
- `smf convert` exits `0` for `review_required`; this is not converted success and must not enter
  generated-success totals.
- `smf-agent plan` exits `0` even when `blockers` is non-empty; inspect `readiness` and `blockers`.
- `smf execute` can return `submitted` with exit `0`; `submitted` is not `executed`.
- `cancelled` is a recorded terminal disposition; never automatically retry `outcome_unknown`: an
  external side effect may have occurred. Escalate for authoritative reconciliation.

## Product command inventory

The first command token in this table is checked directly against `smf.cli.main.build_parser()`.

| Command | Purpose and evidence | Exit interpretation | Retry, stop, and escalation |
|---|---|---|---|
| `smf ai-gateway` | Namespace for `smf ai-gateway preflight`, which validates and binds the strict provider-neutral gateway configuration, deployment snapshot, implementation manifest, workload, run, and attempt without resolving credentials or contacting a provider. | `2` for valid offline configuration evidence blocked at external authority/connectivity; `1` for malformed, unsafe, changed, direct-provider, or publication-integrity failure. Exit `0` is unavailable in AIGW-01. | Use `examples/ai-gateway-preflight.yaml`; supply only opaque credential/CA/mTLS/header references. Treat the result as configuration-contract evidence, never connectivity or repair evidence. Synthetic mock outcomes cannot authorize execution. |
| `smf architecture-review` | Namespace for `smf architecture-review assemble`, which writes an immutable, offline, non-authorizing architecture/security packet and projection. | `0` only for `review_ready`; `2` for a valid blocked/non-ready packet; `1` for input or operational error. | Replay exact discovery/source/configuration bindings. Stop on missing closure, unsafe content, changed bytes, or unavailable authority; escalate to architecture/security owners. |
| `smf deployment-config` | Namespace for `smf deployment-config init`, `plan`, and `preflight`. `init` writes a deterministic template; `plan` publishes a non-mutating environment plan from opaque references; `preflight` emits offline binding checks. | `init`: `0` written, `1` error. `plan`: `0` complete offline plan, `2` valid blocked plan, `1` malformed/integrity failure. `preflight`: `0` only for `qualified`, `2` non-qualified, `1` error. | Never insert secrets into Git. Correct configuration in a new reviewed revision. Neither plan nor preflight is provider contact, live validation, provisioning, or readiness. |
| `smf discover` | Acquires supported local evidence and emits a canonical discovery model/inventory. | `0` discovery produced; `1` input, acquisition, or immutable-publication error. Inspect the payload. | Reuse the authorized source root; stop on traversal, symlink escape, duplicate identity, incomplete closure, or source mutation. Escalate unresolved discovery/provider coverage. |
| `smf intake-batch` | Verifies signed batch policy/manifest inputs and creates immutable attempt-isolated workload snapshots and result/projections. | `0` only for `admitted`; `2` valid blocked/rejected admission; `1` error. | Retry may recover missing projections from canonical state. Never overwrite results or select among duplicate identities; escalate policy/signature/source-closure failures. |
| `smf migrate` | Namespace for the offline `convert`, `modernize`, `status`, `resume`, `exceptions list|submit|decide`, `approve`, and `promote` contract scaffold. It qualifies and binds local inputs but performs no migration or lifecycle mutation. | `2` for every schema-valid scaffold result; `1` for malformed input or local integrity/publication failure. Exit `0` is unavailable. | Inspect canonical blockers and false lifecycle claims. Retry may recover missing telemetry from byte-identical canonical evidence; use a new attempt or invocation for changed inputs. Operational backends remain owned by later items. |
| `smf upstream` | Namespace for `smf upstream qualify`, which verifies the governed pinned-upstream inventory and signed offline artifact/license/capability evidence and publishes a signed non-authorizing result and bounded projection. | `qualify`: `0` only for complete `qualified`; `2` valid blocked/pending/denied/incompatible/stale/unsupported/failed result; `1` malformed or unverifiable input. | Never fetch or install. Stop on an unlisted upstream, license/disposition conflict, unsafe path, changed bytes, untrusted authority, absent canonical SEC-03 completion, or Reviewer rejection. Retry preserves the existing canonical decision and only recovers deterministic derivatives. |
| `smf acquire-baseline` | Imports a governed SAS baseline export and persists attributable acquisition evidence. | `0` only for `acquired`; `2` valid non-acquired result; `1` error. | Reuse exact intake/source/approval bindings. Never infer approval from a signed locator or caller label; escalate pending/denied/expired authority distinctly. |
| `smf assess` | Performs static per-file SAS assessment and optionally emits JSON/explanation. | `0` assessment produced; `1` read/parse/operational error. | Re-run only against unchanged bytes or record a new source revision. Assessment is not workload readiness, execution, or parity. |
| `smf convert` | Runs assessment-first conversion and emits generated artifacts/manifest or a non-success/review disposition. | `0` for `converted` **or** `review_required`; `2` for `unsupported`/blocked dispositions; `1` failure. Inspect `status`. | Stop on unsupported/ambiguous constructs, missing readiness, mutation, or review requirement. Do not retry provider/remote unknown outcomes or count review-required output as success. |
| `smf ready` | Qualifies canonical discovery plus governed evidence under a versioned policy and persists manifest/telemetry. | `0` only for `READY`; `2` for a valid non-ready classification; `1` malformed/operational error. | Preserve the attempt. New evidence normally creates a new attempt; only rebuild missing derived output from unchanged canonical evidence. Escalate pending/denied/conflicting authority. |
| `smf select-pilot` | Evaluates a governed offline inventory and policy and writes selection evidence. | `0` only for `qualified`; `2` valid non-qualified result; `1` error. | Preserve the full denominator and exclusions. Stop on incomplete closure, duplicate identity, caller-supplied qualification, or missing governed inputs. |
| `smf validate` | Performs static validation of source and generated artifact and writes validation results. | Non-JSON: `0` unless `status == failed`; failed returns `1`. JSON mode currently returns `0` after any produced result, including failed. | Always inspect `status`, checks, confidence, and review requirement. Preserve failure output; never treat static validation as semantic/data parity. |
| `smf validate-schema` | Compares authoritative source/target schema snapshots under a versioned policy and writes a manifest. | `0` only for `passed`; `1` failed comparison or error. | Stop on failed checks, unknown policy, stale/mismatched snapshots, or unbound dataset identity. A schema pass is not data or semantic parity. |
| `smf execute` | Executes in the selected validation provider boundary and emits an append-only result under the bound run/workload/attempt. | `0` for `succeeded` or `submitted`; `1` for blocked/failed/cancelled/unknown results or errors. Inspect `status`. | Supply stable `--run-id`, `--workload-id`, and `--attempt-id`. Never rerun a failed or timed-out attempt. Reconcile side effects first, then use a distinct attempt identity for an authorized retry. A claim without a manifest is `outcome_unknown` and retry is prohibited. |
| `smf verify-provenance` | Replays a non-authorizing offline provenance chain from exact lineage, original evidence, artifacts and a lineage-bound producer trust policy. | `0` only for reconstructed `validated`; `2` for a verified blocked, pending, denied, unsupported, cancelled, or failed disposition; `1` for malformed, ambiguous, missing, substituted, unsigned, or tampered evidence. | Never use the chain to authorize execution, approval, certification, promotion, or integration. Preserve missing and human-decision states; `parity_passed` and `certified` remain false in this bounded increment. |

`architecture-review` has only the nested operation `assemble`. `deployment-config` has only `init`,
`plan`, and `preflight`. `upstream` has only `qualify`. `ai-gateway` has only `preflight`. `migrate` has only
`smf migrate convert`, `modernize`, `status`, `resume`, `exceptions`, `approve`, and `promote`; `exceptions` has
only `list`, `submit`, and `decide`. A missing nested operation is usage error, never implicit
selection.

The environment-planning operation is invoked as `smf deployment-config plan`; it is offline and
non-mutating even when its configuration mode is `internal_provision`. The existing
`smf deployment-config init` and `smf deployment-config preflight` operations retain their prior
contracts.

## Engineering-agent command inventory

The first command token in this table is checked directly against
`smf.engineering_agent.cli.build_parser()`.

| Command | Purpose and evidence | Exit interpretation | Retry, stop, and escalation |
|---|---|---|---|
| `smf-agent next` | Recommends the next ready Project item; `--offline` reads the audit snapshot. | `0` candidate found; `1` no ready item/error. | Recommendation is not authorization. Resolve Project/dependency drift; never infer readiness from priority alone. |
| `smf-agent plan` | Prints deterministic readiness and blockers for one key. | Always `0` when a payload is produced, including blocked plans. | Inspect `readiness`, `blockers`, live Status, and Implementation State. Do not launch from `--offline`. |
| `smf-agent work` | Verifies live acceptance, creates an isolated worktree/run record, and runs supervised roles and gates. | `0` only when state reaches human review; `1` for stopped run. | Preserve `.smf-agent/runs/<key>/<run-id>/` and the existing worktree. Never launch with stale acceptance or unresolved blockers. |
| `smf-agent continue` | Opens a new, explicitly authorized bounded reviewer-closure window from the newest recoverable stopped run. | `0` only when the continuation reaches human review; `1` otherwise. | Use only for recoverable reviewer findings with attributable prior records and the existing worktree; never create a replacement workspace. Pre-review/gate failures require diagnosis, not continuation. |
| `smf-agent drain` | Locally processes eligible competition items sequentially and records drain evidence; may create gated local commits. | `0` only for exhausted eligible work; `1` when stopped. | Local-only commits are not push, merge, or completion. Stop on any unresolved finding, protected change, missing acceptance, or external action. |

## GitHub Project operations

Run these only from the repository root with current credentials and explicit human authorization.
They are not product or engineering-agent commands.

| Operation | Safe procedure | Stop/recovery rule |
|---|---|---|
| Acceptance publication | Run `bash scripts/project-tools/sync-acceptance-specs.sh dry-run`; review the complete report; apply only an explicitly selected key and reviewed report; then `verify --key <BACKLOG-KEY>`. | Apply records intent before each write and verification after read-back. If any update is unverified, stop; retain receipts, inspect remote state, and create a fresh dry-run. Never blind-retry. |
| Project status synchronization | Run `./scripts/project-tools/sync-project-status.sh dry-run`, then separately authorize `apply`. | Always pass explicit `dry-run` or `apply`; the script's default is unsafe for unattended use. This maps existing implementation state and does not decide it. |
| Item completion | After human review, approved commit integration, and all required evidence, run `./scripts/project-tools/complete-backlog-item.sh <BACKLOG-KEY> --comment "<evidence summary>"`. | Completion must run from clean, current `main` after the approved commit is on `origin/main`. Stop on any mismatch or missing evidence; do not repair state manually. |
| Epic reconciliation | Run `./scripts/project-tools/reconcile-epic-state.sh <EPIC-KEY> dry-run`, review actual Parent-field children, then separately authorize `apply`. | Always pass explicit mode. Unfinished/deferred children remain visible; never infer membership from key prefixes. |

When an unmanaged live body is byte-equivalent to its reviewed local specification, use the
explicit `dry-run --exact-source-adoption --key <KEY>` path documented in
`scripts/project-tools/README.md`. It replaces the raw body with one canonical managed block rather
than retaining a duplicate prefix. Any difference other than one terminal newline, any extra text,
or any key/identity/metadata drift blocks adoption. This path does not mutate Project fields or
lifecycle state.

## Incident playbooks

### Readiness state incident

- **Detect:** Inspect the persisted classification, blocker codes, policy digest, evidence bindings, and telemetry; distinguish missing, `pending`, `denied`, malformed, conflicting, and expired.
- **Preserve:** Retain the manifest, telemetry, exact discovery/evidence inputs, source digests, run, and attempt. Do not edit the attempt.
- **Contain:** Block conversion and downstream execution. Reject caller-authored approval/pass values and mismatched workload, digest, run, or attempt.
- **Diagnose:** Verify schemas/enums, signatures and configured authorities, freshness, unique identity, complete closure, and immutable source bytes.
- **Recover:** Supply governed evidence in a new attempt. Reconstruct only a missing derived file from unchanged canonical evidence.
- **Verify:** Reload the manifest, confirm exact bindings, and require a replay-valid `READY`; exit `0` alone is insufficient.
- **Escalate:** Route missing/pending authority to its named owner, denial to the decision owner, malformed evidence to its producer, and conflicts to security/governance.

### Conversion disposition incident

- **Detect:** Inspect `status`, manifest, unsupported constructs, applied rules, readiness binding, and output presence; distinguish `blocked`, `unsupported`, `review_required`, and `failed`.
- **Preserve:** Retain source snapshot/digest, assessment, registry/provider/config versions, run/attempt identity, generated bytes, and diagnostics.
- **Contain:** Prevent review-required, unsupported, partial, empty, comment-only, or no-entry-point work from generated-success totals or execution.
- **Diagnose:** Rehash source and policy, validate exact readiness and artifact identity, reject unknown target/provider/mode, and check boundary closure and duplicate rules.
- **Recover:** Fix supported input/configuration or obtain review in a new attributable attempt. Never bless output with caller-authored golden/approval data.
- **Verify:** Replay/reload canonical evidence and require the intended disposition plus exact source/output bindings; validation and parity remain separate.
- **Escalate:** Route unsupported SAS semantics or ambiguous rules to conversion engineering; route governed-policy gaps to the policy owner.

### Local execution or validation failure

- **Detect:** Inspect result `status`, provider, exit code, checks, stderr, output paths, and whether execution was only `submitted`.
- **Preserve:** Retain exact source/generated bytes and digests, provider/configuration, result artifacts, logs, run, and attempt.
- **Contain:** Stop promotion and parity claims. Keep static validation, execution, and semantic/data parity distinct.
- **Diagnose:** Do not reproduce a failed or timed-out artifact until its possible side effects are reconciled. Verify immutable inputs, target, schemas, dependencies, resource limits, boundary-contained paths, and the original attempt's claim and manifest.
- **Recover:** After attributable human reconciliation, correct the defect or configuration and use a distinct `--attempt-id` under the same run/workload. Never reuse the prior attempt, overwrite its claim/manifest, or silently relax checks. A claim without a terminal manifest is `outcome_unknown` and blocks retry.
- **Verify:** Confirm the original manifest is byte-for-byte unchanged, the retry has a separate attempt path, and all applicable checks pass. A mock/local success cannot satisfy real-environment evidence.
- **Escalate:** Route transformation defects to engineering, policy/tolerance questions to named owners, and runtime/provider defects to platform operations.

### Missing workspace, identity, secret, catalog, schema, or permission

- **Detect:** Read the categorical result; keep `blocked_missing`, `blocked_pending`, `denied`, expired, wrong-workspace, wrong-identity, permission-denied, unsupported, and provider-unavailable distinct.
- **Preserve:** Retain sanitized result, configured non-secret identifiers, required permission list, policy/version, authority, run, attempt, and decision identity.
- **Contain:** Stop before provider action when admission is incomplete. Never print, hash, persist, or paste a credential or protected identity value into evidence.
- **Diagnose:** Verify configured workspace/catalog/schema, secret reference, identity, exact permissions, evidence freshness, and trusted authority without exposing secret bytes.
- **Recover:** The responsible owner updates the governed configuration or permission. Start a new attributable attempt; never fabricate a receipt.
- **Verify:** Re-run the boundary and inspect the terminal categorical state. Authentication proves only authentication, not submission or execution.
- **Escalate:** Route access denial to the named access owner, missing client inputs to the client owner, secret exposure to security, and provider outage to platform operations.

### Engineering-agent stop

- **Detect:** Inspect the printed worktree/run directory, `run.json`, role artifacts, gates, findings, and final state; identify Architect, Developer, gate, or Reviewer stop.
- **Preserve:** Retain `.smf-agent/runs/<key>/<run-id>/`, the existing worktree, diff, gate output, findings, and continuation chain.
- **Contain:** Do not commit, push, merge, publish, close, or mutate Project state. Do not run `continue` for pre-review or non-recoverable failures.
- **Diagnose:** Confirm live acceptance freshness, protected-path integrity, exact failed gate/finding family, available worktree, and bounded repair eligibility.
- **Recover:** For authorized recoverable reviewer findings only, use `smf-agent continue <key>` so the new run points to the stopped run and reuses the existing worktree; never create a replacement workspace.
- **Verify:** Require all gates and independent review to pass and inspect the complete run chain. `READY FOR HUMAN APPROVAL` still requires human disposition.
- **Escalate:** Escalate missing worktrees/evidence, acceptance conflicts, protected changes, repeated finding families, or required external actions to the maintainer.

### Interrupted canonical or derived publication

- **Detect:** Inspect claim/intent markers, canonical result existence and validity, and missing telemetry/projections; a marker without a result is `outcome_unknown`.
- **Preserve:** Retain every canonical file, marker, temporary artifact, digest, lock record, run, attempt, and decision identity; do not clean up first.
- **Contain:** Prevent a second external invocation or reevaluation. Quarantine corrupt/conflicting derived output without altering canonical evidence.
- **Diagnose:** Validate canonical bytes/signature/schema and determine whether the interruption preceded or followed the potentially state-changing action.
- **Recover:** If canonical evidence is valid, idempotently reconstruct only missing derivatives from it. If outcome is unknown, reconcile externally or escalate; do not retry.
- **Verify:** Confirm canonical digest/decision identity is unchanged and reconstructed derivatives deterministically match it.
- **Escalate:** Escalate any corrupt canonical result, conflicting decision, ambiguous side effect, or recovery requiring overwrite/deletion.

### Partial acceptance-body publication

- **Detect:** Inspect the acceptance-sync report plus per-item intent and verification receipts; compare exact remote read-back and metadata.
- **Preserve:** Retain the reviewed dry-run, before/after bodies, hashes, intent, verification, resolved IDs, and remote snapshot.
- **Contain:** Stop the batch. Do not roll back successful earlier writes automatically and do not reuse the old report.
- **Diagnose:** Identify verified writes, intent-without-verification, remote drift, ambiguous markers, duplicate keys, or concurrent edits.
- **Recover:** Re-read remote state, resolve discrepancies with a human, generate a fresh dry-run, and apply only newly approved exact keys.
- **Verify:** Run `verify --key <BACKLOG-KEY>` and require exact managed-section read-back. Publication does not approve implementation.
- **Escalate:** Escalate unknown remote outcome, concurrent edits, malformed markers, identity mismatch, or any requested lifecycle/priority change.

### Sensitive-data or credential exposure

- **Detect:** Treat a synthetic canary hit, client byte outside authorized scope, credential pattern, secret in output/error, or unsafe identity persistence as an incident.
- **Preserve:** Preserve only sanitized metadata and authorized forensic references; do not copy the exposed value into tickets, hashes, logs, or this repository.
- **Contain:** Stop processing and sharing, isolate affected artifacts according to approved security procedure, and revoke/rotate credentials through the owner.
- **Diagnose:** Determine input/error/artifact/telemetry boundaries affected, recipients, persistence, and whether untrusted instructions altered policy or endpoints.
- **Recover:** Use the enterprise security process to sanitize or remove exposure while retaining an attributable incident record; reacquire clean governed inputs.
- **Verify:** Re-run canary and secret scans and confirm no protected bytes remain in unauthorized artifacts, history, or derived evidence.
- **Escalate:** Notify the authorized security/privacy owner immediately. Do not invent Humana contacts or retention actions.

### Mutable or conflicting evidence

- **Detect:** Rehash qualified source/policy/evidence before use; detect digest, authority, version, identity, duplicate/case collision, or decision conflicts.
- **Preserve:** Retain both versions and acquisition metadata without selecting or rewriting either; bind all observations to run/attempt.
- **Contain:** Stop downstream work and reject stale recall, caller assertions, ambiguous matches, symlink/traversal escapes, and cross-client/workload references.
- **Diagnose:** Compare canonical bytes/digests, trust roots, source closure, policy versions, supersession/rejection state, and selection rationale.
- **Recover:** Obtain a governed authoritative resolution and create a new decision/attempt from immutable bytes. Never coordinate source and golden changes to bless drift.
- **Verify:** Revalidate at the consumption boundary and require one unique, exact, policy-allowed identity with reconstructable evidence.
- **Escalate:** Escalate unresolved conflicts, duplicate authority, mutable canonical state, or any request to waive source fidelity.

### Completion-state disagreement

- **Detect:** Compare issue state, Project Status, Implementation State, approved commit on `origin/main`, gate/review evidence, and item/epic identity.
- **Preserve:** Retain read-only Project/Issue snapshots, commit identity, CI/run references, completion command output, and any partial mutation evidence.
- **Contain:** Do not rerun completion blindly, manually edit fields, close/reopen issues, or infer epic completion from names.
- **Diagnose:** Determine which separately governed action is absent or failed and whether local `main` is clean/current with the approved commit.
- **Recover:** After human disposition, use the supported completion utility from clean current `main`; then dry-run/apply epic reconciliation separately if authorized.
- **Verify:** Re-read the exact Issue and Project item and require closed plus `Done / Foundation Complete`; verify Parent-field child reconciliation independently.
- **Escalate:** Escalate unknown mutation outcome, identity mismatch, inconsistent remote state, missing approval/evidence, or any need for manual repair.

## Threat-pattern review checklist

- Reject optional/caller-supplied success attestations; require governed, reconstructable evidence.
- Bind evidence to exact subject/source/policy/authority/run/attempt/decision and reject replay.
- Reject unknown enum/type/status/reason values; never fall back to a permissive path.
- Require a meaningful eligible subject; reject empty/comment-only/no-entry-point input.
- Rehash qualified mutable inputs immediately before consumption.
- Keep missing/pending human action distinct from explicit denial/failure.
- Reject duplicate/case-colliding identities and multiple active matches.
- Keep blocked, skipped, unsupported, review-required, generated-only, mock-only, and unexecuted work out of success totals.
- Reject traversal, symlink escape, incomplete closure, cross-workload evidence, and unresolved dependencies.
- Preserve append-only canonical evidence; reconstruct missing derivatives without reevaluation or decision-identity change.

## Deterministic evidence references

The selectors below are deliberately checked by the runbook contract test. They provide offline
counterexamples for permission denial, stopped-run recovery, partial publication, append-only
recovery, two-workload isolation, source mutation, duplicate identity, and false-success handling.

<!-- verified-references:begin -->
- `tests/unit/test_databricks_auth_boundary.py::test_denial_pending_missing_and_expiry_remain_distinct`
- `tests/unit/test_databricks_auth_manifest.py::test_claim_without_result_is_outcome_unknown_and_not_retried`
- `tests/unit/test_engineering_agent.py::test_latest_stopped_run_selects_newest_stopped`
- `tests/unit/test_engineering_agent.py::test_continuation_run_records_parent`
- `tests/unit/test_acceptance_sync.py::test_partial_failure_retains_intent_without_false_verification`
- `tests/unit/test_baseline_acquisition.py::test_retry_recovers_derivatives_without_overwriting_canonical_result`
- `tests/unit/test_baseline_acquisition.py::test_approval_cannot_be_replayed_to_changed_source_subject`
- `tests/unit/test_batch_intake.py::test_two_workloads_are_canonical_isolated_and_truthful`
- `tests/unit/test_batch_intake.py::test_repeat_is_idempotent_and_changed_bytes_create_revision`
- `tests/integration/test_cli_conversion_validation.py::test_conversion_exit_status_does_not_report_blockers_as_command_success`
- `tests/integration/test_cli_execute.py::test_json_execute_returns_nonzero_for_blocked_result`
- `tests/integration/test_execution_schema.py::test_failed_state_changing_execution_cannot_repeat_or_overwrite_attempt`
<!-- verified-references:end -->

Run `python -m pytest -q tests/unit/test_operator_runbook.py` after any parser or runbook change.
Run `bash scripts/ops03-affected-regressions.sh` for the checked-in affected-suite selector manifest.
Network-dependent or
live-environment checks that are unavailable remain explicitly unavailable, never passed.
