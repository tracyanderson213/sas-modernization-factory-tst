# OPS-03 Acceptance Evidence

## Scope and evidence identity

- Backlog item: `OPS-03`
- Issue: `#100`
- Source commit under review (candidate base):
  `a58399c8337a199b15a0edbb2db7ff449b02f13a`
- Live acceptance source digest:
  `ab9f0f71a218775e236cdf4e1654685a203b681aaffe68fa866334088a5602aa`
- Evidence scope: bounded offline operator/incident runbook foundation
- Evidence authority: repository parsers, reviewed documentation, deterministic tests, and their
  captured run/CI records; no manually authored `PASS` value is acceptance evidence

The exact approved candidate commit does not exist until a human integrates this change. Local test
output is reproducible developer evidence, but is not an immutable CI artifact. Rows relying on the
candidate therefore remain **locally verified; immutable evidence pending** until an approved commit
and attributable CI/run record exist. This document records no live Humana execution claim.

## Acceptance matrix

| Criterion | Test / review procedure | Expected outcome | Actual outcome and exact exit | Safe evidence reference | Status |
|---|---|---|---|---|---|
| OPS-03-AC01 | Review `docs/operations/runbook.md`; run `python -m pytest -q tests/unit/test_operator_runbook.py`. | Every parser-exposed product and agent flow has purpose, evidence, exit semantics, retry/stop/escalation, plus ten complete incident playbooks. | `7 passed`; exit `0` in the final developer run. | Base commit above + candidate diff; selector `tests/unit/test_operator_runbook.py`; future approved commit/CI artifact required. | Locally verified; immutable evidence pending. |
| OPS-03-AC02 | Parser comparison in `test_runbook_command_inventory_matches_current_parsers`; reference validation in `test_runbook_references_existing_paths_and_test_selectors`. | Commands match current code, referenced paths/selectors exist, recovery retains the run directory/worktree, and unsupported commands are rejected. | Both tests passed within the `7 passed` run; command exit `0`. | Base commit + candidate diff and future CI; authoritative parsers are `src/smf/cli/main.py` and `src/smf/engineering_agent/cli.py`. | Locally verified; immutable evidence pending. |
| OPS-03-AC03 | Run the focused runbook test plus `bash scripts/ops03-affected-regressions.sh`; review every playbook's contain/recover rules. | Permission denial, stopped runs, partial publication, unknown outcome, source mutation, duplicate identity, false success, and append-only recovery remain visible and cannot bypass approval or erase evidence. | Focused `7 passed`; final affected regression script `141 passed in 11.85s`; both exited `0`. | Base commit + candidate diff; checked-in executable selector manifest plus named runbook selectors; future approved commit/CI required. | Locally verified; live procedures blocked and immutable evidence pending. |
| OPS-03-AC04 | Review the failure/recovery experiments referenced by the runbook; run focused, affected, full, confidence, and diff gates. | Offline counterexamples pass; a failed state-changing execution cannot repeat in the same attempt or overwrite its manifest; an interrupted claim blocks as unknown outcome; a reconciled retry has a distinct attempt path; two-workload isolation is demonstrated; live requirements remain blocked. | Focused and affected suites passed; full pytest `1428 passed in 145.05s`; all three discovery gates passed; each exited `0`. Aggregate `make verify` exited `2` only because the network-dependent audit was unavailable. | Base commit + candidate diff; gate commands/results below; future approved commit/CI required. | Applicable offline tests locally verified; dependency audit/immutable evidence pending. |
| HC-01 | Review Safety contract/claim separation; execute evidence-binding, cross-workload, source-replay, and execution-attempt regressions in the affected suite. | Results bind applicable client/deployment, workload, subject/artifact, source digest, policy/configuration, authority, run, attempt, and decision; missing bindings block. | Affected suite `141 passed in 11.85s`, exit `0`; execution manifests now bind run/workload/attempt plus source/generated digests. | `test_approval_cannot_be_replayed_to_changed_source_subject`, `test_two_workloads_are_canonical_isolated_and_truthful`, `test_failed_state_changing_execution_cannot_repeat_or_overwrite_attempt`, and approved CI/run evidence when available. | Locally verified only; live Humana evidence blocked. |
| HC-02 | Review the runbook's stale/conflicting evidence procedure and confirm the acceptance path adds no recall service. | Recalled/derived advice is advisory; conflicts and supersession stay visible; OPS-03 has no durable recall dependency. | Documentation review encoded by focused tests; exit `0`. Execution recovery changed only to enforce append-only evidence and does not add recall behavior. | Candidate diff plus protected-path check in Gate results. | Locally verified; immutable review pending. |
| HC-03 | Review source-fidelity/claim boundaries; run conversion false-success and mutation regressions. | SAS source, generated target, and validation/parity claims remain distinct; unsupported/review-required work does not become success. | Affected suite `141 passed in 11.85s`, exit `0`; focused suite `7 passed`, exit `0`. | `test_conversion_exit_status_does_not_report_blockers_as_command_success`, source-mutation tests in the affected suite, and future CI. | Locally verified only; live parity blocked. |
| HC-04 | Review sensitive-data playbook and boundary rules; run Databricks auth, intake, baseline, acceptance-sync, and repository gates. | Synthetic canaries and unsafe identities are rejected/sanitized; no secret/client bytes enter docs/evidence; untrusted instructions cannot alter authority. | Affected suite `141 passed` and full pytest `1428 passed`, exit `0`; `pip-audit` could not resolve pypi.org and exited `1` (`make verify` exit `2`). | Affected tests and `make verify`; future approved commit/CI artifact required. | Local tests verified; dependency audit unavailable and client-specific response blocked. |
| HC-05 | Run all deterministic gates and inspect this matrix for separate expected/actual fields, exact exits, negative cases, and explicit blockers. | Positive and negative/mutation evidence is attributable; skipped/blocked/mock/generated-only outcomes never masquerade as execution, parity, certification, or completion. | Focused, affected, full pytest, and discovery-confidence tests passed with exit `0`; aggregate verification exited `2` only at unavailable dependency audit. The BF-002 contract test resolves and collects every selector from the checked-in affected-suite script. | This matrix, runbook evidence selectors, candidate diff, and future approved commit/CI. | Partially locally verified; dependency audit/immutable evidence pending and completion human-controlled. |

## Deterministic gate results

Results are filled from actual command output. An unrun, interrupted, unavailable, or
network-dependent check is never recorded as passed.

| Gate | Expected | Actual result | Exit | Evidence status |
|---|---|---|---:|---|
| `python -m pytest -q tests/unit/test_operator_runbook.py` | Runbook contract passes. | `7 passed` after final evidence updates. | 0 | Local output; immutable CI pending. |
| `bash scripts/ops03-affected-regressions.sh` | Every checked-in selector is collected and all selected regressions pass. | `141 passed in 11.85s` after final implementation. | 0 | Local output plus checked-in exact selector manifest; immutable CI pending. |
| `make format` | Formatter completes without weakening checks. | Ruff formatted the new test file and fixed one lint issue; no other tracked file changed. Focused tests passed afterward. | 0 | Local output and candidate diff; immutable CI pending. |
| `make verify` | Ruff, strict mypy, pytest, dependency audit, and configured checks pass. | Final run: Ruff passed; mypy reported no issues in 186 source files; pytest reported `1428 passed in 145.05s`; `pip-audit` was unavailable because pypi.org name resolution failed. | 2 | Test/static gates locally verified; dependency audit unavailable, not passed. |
| `make security` diagnostic rerun | Establish exact dependency-audit failure status. | `pip-audit` again failed resolving pypi.org; underlying command exit `1`, make target exit `2`. | 2 | Environment/network unavailable; no vulnerability result claimed. |
| `./scripts/test-discovery-confidence.sh` | Controlled/adversarial/public discovery confidence passes. | Gate A `1 passed`, Gate B `15 passed`, Gate C `16 passed`; all three gates passed. | 0 | Local output; immutable CI pending. |
| `git diff --check` | No whitespace errors. | Completed with no output. | 0 | Local repository check. |
| Protected/public corpus review | No public/private corpus, `competition/generated`, Project-tool, engineering-agent, schema, or provider bytes change. | Final `git status --short` and `git diff --name-only` showed changes only in operator/execution documentation, execution CLI/engine/model/manifest, the OPS-03 selector script, and their tests; no protected path changed. | 0 | Candidate worktree status/diff; immutable review pending. |

## Blocked and non-applicable live evidence

| Requirement | Status | Reason / required owner evidence |
|---|---|---|
| Live Humana execution, client contacts, endpoints, credentials, workspace/catalog/schema permissions, retention actions, and incident response | Blocked | HC-REQ-01, HC-REQ-02, and HC-REQ-04 plus named Humana owners and approved access are external. They are not required for this offline foundation and cannot be fabricated. |
| Live SAS-to-Databricks semantic/data parity and production certification | Blocked | Requires independently acquired authorized baselines, approved tolerances/business rules, actual executions, and attributable review. Static/mocked/generated output is insufficient. |
| Automatic remote retry after an interrupted action | Not applicable and prohibited | A missing canonical result after a state-changing marker is `outcome_unknown`; operator escalation/reconciliation is required. |
| Durable recall/memory service | Not applicable | OPS-03 consumes repository contracts and reviewer learning as advisory context; it introduces no memory store, embeddings, transcript capture, hook, or scheduler. |
| Project publication, Priority mutation, commit, push, merge, issue closure, or `Done / Foundation Complete` closeout | Pending human authority | These are separate human-controlled operations and are not authorized by implementation or this evidence record. |

## Closeout rule

OPS-03 may be proposed for human approval only after all applicable offline gates above have actual
successful output and an attributable reviewed candidate. It is complete only after human-controlled
integration and the documented lifecycle process verifies the Issue is closed and Project state is
`Done / Foundation Complete`. This offline foundation never establishes live Humana readiness,
execution, parity, certification, or production fitness.
