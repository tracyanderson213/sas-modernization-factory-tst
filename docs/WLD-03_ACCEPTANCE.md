# WLD-03 Acceptance Evidence

## Scope and revision

This record covers the bounded offline static code-dependency increment at source revision
`03524e6ce77ecebcb515eebef846299dc9e11002` plus the WLD-03 working-tree changes. The analyzer
policy is identified in each result by analyzer/version and SHA-256 policy digests. The
implementation does not execute SAS or claim Humana runtime, parity, certification, production
promotion, or human approval.

## Criterion matrix

| Criterion | Evidence and procedure | Expected and actual result |
|---|---|---|
| WLD-03-AC01 | `tests/unit/test_code_dependencies.py`; run the focused pytest command below. | Exact byte-bound include/call occurrences, typed outcomes, candidates, source revisions, policy digests, and inventory targets are present. Passed. |
| WLD-03-AC02 | `test_code_analysis_preserves_include_cycle_as_typed_group`, `test_resolved_sas_configuration_dependency_is_in_ordering_closure`, and existing dependency-domain tests. | Cycles remain typed SCCs; resolved `autoexec.sas`/`config.sas` prerequisites remain in prerequisite-first code ordering; data, scheduler, and runtime domains remain separate. Passed. |
| WLD-03-AC03 | Quote/comment/dynamic tests in `test_code_dependencies.py`, source-revision graph test in `test_dependency_graph.py`, and include resolver regressions. | Quoted/commented/dynamic references do not fabricate edges; source edits change closure, analysis, and graph identity. Passed. |
| WLD-03-AC04 | Qualification persistence, source-mutation, caller-analysis replay, telemetry-recovery after source mutation/removal, and attempt-isolation tests in `test_code_dependencies.py`. | Exact identity bindings and source closure persist; new qualification rejects changed source or caller-replaced analysis; retry reconstructs missing telemetry from identical canonical evidence without mutable-source re-analysis; attempts remain isolated. Passed for synthetic offline sources. Live Humana evidence remains unavailable. |
| HC-01 | Qualification payload and path bind client, workload, subject, source closure, policy, run, attempt, execution, and analysis IDs. | Claims remain distinct and attributable. Passed. |
| HC-02 | Static modules have no recall or memory dependency. | Qualification operates without recall. Passed by source review and focused tests. |
| HC-03 | `claim=static_discovery_only`; all runtime/parity claims are fixed false. | No macro execution, target inference, or parity claim occurs. Passed. |
| HC-04 | Existing discovery sanitization is applied before identity/persistence; unsafe IDs, path escapes, percent escapes, symlinks, and changed bytes are rejected. | Protected boundary remains fail closed. Passed for synthetic probes. No live client data used. |
| HC-05 | Positive, unresolved, cycle, malformed enum, duplicate identity, missing evidence, caller-attestation mutation, configuration-boundary, restart/recovery, and isolation regressions. | Blocked/skipped/unvalidated states and caller-replaced analysis cannot qualify or count as runtime success. Passed. |

## Reproducible commands

```text
pytest -q tests/unit/test_code_dependencies.py tests/unit/test_dependency_graph.py \
  tests/unit/test_include_reconciliation.py tests/integration/test_cli_discover.py \
  tests/integration/test_discovery_adversarial.py
ruff check src tests
mypy src
make verify
```

The focused regression result was `68 passed`. Ruff passed, strict mypy passed across 193 source
files, and the final full test suite passed with `1,721 passed`. `make verify` reached `pip-audit`,
which could not resolve `pypi.org` in the restricted environment. The security-audit result therefore
remains unverified rather than being represented as passed.

## Remaining live blockers

No authoritative Humana manifest, source snapshot, acceptance quota, numerical tolerance, runtime
environment, baseline, cost/resource policy, or owner approval was supplied. Those prerequisites
remain explicit blockers to live competition qualification. Static qualification is not execution,
validation, parity, certification, approval, publication, merge, or Project closeout.
