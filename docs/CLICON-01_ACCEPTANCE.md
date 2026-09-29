# CLICON-01 Acceptance Evidence

## Scope and authority

This record covers the offline migration CLI contract scaffold only. It does not attest live Humana
execution, conversion, modernization, provider invocation, validation, parity, approval, promotion,
merge, Project state, or lifecycle completion. Independent Reviewer acceptance remains pending.

## Evidence matrix

| Criterion | Concrete evidence | Expected and actual result | Immutable evidence / disposition |
|---|---|---|---|
| CLICON-01-AC01 | `tests/integration/test_migration_cli.py::test_exact_migration_parser_inventory`; `test_every_run_level_handler_emits_json_blocked_evidence_and_exit_2` | Exact command inventory; valid handlers publish `not_implemented`, exit `2`, and perform no backend operation. Passed locally. | Test source plus canonical temporary-test artifacts; Reviewer pending. |
| CLICON-01-AC02 | `tests/unit/test_migration_cli_contract.py::test_convert_is_bound_and_always_non_authorizing`; `test_identity_changes_across_source_environment_run_and_attempt`; `test_literal_includes_are_bound_transitively_and_change_identity` | Source/configuration/run/attempt identities and digests are reconstructable and domain-separated. Nested literal SAS dependencies alter the closure and decision identities. Passed locally. | Append-only `migration-cli.result.json`; Reviewer pending. |
| CLICON-01-AC03 | Unit adversarial cases plus integration malformed-enum, strict gateway configuration, and legacy-exit tests | Missing, duplicate, unsafe, empty, mutable, unknown, incompatible, and caller-success inputs fail closed; no mocks satisfy execution. Passed locally. | Preserved regression tests; Reviewer pending. |
| CLICON-01-AC04 | Packaged schema mirror test, deployment/security/upstream regressions, full gates below | Exact dependency contracts are reused; external qualification remains an explicit blocker. Focused scaffold tests passed; full gate result recorded below. | No external-system evidence claimed; Reviewer pending. |
| HC-01 | Result identity, source snapshot, configuration manifest, run/attempt/invocation, and canonical reference schemas | Required identities are bound or explicitly null with blockers. Passed locally. | Canonical result is the authority for derived telemetry. |
| HC-02 | `upstream_qualification_not_bound` blocker and no recall subsystem | No upstream/recalled knowledge can authorize the scaffold. Passed locally. | Upstream integration remains pending. |
| HC-03 | Lifecycle schema constants and eligible-source qualification tests | Generated output and schema validity never become execution, validation, or parity. Passed locally. | All operational claims fixed false. |
| HC-04 | Boundary/symlink/credential-canary rejection and no gateway transport | Unsafe bytes and paths fail before persistence; preflight does not contact a provider. Passed locally. | Synthetic local tests only. |
| HC-05 | Positive blocked, negative, malformed-enum, duplicate, boundary, and canonical recovery tests | Non-success states remain visible; valid scaffold results cannot exit `0`; a unique invocation-derived result recovers missing telemetry without producer inputs while ambiguous matches fail closed. Passed locally. | Reviewer pending. |

## Deterministic gate record

Implementation base revision: `20018bd77bbde374ec22116a0f5ceebf8dfe62bf`.
The sorted changed-file content inventory digest after the final implementation gates, excluding
this self-referential acceptance record, is
`bb045c5b5ca667c004251311aa6065e626a7ea3b6d00c88ebeae60cb87cc371a`. This uncommitted working-tree
digest is reproducibility evidence, not a merged source revision or approval.

| Command | Actual result |
|---|---|
| `python -m pytest -q tests/unit/test_migration_cli_contract.py` | Passed: 14 tests |
| `python -m pytest -q tests/integration/test_migration_cli.py` | Passed: 8 tests |
| `python -m pytest -q tests/integration/test_migration_schema_packaging.py` | Passed: 1 test |
| Required dependency regression selection | Passed: 155 tests |
| `python -m pytest` | Passed: 1,780 tests in 196.71 seconds; final `make verify` run repeated them in 195.50 seconds |
| `python -m ruff check src tests` | Passed |
| `python -m mypy src` | Passed: 207 source files |
| `python -m pip_audit` | Blocked: sandbox DNS could not resolve `pypi.org`; no audit success claimed |
| `make verify` | Tests, lint, and typecheck passed; target exited nonzero at the same network-blocked `pip_audit` step |

Final disposition: **implementation evidence assembled; independent Reviewer acceptance pending**.
