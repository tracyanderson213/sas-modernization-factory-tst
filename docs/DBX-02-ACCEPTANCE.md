# DBX-02 acceptance evidence

Status: deterministic offline contract implemented; live Humana qualification remains unverified.
This document is not a completion, deployment, merge, or launch approval.

Revision under review: current DBX-02 isolated worktree (final commit remains human-controlled).

| Criterion | Test or review artifact | Expected and actual result | Safe evidence reference |
|---|---|---|---|
| DBX-02-AC01 | `test_databricks_auth_models.py`, `test_databricks_auth_boundary.py` | Approved injected enterprise response verifies; malformed, duplicate, unbound, caller-authored and self-asserted inputs block. Passed offline. | Pending immutable revision; `tests/unit/test_databricks_auth_boundary.py` |
| DBX-02-AC02 | `test_workspace_identity_and_exact_permissions_fail_closed`, `test_incomplete_permission_policy_cannot_authenticate` | Wrong workspace/principal, denied or incomplete permissions have distinct non-success states. The exact five-kind permission policy and its digest are mandatory. Passed offline. | Pending immutable revision; `tests/unit/test_databricks_auth_models.py` |
| DBX-02-AC03 | `test_environment_credentials_cannot_manufacture_submission` and secret receipt binding tests | Environment/PAT/default-profile fallback is unused; expired/denied secret resolution cannot satisfy the required resolved receipt contract. Passed offline. | Pending immutable revision; `tests/unit/test_execution_databricks.py` |
| DBX-02-AC04 | `test_append_only_result_and_telemetry_recovery`, `test_claim_without_result_is_outcome_unknown_and_not_retried` | Exact snapshots are digest-bound; retry repairs telemetry without another probe; cancellation is categorical; unrelated workloads have isolated paths. Passed offline. Live environment proof remains unverified. | Pending immutable revision; `tests/unit/test_databricks_auth_manifest.py` |
| HC-01 | Request/result schemas and deterministic request/decision identity tests | Workload, source/generated, deployment, policy, authority, secret receipt and attempt identities are bound. Passed offline. | Pending immutable revision; `schemas/databricks-authentication-*.schema.json` |
| HC-02 | Code review of DBX modules | Current governed evidence is consumed directly; no recall or durable-memory subsystem is added. Passed review. | Pending immutable revision; `src/smf/execution/databricks_auth.py` |
| HC-03 | Immutable source rehash and executable-entry tests | Comment-only, macro-text-only, empty subjects and changed source bytes fail; authentication is not semantic parity. Passed offline. | Pending immutable revision; `tests/integration/test_secret_provider_admission.py` |
| HC-04 | Workspace-origin, traversal-safe path, exception, protected-reference and secret-canary tests | Alternate/fallback origins, credential-shaped identity references and unsafe paths fail; credential and provider diagnostics do not persist. Passed offline. | Pending immutable revision; `tests/unit/test_databricks_auth_boundary.py` |
| HC-05 | Lifecycle, provider blocking, negative and recovery tests | Generated/authenticated/submitted/executed/validated/parity/human states remain distinct; unknown and blocked are not success. Passed offline. | Pending immutable revision; `tests/integration/test_databricks_auth_guardrails.py` |

Reproduction command (50 deterministic DBX-02-focused tests pass in the current worktree):

```bash
./scripts/test-dbx02-confidence.sh
```

The checked-in Humana bindings remain unresolved, so exact workspace, identity, Vault, network,
catalog/schema/scope, compute and runtime permissions still block live qualification. Mocks prove
the deterministic boundary only; they do not prove live authentication, remote execution, parity,
certification, competition acceptance, or production readiness.

The implementation is intentionally uncommitted. Therefore no immutable source revision or signed
test-run artifact exists yet; the local results above are reproducible but remain provisional for
final acceptance until a human-controlled revision and reviewer evidence are published.

Repository-wide verification result: Ruff and strict mypy passed; all 1,419 tests passed. The final
`pip-audit` step could not query PyPI because the execution environment could not resolve
`pypi.org`. The dependency audit therefore remains an explicit external network blocker and was not
waived or converted into a pass.
