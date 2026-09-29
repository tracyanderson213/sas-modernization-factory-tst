# DBENV-02 - Customer-owned Databricks readiness validation

## Business purpose

Deterministically prove whether a customer-supplied Databricks execution environment has the exact
capabilities required by an approved migration run without requiring Azure subscription,
Contributor, metastore-admin, broad Unity Catalog, or infrastructure-creation authority.

## Competition priority

Competition horizon: **P0**. Disposition: **NEW**. Planned Project priority: **P0**.

This record remains dependency-blocked. Publication is not live-environment authorization.

## Humana competition acceptance contract

### Bounded behavior and acceptance criteria

- **DBENV-02-AC01:** Implement injected provider adapters for authentication, expected workspace and
  principal, governed compute/runtime, Unity Catalog and six schemas, landing read, artifact/
  validation/checkpoint scoped write/read, managed Delta create/write/read, Python/PySpark,
  supplied `.sas` and `.sas7bdat` accessibility, Vault, AI Gateway/approved Anthropic route,
  packages, and configured source systems.
- **DBENV-02-AC02:** Emit per-probe `PASS`, `FAIL`, `BLOCKED`, or `NOT_CONFIGURED` receipts
  and an immutable aggregate. Every required non-PASS outcome prevents `READY`; optional
  `NOT_CONFIGURED` remains visible. Environment failures remain distinct from conversion,
  execution, validation, and parity defects.
- **DBENV-02-AC03:** Use only least-privilege configured operations. Write probes require an exact
  admitted plan and approved run-owned scope; never replace, truncate, adopt, or delete pre-existing
  customer objects. Cleanup requires matching ownership evidence and configured authority.
- **DBENV-02-AC04:** Automate the maintained reference-smoke capability set with replay, retry,
  timeout, mutation, stale-evidence, wrong-workspace/principal, permission denial, provider
  malformed-response, cross-environment, partial-write, and cleanup tests. Synthetic providers prove
  mechanics only; a real environment becomes READY only from its own authorized live receipt.

### Shared competition gates

- **HC-01:** Bind every observation to exact environment/configuration/plan/policy/provider/run/
  attempt and safe provider-request identities.
- **HC-02:** Historical smoke results and remembered settings are advisory and cannot qualify the
  configured environment.
- **HC-03:** Accessibility is not parsing, conversion, reconciliation, SAS equivalence, or migration
  completion.
- **HC-04:** Persist no credentials, secret values, prompts with customer data, provider diagnostics,
  PHI, or PII. Direct public-provider fallback is prohibited.
- **HC-05:** Required unavailable, stale, denied, ambiguous, incompatible, or unknown results block
  readiness and remain actionable.

### Required evidence and launch check

All deterministic gates and independent review are mandatory. Live write probes, Vault/gateway
calls, Databricks execution, or customer-system contact require separate environment-specific
authority even after implementation passes.

## Competition delivery reconciliation

Local planning decision: **competition-critical**, wave **2**, Project priority **P0**.

**Explicit implementation dependencies:** `DBENV-01`, `DBX-02`, `DBX-03`, `AIGW-01`.

**Evidence review:** The current Databricks execution provider keeps remote submission disabled.
DBX-03 owns compute-policy selection and AIGW-01 owns gateway transport; this record must reuse both.

**Review disposition:** `implement-or-close-evidence-gap`.

## Prohibited claims

No synthetic/mock test, historical smoke run, configuration presence, accessible filename, or
generated artifact establishes customer readiness, production authority, SAS parity, or migration.
