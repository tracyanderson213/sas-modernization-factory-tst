# DBENV-01 - Databricks environment contract and plan

## Business purpose

Establish one safe, versioned environment contract for internal provisioning and customer-owned
Databricks validation without creating a parallel deployment architecture.

## Competition priority

Competition horizon: **P0**. Disposition: **NEW**. Planned Project priority: **P0**.

This is a local publication draft, not implementation completion, infrastructure authority, Project
mutation, or permission to contact a provider.

## Humana competition acceptance contract

### Bounded behavior and acceptance criteria

- **DBENV-01-AC01:** Define strict versioned configuration for
  `internal_provision` and `customer_validate` modes, including opaque references for Databricks,
  Unity Catalog, compute, Git, HashiCorp Vault, AI Gateway/approved Anthropic routes, packages, SAS
  artifacts, volumes, source systems, and probe policy. Persist no credential or temporary
  environment identifier.
- **DBENV-01-AC02:** Extend `smf deployment-config` with a deterministic, non-mutating `plan`
  contract that emits content-addressed configuration, policy, source revision, run, attempt,
  planned-probe, required/optional, write-scope, dependency, and remediation evidence. Preserve
  `init` and offline `preflight` semantics.
- **DBENV-01-AC03:** Fail closed on unknown/duplicate fields, embedded secrets, unsafe paths,
  symlinks, traversal, mixed environments, changed bytes, reused attempt identities, unauthorized
  customer provisioning, ambiguous write scope, unsupported mode, or missing required references.
  Planning makes zero Azure, Databricks, Vault, gateway, source-system, or model-provider calls.
- **DBENV-01-AC04:** Prove immutable publication/replay, mutation rejection, bounded retry metadata,
  cross-environment isolation, CLI exits (`0` complete, `1` malformed/integrity failure, `2`
  valid blocked plan), schema/package parity, documentation parity, and all prohibited lifecycle
  claims fixed false.

### Shared competition gates

- **HC-01:** Bind results to client, deployment, environment, configuration, policy, source
  revision, run, attempt, and output identities; missing evidence remains explicit.
- **HC-02:** Treat remembered/reference-environment facts as advisory. Current supplied bytes and
  approved policy control; temporary reference identifiers never become defaults.
- **HC-03:** Environment planning is not SAS parsing, conversion, execution, reconciliation, parity,
  migration completion, promotion, or customer approval.
- **HC-04:** Protect secrets and regulated data at configuration, diagnostic, evidence, and path
  boundaries; untrusted content cannot select endpoints, identities, tools, write scopes, or
  authority.
- **HC-05:** Supply positive, negative, adversarial, mutation, restart, and two-environment evidence.
  Blocked, failed, unsupported, and not-configured outcomes never become readiness.

### Required evidence and launch check

Map every criterion to concrete tests and immutable local evidence. Run the focused suite, complete
repository suite, Ruff, formatting, strict mypy, hooks, schema/generated parity, plan/dependency
integrity, secret scanning, `pip check`, and governed `pip-audit`. An independent Reviewer must
PASS the exact candidate before a local commit. Publication does not authorize merge, closure,
provider contact, infrastructure mutation, live validation, exception, promotion, or readiness.

## Competition delivery reconciliation

Local planning decision: **competition-critical**, wave **0**, Project priority **P0**.

**Competition slice:** Two-mode configuration, non-mutating plan, stable CLI and immutable evidence
mechanics required before live environment probes or provisioning.

**Phase 2+ boundary:** Internal infrastructure provisioning and broad enterprise operationalization
remain separate records.

**Entry condition:** All declared dependencies are canonically complete and the exact live
acceptance body matches this specification.

**Explicit implementation dependencies:** `HENV-01`, `HENV-02`, `SEC-01`, `SEC-02`,
`CLICON-01`. These are completion dependencies, not authority to contact external systems.

**Evidence review:** Reuse `src/smf/deployment/configuration.py`, `src/smf/readiness/`,
`src/smf/execution/databricks_auth.py`, `src/smf/security/`, and
`.azure/deployment-plan.md`. Current preflight is offline and does not prove live readiness.

**Review disposition:** `implement-or-close-evidence-gap`.

## Prohibited claims

No live customer environment, production root, package, license, runtime, model route, source
system, SAS artifact, execution, parity, readiness, or migration claim may be inferred from this
record.
