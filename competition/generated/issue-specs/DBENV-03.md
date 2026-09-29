# DBENV-03 - Internal Azure Databricks provisioning

## Business purpose

Provide an idempotent, reviewable Terraform composition for an internally controlled Databricks
development environment while keeping all provisioning authority out of customer mode.

## Competition priority

Competition horizon: **P1**. Disposition: **NEW**. Planned Project priority: **P1**.

This record remains dependency-blocked. Publication is not Terraform apply authority.

## Humana competition acceptance contract

### Bounded behavior and acceptance criteria

- **DBENV-03-AC01:** Model an optional Premium workspace, supplied existing regional Unity Catalog
  metastore assignment, ADLS Gen2, managed-identity Access Connector, scoped storage RBAC, storage
  credential/external location, one configured catalog, six schemas, four external volumes, and a
  governed development compute policy/template. No customer resource is created.
- **DBENV-03-AC02:** Pin providers and define strict variables, remote-state requirements, outputs,
  ownership, tags, managed-identity storage, and compatible compute inputs without universal VM SKU,
  subscription, workspace, metastore, storage, user, credential, or temporary-environment defaults.
- **DBENV-03-AC03:** Default to saved Terraform plan. Parse and evidence every action; block delete,
  replacement, metastore creation/reassignment, ownership transfer, state migration, broad role
  assignment, or protected network change. Apply requires a separate unexpired approval bound to the
  exact plan/configuration/environment/identity/run.
- **DBENV-03-AC04:** Prove format/validate, static security/policy checks, create/no-op/safe-update
  classification, drift, restart/idempotency, changed-plan rejection, cross-environment isolation,
  partial failure, and post-provision DBENV-02 handoff. Tests create no live resources.

### Shared competition gates

- **HC-01:** Bind plan and receipt to source commit/tree, Terraform/provider versions, input/state/
  plan digests, environment, identity, run, attempt, approval, actions, and outputs.
- **HC-02:** Supplied existing resources and historical reference settings remain untrusted until
  current evidence verifies them.
- **HC-03:** Infrastructure creation is separate from conversion, execution, validation, parity,
  promotion, and migration completion.
- **HC-04:** Credentials and Terraform state remain in approved runtime/backends, never Git or SMF
  evidence. Untrusted input cannot change authority or scope.
- **HC-05:** Missing subscription/region/quota/registration/state/identity/policy, destructive plans,
  or changed approvals block apply without waiver.

### Required evidence and launch check

All repository, IaC, security, dependency, packaging, and independent review gates must pass. Any
future Terraform apply requires separate target-specific authority and pre-deployment validation.

## Competition delivery reconciliation

Local planning decision: **competition-conditional**, wave **5**, Project priority **P1**.

**Explicit implementation dependencies:** `DBENV-01`, `DBX-03`, `LIC-01`,
`PKG-DES-01`.

**Evidence review:** `.azure/deployment-plan.md` selects Terraform for internal infrastructure.
Customer Configure/Validate mode never invokes this provider.

**Review disposition:** `implement-or-close-evidence-gap`.

## Prohibited claims

No plan, test, or local module authorizes apply, customer infrastructure access, metastore
administration, real license acceptance, production readiness, or migration completion.
