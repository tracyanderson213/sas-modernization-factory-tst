# SMF Databricks Environment Bootstrap and Readiness Plan

Status: Proposed for architecture approval; no deployment, live validation, or Project mutation is
authorized by this document.

## 1. Objective and delivery classification

Add a first-class SMF capability for repeatable Databricks environment planning, optional internal
provisioning, customer-supplied environment configuration, and deterministic capability validation.
This modifies the existing Python CLI and deployment/readiness architecture; it is not a new
application or a parallel script framework.

The current planning phase creates zero Azure or Databricks resources. A later internal provision
run may create the bounded resources in Section 7 only after an exact plan and state-changing
authorization. Customer mode never creates customer infrastructure.

## 2. Repository findings and reuse decisions

The implementation must extend these existing foundations:

- `smf deployment-config init|preflight` for strict, duplicate-key-rejecting, credential-free
  configuration loading and fail-closed exit behavior.
- `smf.readiness` for immutable, policy-bound readiness evidence and explicit environment blockers.
- `smf.execution.databricks_auth` for governed workspace, identity, and least-privilege checks.
- `smf.security` for Entra workload identity and HashiCorp Vault transport contracts.
- `smf ai-gateway preflight` for the customer gateway boundary. Customer mode must not add direct
  Anthropic, OpenAI, or other public-provider fallback.
- DBX-03 for approved runtime/compute selection. Environment validation may observe compute, but it
  may not invent or override the governed compute policy.
- Existing deployment identity, digest, immutable publication, replay, telemetry, and lifecycle
  claim separation conventions.

The present deployment preflight validates local configuration only and deliberately performs no
provider contact. The new live validator is therefore a separate subcommand and result contract;
`preflight` remains network-free and retains its current meaning.

The manually proven reference smoke test is accepted as historical design input only. Its temporary
workspace, catalog, storage, metastore, identity, and user values will not become defaults or
qualification evidence. The maintained acceptance path must reproduce the capabilities and issue a
new immutable receipt for the exact configured environment.

## 3. Operating modes and ownership

### 3.1 Internal Provision Mode

SMF may plan and, under a separate state-changing approval, create an SMF-controlled development
environment. Infrastructure is owned by the internal Azure platform owner; Unity Catalog objects
and compute policy are owned by the internal Databricks platform owner; SMF owns only its declared
catalog namespace, validation artifacts, evidence, and run-scoped smoke resources.

Internal mode uses Terraform because this is infrastructure composition rather than application
hosting and the repository has no existing `azd` application topology. Terraform is wrapped by the
same SMF configuration and evidence contracts. It is never invoked implicitly by configuration
validation.

### 3.2 Customer Configure/Validate Mode

The customer owns Azure, Databricks, Unity Catalog, storage, identity, networking, HashiCorp Vault,
Git, package repositories, SAS sources, source systems, and AI Gateway. SMF consumes supplied
references and performs only approved capability probes.

Customer mode requires no Azure subscription read/write access, Azure Contributor role, metastore
administrator rights, broad Unity Catalog rights, or authority to create customer infrastructure.
It reports the minimum missing permission or configuration without escalating privileges or
falling back to personal access tokens, default CLI profiles, or another workspace.

Customer-facing wording describes modernization source and evidence executed in customer-controlled
infrastructure. It does not describe installation of a 3Cloud tool, proprietary accelerator, or SMF.

## 4. Stable CLI contract

Extend the existing namespace instead of introducing `scripts/databricks/*`:

```text
smf deployment-config init       # existing deterministic template generation
smf deployment-config preflight  # existing local/no-network validation
smf deployment-config plan       # new non-mutating environment plan
smf deployment-config validate   # new approved live capability probes
smf deployment-config provision  # new internal-only Terraform plan/apply wrapper
```

Proposed command shapes:

```text
smf deployment-config plan \
  --config deployments/<environment>/factory.yaml \
  --environment-config deployments/<environment>/environment.yaml \
  --run-id <run> --attempt-id <attempt> --out <evidence-root> --json

smf deployment-config validate \
  --config deployments/<environment>/factory.yaml \
  --environment-config deployments/<environment>/environment.yaml \
  --plan-manifest <immutable-plan.json> \
  --run-id <run> --attempt-id <attempt> --out <evidence-root> --json

smf deployment-config provision \
  --environment-config deployments/<environment>/environment.yaml \
  --terraform-root infra/databricks-environment \
  --plan-manifest <immutable-plan.json> \
  --provision-approval <exact-approval.json> \
  --run-id <run> --attempt-id <attempt> --out <evidence-root> --json
```

`plan` performs no provider contact or mutation. `validate` contacts only configured providers and
may perform write probes only when the immutable plan, approved validation namespace, and explicit
write-probe authority all agree. `provision` is rejected in customer mode. It defaults to Terraform
plan; apply requires a separate, unexpired approval bound to the environment, configuration digest,
Terraform plan digest, identity, subscription reference, workspace reference, run, and expiration.

Exit behavior follows existing SMF conventions:

- `0`: valid completed operation whose required checks all pass.
- `1`: malformed input, unsafe path, secret exposure, integrity failure, provider protocol failure,
  or evidence-publication failure.
- `2`: valid fail-closed result with one or more required `FAIL`, `BLOCKED`, or `NOT_CONFIGURED`
  checks; no readiness or provisioning-success claim.

Repeating an identical run/attempt returns the identical immutable result. Reusing an identity with
different bytes fails. A new attempt may resume only incomplete probes whose inputs and prerequisite
receipts still match; successful prior probes are replay-verified before reuse.

## 5. Configuration contract

Add a strict versioned environment configuration schema with unknown-field and duplicate-key
rejection. Values are references, never secrets. Required fields vary by mode and probe policy:

- deployment identity and mode (`internal_provision` or `customer_validate`);
- canonical Databricks host and workspace reference;
- governed authentication context and expected principal reference;
- catalog plus the six logical schemas: source, discovery, conversion, validation, evidence, and
  operations;
- landing, artifact, validation, and checkpoint volume references;
- approved existing compute ID or governed job-compute request;
- Git/repository identity where required;
- HashiCorp Vault origin, namespace/mount/auth-method references, audience, role, and secret-binding
  references without tokens or secret values;
- AI Gateway origin/config reference and approved Anthropic route/model identifiers, with no direct
  model-provider credential or fallback;
- approved package-repository and offline-artifact references;
- SAS program, `.sas7bdat`, and configured source-system locations;
- per-probe required/optional policy, timeout, retry limit, evidence age, and validation-write scope.

Environment-specific identifiers remain in ignored deployment instances or approved secret/config
systems. The repository contains schemas and sanitized examples only. No subscription, workspace,
metastore, storage, catalog, user, or credential value from a temporary reference environment is
embedded in source, tests, Terraform defaults, or documentation.

## 6. Customer readiness probes and result semantics

The validator executes only admitted probes and emits one immutable result per probe plus a canonical
aggregate manifest. Probe outcomes are exactly `PASS`, `FAIL`, `BLOCKED`, or `NOT_CONFIGURED`.
Required `FAIL`, `BLOCKED`, or `NOT_CONFIGURED` prevents aggregate `READY`; optional
`NOT_CONFIGURED` remains visible without failing unrelated required checks.

Required probe families:

1. Databricks authentication, expected workspace, and expected principal.
2. Compute existence/startability or job-compute admission, runtime/Spark/Scala/engine/access-mode,
   worker/driver minimums, elastic disk, auto-termination, policy, quota, and timeout compatibility.
3. Unity Catalog and required schema accessibility using least-privilege operations.
4. Landing-volume read/list access.
5. Artifact-, validation-, and checkpoint-volume scoped write/read using unique run-owned objects.
6. Managed Delta create/write/read in the approved validation schema using a collision-safe run-owned
   table; never replace, truncate, or drop a pre-existing object.
7. Python and PySpark execution with captured runtime versions.
8. `.sas` accessibility and `.sas7bdat` byte accessibility when supplied. Accessibility is not
   parsing, conversion, reconciliation, or parity.
9. HashiCorp Vault configuration and connectivity through the existing Entra/Vault boundary without
   persisting resolved secret bytes.
10. AI Gateway and approved Anthropic route connectivity through AIGW-01; no prompt containing
    customer data is required for environment validation.
11. Required configured source-system/data connectivity using provider-specific safe probes.

Every observation records probe/version, environment/configuration/plan digests, run/attempt,
provider request identity where safe, start/end times, sanitized diagnostics, remediation code, and
immutable artifact digests. The aggregate uses failure domain `environment`; downstream conversion
results use their existing conversion/execution/validation domains. Neither can masquerade as the
other.

Write probes are explicit, bounded, and non-destructive. They use unique run-owned names inside a
pre-approved validation scope. Cleanup removes only objects whose ownership receipt matches the same
run and only when cleanup authority is configured; otherwise retention is reported. Validation never
reconciles, deletes, replaces, or changes customer resources merely because configuration differs.

## 7. Internal provisioning architecture

The reusable Terraform root will declare provider versions, remote-state requirements, tags, and
input validation. It may plan these quantities when requested:

| Resource or binding | Planned quantity | Ownership and behavior |
| --- | ---: | --- |
| Azure Databricks Premium workspace | 0 or 1 | Create only when the internal configuration requests it; otherwise bind an existing workspace. |
| Existing regional Unity Catalog metastore assignment | 0 or 1 | Bind only a supplied metastore; do not create or replace a metastore. |
| ADLS Gen2 storage account/container set | 1 logical storage boundary | Internal-only; hierarchical namespace enabled and names supplied through configuration. |
| Databricks Access Connector with managed identity | 1 | Internal-only; scoped to the declared storage boundary. |
| Storage RBAC assignments | Minimum required set | Exact principal and scope; no subscription-wide role assignment. |
| Unity Catalog storage credential and external location | 1 each or supplied existing references | Managed-identity pattern; never store storage keys. |
| Catalog | 1 | Name supplied by configuration; prevent destructive replacement. |
| Schemas | 6 | source, discovery, conversion, validation, evidence, operations. |
| External volumes | 4 | source landing, conversion artifacts, validation evidence, operations checkpoints. |
| Development compute policy/template | 1 | Governed baseline; no universal VM SKU default. |

The validated reference compute envelope is a compatibility baseline, not a hard-coded customer
requirement: DBR `16.4.x-scala2.12`, Spark `3.5.2`, standard engine, `USER_ISOLATION`, at least
4 vCPU/16 GiB for driver and worker, one initial worker, elastic disk, and 30-minute development
auto-termination. The Azure reference VM family is evidence of one passing shape only. DBX-03 owns
the versioned allowlist and may approve compatible alternatives.

Terraform lifecycle controls protect workspace, storage, connector, catalog, credential, external
location, schemas, and volumes from destroy/replacement. The SMF wrapper parses the saved plan and
blocks any delete or replacement by default. Import/adopt decisions, state migration, metastore
assignment, privilege ownership changes, and any destructive plan require a separate human decision.
Terraform state and provider credentials remain in an approved backend/runtime, not Git or SMF
evidence.

No subscription or region is selected during implementation. Before a future internal apply, the
operator must supply the approved subscription, region, quotas, provider registrations, identity,
remote-state backend, and network policy. Absence blocks apply and does not affect customer mode.

## 8. Identity, storage, Vault, gateway, and dependency boundaries

- Internal Azure resource creation uses a separately approved deployment identity. Customer mode
  never asks for that identity or its permissions.
- Databricks validation uses DBX-02's governed enterprise authentication evidence and the exact
  workspace/principal binding. PAT/default-profile fallback remains prohibited.
- Unity Catalog probes request only `USE CATALOG`, `USE SCHEMA`, volume read/write, and validation
  table privileges needed by configured probes. Ownership and metastore-admin rights are not
  prerequisites for customer validation.
- Managed identity plus Access Connector is the internal storage pattern where applicable. Customer
  mode validates the supplied storage path and UC permissions without requiring knowledge of the
  customer's underlying Azure subscription.
- HashiCorp Vault readiness reuses the existing provider-neutral secret and Entra identity contracts.
  A connectivity receipt proves only the configured binding and safe operation; it does not expose or
  persist secret material.
- AI Gateway readiness reuses AIGW-01. For Humana, only the configured customer gateway and approved
  Anthropic route identifiers are admissible; no public-provider SDK fallback is added.
- No runtime public downloads are permitted in customer execution. Package readiness reports the
  required offline wheel/JAR/native artifact when an approved dependency is missing.

## 9. Evidence, security, and failure handling

Schemas will define environment configuration, plan, per-probe result, aggregate readiness result,
provision approval, and provisioning receipt. Every canonical result is content-addressed, published
atomically, replayable, secret-sanitized, and bound to the exact source commit/tree, Python version,
platform, configuration bytes, policy bytes, provider/adapter versions, run, and attempt.

Security failures, wrong workspace/identity, stale evidence, changed plans, duplicate keys, symlinks,
path traversal, malformed provider replies, partial writes, timeouts, quota failures, policy denial,
and unknown outcomes fail closed. Retry policy is bounded and records each attempt. One environment
or workload cannot overwrite another environment's evidence.

Environment readiness does not establish SAS conversion, physical data parsing, semantic parity,
reconciliation, migration completion, production readiness, promotion, or customer approval.

## 10. Exact backlog proposal

No existing completed record receives new acceptance scope or dependencies. These are new child
records under `EPIC-HENV`:

| Record | Priority | Dependencies | Scope and completion boundary | Estimate |
| --- | --- | --- | --- | ---: |
| `DBENV-01` - Databricks environment contract and plan | P0 | HENV-01, HENV-02, SEC-01, SEC-02, CLICON-01 | Strict two-mode configuration, non-mutating plan, CLI contract, evidence schemas, status/exit semantics, replay, security tests, and docs. No provider contact or infrastructure mutation. | 4-6 d |
| `DBENV-02` - Customer-owned Databricks readiness validation | P0 | DBENV-01, DBX-02, DBX-03, AIGW-01 | Provider adapters and all customer capability probes in Section 6, automated reference-smoke acceptance, immutable receipts, remediation, resume, and cross-environment isolation. Mechanics may complete with synthetic providers; a real environment is not READY until its own live receipt passes. | 7-11 d |
| `DBENV-03` - Internal Azure Databricks provisioning | P1 | DBENV-01, DBX-03, LIC-01, PKG-DES-01 | Terraform composition for Section 7, safe plan/apply wrapper, deletion/replacement guard, approval binding, idempotency, drift reporting, and post-provision validation handoff. No customer infrastructure authority. | 7-12 d |

`DBENV-01` is the first runnable increment because all five dependencies are currently verified live as
`Done / Foundation Complete`. `DBENV-02` remains dependency-blocked until DBX-03 and AIGW-01 are
canonically complete. `DBENV-03` remains blocked until its policy, license, and portability
dependencies pass. This priority does not mutate or implicitly approve the separate local DBX-03
candidate.

Downstream dependency proposal: DBPKG-01, DBX-01, HPILOT-03, and READY-02 should consume a passing
DBENV-02 environment receipt when live Databricks execution is in scope. This must be added through a
separate dependency-integrity review; completed records are not retroactively changed.

## 11. Planned repository surfaces

`DBENV-01` is expected to change only:

- `.azure/deployment-plan.md` and the narrow `.gitignore` exception that tracks it;
- `src/smf/deployment/` models, strict loaders, planning, and immutable evidence publication;
- mirrored schemas under `schemas/` and `src/smf/schemas/`;
- `src/smf/cli/main.py` and existing CLI/operator documentation;
- sanitized generic deployment examples and package-data declarations as required;
- focused unit/integration/security tests;
- approved generated backlog artifacts after publication authorization.

`DBENV-02` may add provider interfaces/adapters under the existing deployment/execution/security
packages and maintained acceptance fixtures. `DBENV-03` may add
`infra/databricks-environment/` Terraform modules, version constraints, variable validation, outputs,
sanitized example inputs, and focused IaC tests. Neither record may modify real environment files or
local Databricks CLI profiles.

## 12. Verification gates

Each increment requires Architect acceptance, Developer implementation, deterministic gates, an
independent Reviewer verdict, bounded repair, and a focused local commit before integration is
proposed.

Required gates include:

- Ruff check and formatting verification; strict mypy; complete repository tests; `make verify`;
- schema/package-copy parity and generated-artifact integrity;
- positive, negative, adversarial, mutation, retry, replay, idempotency, concurrency, and
  cross-environment isolation tests;
- secret/protected-data scans and tests proving credentials never enter errors or evidence;
- CLI contract and operator-runbook parity;
- Terraform format/validate plus static security/policy checks using pinned approved tooling;
- saved-plan tests proving creates/no-op/updates are classified and delete/replace fails closed;
- repository-approved `pip-audit` with a valid advisory receipt; unavailable is not passing;
- an acceptance test reproducing the reference smoke capabilities against an explicitly authorized
  environment, while synthetic provider tests remain clearly non-authorizing.

## 13. External inputs and stop rules

Implementation can proceed offline without customer values. Live customer validation stops safely
until the customer supplies the configuration references, identity authority, probe permissions,
Vault binding, AI Gateway/Anthropic route, package source, SAS locations, and source-system access
required by its policy.

Internal apply stops for missing subscription/region/quota/provider registration, missing remote
state, unapproved role assignment, unavailable approved providers, delete/replace actions, metastore
creation or reassignment, ownership transfer, protected-network changes, license/security exception,
or plan/approval drift.

Any live customer write probe, internal Terraform apply, merge, Issue closure, Project lifecycle
change, exception, promotion, or migration-completion decision requires its own applicable authority.

## 14. Proposed execution sequence

1. Approve this architecture and the exact three-record backlog proposal.
2. Materialize and dependency-validate the three local records; publish/start only DBENV-01 through
   the supported Project workflow and verify live read-back.
3. Implement DBENV-01 in a clean dedicated worktree through Architect -> Developer -> Reviewer.
4. Prepare a reviewed integration/lifecycle package; do not merge or close without explicit approval.
5. Advance DBENV-02 and DBENV-03 only when their declared dependencies are canonically complete.
6. Perform live validation or provisioning only under a separate environment-specific authorization.

Approval of this plan authorizes repository implementation mechanics only. It does not authorize a
live Azure/Databricks/Vault/AI Gateway operation or any infrastructure mutation.
