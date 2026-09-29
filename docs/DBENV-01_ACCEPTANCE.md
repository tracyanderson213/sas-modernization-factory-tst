# DBENV-01 Offline Environment Contract and Plan

## Implemented boundary

DBENV-01 adds a strict, versioned environment-planning contract for two modes:
`internal_provision` describes an internally owned future provisioning boundary, while
`customer_validate` describes a customer-owned future validation boundary. Both modes are offline
in this increment. Planning does not authenticate, call a provider, run a probe, provision or alter
infrastructure, or establish environment or source readiness.

The environment configuration contains only safe opaque reference identifiers and must share the
authorized directory and exact deployment identity of the existing HENV factory configuration. Its
closed structure covers canonical host/workspace references, governed authentication context and
expected principal; exactly the Unity Catalog schemas `source`, `discovery`, `conversion`,
`validation`, `evidence`, and `operations`; exactly the volume references `landing`, `artifact`,
`validation`, and `checkpoint`; existing-or-governed compute selection; optional Git; HashiCorp
Vault origin/vault, namespace, mount, auth method, audience, role, and secret bindings; AI Gateway
origin/gateway/configuration plus approved Anthropic route/model; approved package repository and
offline bundle/wheel/JAR/native artifacts; SAS programs,
`.sas7bdat`, source systems, and an exact per-probe policy. It cannot contain credentials, endpoints,
customer resource values, or direct model-provider fallback.
Customer mode permits only `none` or a declared future `read_only` probe and rejects
`scoped_internal`; planning still performs neither. The production reference set remains an external
input; the tests use synthetic identifiers only.

## CLI contract

```bash
smf deployment-config plan \
  --config deployments/client/factory.yaml \
  --environment-config deployments/client/environment-plan.yaml \
  --out out \
  --run-id run-1 \
  --attempt-id attempt-1 \
  --json
```

The result path is
`out/runs/<run-id>/environments/<environment-id>/plan-attempts/<attempt-id>/environment-plan.result.json`;
derived telemetry is adjacent as `environment-plan.telemetry.json`. Exit `0` means the supplied offline references form a
complete plan, exit `2` means the input is valid but the plan is blocked, and exit `1` means the
input, path, replay, or immutable publication is malformed or unsafe. A complete plan is not a live
environment pass.

The public verifier and telemetry projection require the original request and deterministically
re-evaluate current governed inputs; self-consistency alone is never an authority boundary.
Publication writes the result and telemetry pair only into a root-confined, no-follow staging
attempt directory. It repeats request-bound evaluation after staging, atomically promotes the
complete directory, and rechecks current input fingerprints after promotion. Input drift quarantines
only the function-owned staging or promoted attempt under a noncanonical rejected name, leaving the
canonical attempt path absent. Interrupted staging is quarantined before a clean retry; identical
complete canonical attempts replay idempotently and conflicting attempts are never overwritten.
Promotion uses the operating system's atomic no-replace directory primitive (`renameatx_np` with
`RENAME_EXCL` on Darwin or `renameat2` with `RENAME_NOREPLACE` on Linux). Other platforms fail closed;
a concurrently created canonical path is preserved while only SMF's staging directory is rejected.

Result identity binds client, deployment, environment, mode, the existing factory configuration and
bundle digests, exact environment bytes, probe policy, and a structured local implementation
manifest covering the planner, factory loader, immutable publisher, CLI, and all three schemas. The
manifest digest serves as the local source-revision binding; no caller-authored revision is trusted.
Identity also binds run, attempt, and canonical output path. Publication is append-only and idempotent
for identical bytes. Changed inputs cannot reuse an attempt. Missing telemetry can be reconstructed
only from the verified canonical result; conflicting or mutated evidence fails closed.

## Acceptance mapping

| Criterion | Implementation and evidence |
|---|---|
| DBENV-01-AC01 | `environment-plan-config.schema.json` and `load_environment_plan_config`; strict two-mode topology, opaque-reference, duplicate/unknown-field, factory-identity, secret, compute-XOR, and write-scope tests in `tests/unit/test_environment_plan.py` |
| DBENV-01-AC02 | `smf deployment-config plan`, deterministic evaluation, content/policy/source/run/attempt bindings, planned probes, dependencies, write scopes, remediation, immutable result and telemetry; `tests/integration/test_environment_plan_cli.py` |
| DBENV-01-AC03 | Symlink, traversal/output-boundary, duplicate, secret, unsupported mode, customer-write, static dependency-closure mutation, attempt-reuse, and cross-environment tests; the implementation imports no Azure, Databricks, Vault, gateway, HTTP, or model-provider SDK |
| DBENV-01-AC04 | CLI exit tests, byte-identical public/package schemas, idempotent replay, missing-telemetry recovery, result/telemetry mutation rejection, and two-environment isolation; every prohibited claim is schema-fixed `false` |
| HC-01/HC-02 | Publication and replay fully re-evaluate current factory/environment bytes, policy, the structured implementation manifest, run, attempt, and output identity; a recomputed unkeyed digest cannot substitute a different disposition, and no remembered, caller-authored revision, or temporary environment value is accepted |
| HC-03 | Claims for generation, execution, validation, reconciliation, parity, migration completion, promotion, certification, approval, and lifecycle closure remain `false` |
| HC-04 | Configuration and immutable path boundaries reject credential markers, unsafe identity, symlinks, traversal, changed bytes, and cross-environment replay without echoing input values |
| HC-05 | Focused tests cover complete, blocked, malformed, adversarial, mutation, recovery, replay, and cross-environment behavior using synthetic inputs only |

## Prohibited claims

DBENV-01 does not prove Azure, Databricks, Unity Catalog, compute, Git, Vault, gateway, Anthropic,
package, SAS artifact, volume, or source-system availability. It does not authorize customer
provisioning or any write. It establishes no authentication, execution, reconciliation, parity,
readiness, migration completion, promotion, certification, approval, or lifecycle result. DBENV-02
owns future customer-configured live validation and DBENV-03 owns separately authorized internal
provisioning.
