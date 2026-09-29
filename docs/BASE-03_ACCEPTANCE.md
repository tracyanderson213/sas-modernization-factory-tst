# BASE-03 governed target-resolution acceptance

BASE-03 implements a strictly offline contract that resolves an explicit logical SAS dataset name
to one catalog, schema, and table in one named environment. It is a prerequisite for BASE-10 target
mapping; it does not inspect or mutate Unity Catalog.

## Contract boundaries

- Configuration is strict, duplicate-key rejecting, versioned, content-addressed, and acquired from
  a regular no-follow file. Client, deployment, environment, workload, source, run, attempt, artifact,
  policy, binding, access mode, and evaluation time are bound into immutable evidence.
- Every target is an explicit governed binding. There is no default catalog/schema, case-insensitive
  fallback, or environment fallback. Logical-name, binding-ID, and qualified-target collisions fail
  closed. Evaluation and production environment classes cannot be crossed.
- Missing bindings, pending/stale authority, case mismatch, and denied access modes produce explicit
  blocked evidence. Configuration or identity ambiguity is rejected before resolution.
- Publication reacquires and reevaluates current configuration, binds the packaged implementation,
  publishes atomically without overwrite, verifies replay, and supports telemetry-only recovery.

## Acceptance evidence

| Criterion | Evidence |
| --- | --- |
| BASE-03-AC01 | `test_explicit_environment_binding_resolves_and_publishes_immutable_evidence` proves deterministic logical-to-qualified resolution. |
| BASE-03-AC02 | The result binds binding version, explicit namespace source, deployment/environment identity and class; environment isolation negatives cover evaluation versus production. |
| BASE-03-AC03 | Missing binding, case collision/mismatch, denied access, unknown/duplicate configuration, identity mismatch and no-follow tests fail closed. |
| BASE-03-AC04 / HC-01 | Immutable result and telemetry bind client/workload/source/run/attempt/artifact/configuration/policy/implementation identities. |
| HC-02 / HC-03 | No memory or generated target is consumed; no source values or SAS semantics are changed. |
| HC-04 | Protected-data/secret markers and unsafe identities are rejected before evidence publication. |
| HC-05 | Positive, blocked, mutation, replay, concurrent idempotence, recovery and two-workload isolation tests preserve distinct outcomes. |

## Prohibited claims

All result claims remain false. This increment does not prove a target exists, grant read or write
access, contact Azure Databricks or Unity Catalog, establish a Humana namespace, authorize a
production target, execute migration, or prove semantic parity or readiness. Synthetic configuration
is contract evidence only; real customer bindings and authority remain externally supplied inputs.
