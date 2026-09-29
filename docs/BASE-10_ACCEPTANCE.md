# BASE-10 governed Delta target-mapping acceptance

BASE-10 composes current, immutable BASE-02 semantic mapping evidence with current BASE-03
environment-specific namespace resolution. It produces offline packaging metadata for a planned
Delta target. It does not contact or mutate Databricks or Unity Catalog.

## Contract boundaries

- The complete BASE-02 result is replayed against its current BASE-04 descriptor, source snapshot,
  reader providers, policy, and runtime. Every BASE-03 result is reacquired from its authorized
  configuration root, reevaluated, and required to match its immutable published evidence.
- Client, deployment, environment, environment class, workload, source, run, attempt, artifact,
  semantic-policy, namespace-policy, packaging-policy, schema, transformation, implementation, and
  evaluation-time identities are digest-bound. Multi-target mappings cannot cross deployments or
  environments.
- The resolution inventory must exactly match the qualified semantic targets. Missing, extra,
  duplicate, identity-mismatched, read-only, blocked, stale, or production targets fail closed.
  Qualified catalog/schema/table names are case-folded and collision-rejected.
- BASE-02 policy and source-snapshot authority plus BASE-03 namespace authority are reevaluated at
  the BASE-10 evaluation time. Exact expiry boundaries fail closed; historical success is not reused
  as current authority.
- The bounded packaging policy permits only planned managed Delta metadata, denies overwrite and
  implicit schema evolution, and records that the environment-resolved storage location was not
  accessed. BASE-09 rationalization is not an input to this as-is mapping contract.
- Results publish atomically without replacement, are replayed from current inputs, detect mutation,
  fail before publication on cancellation, and remain isolated by run, workload, and attempt.

## Acceptance evidence

| Criterion | Evidence |
| --- | --- |
| BASE-10-AC01 | The qualified synthetic contract maps one BASE-02 logical output to one explicit BASE-03 catalog/schema/table and preserves Delta packaging metadata. |
| BASE-10-AC02 | The result preserves the exact BASE-02 columns/schema digest, transformation, storage disposition, policy digests, and upstream result identities without changing semantic intent. |
| BASE-10-AC03 | Exact-inventory, identity, read/write, stale-policy, production-namespace, duplicate-target, and case-folded namespace collision tests fail closed before execution. |
| BASE-10-AC04 / HC-01 | Full-decision IDs and content digests bind current upstream evidence, the request, policy, implementation manifest, and target projections. |
| HC-02 / HC-03 | No memory, rationalization, code generation, format execution, or semantic transformation is used. The mapping carries underlying-value policy forward unchanged. |
| HC-04 | Unsafe or protected-data-like identities are rejected; no source row, credential, endpoint, or customer configuration is persisted. |
| HC-05 | Positive, blocked, mutation, concurrent retry, cancellation, publication-collision, schema-parity, and two-workload isolation tests preserve honest outcomes. |

## Prohibited claims

All operational claims remain false. This foundation does not prove that a catalog, schema, table,
or storage location exists; authorize a principal; apply a schema; write Delta data; contact
Databricks or Unity Catalog; validate Humana configuration; establish production readiness;
execute or reconcile a migration; or prove SAS semantic parity.
