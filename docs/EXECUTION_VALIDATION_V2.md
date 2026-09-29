# Execution Validation v2

## Purpose

Execution Validation v2 adds a runtime evidence layer after static validation.

The execution engine does not bypass Validation Engine v1. A generated artifact
must first pass static validation and must not require human review.

## Providers

### Local

The local provider executes Python/PySpark-shaped artifacts using the active
Python interpreter.

This provider exists for engineering tests only. It does not prove Databricks
runtime compatibility.

### Databricks

The Databricks provider contract is established in v2 and validates required
configuration.

Remote execution remains feature-gated until an enterprise validation workspace,
compute policy, catalog, authentication method, and write boundaries are
approved.

DBX-03 adds an offline compute-policy qualification boundary. It accepts only a named job-cluster
profile from an exact versioned policy and a signed availability/quota observation, and records the
effective DBR, Spark, Scala, JVM, isolation, network, scope, worker, concurrency, cost, runtime,
retry and cancellation limits. Active policies require an explicit positive availability maximum
age; a pending policy with no selectable profiles records that unprovided input as null. The request embeds the replay-valid readiness manifest and exact
parsed policy snapshot; the result retains the signed provider observation, evaluation time, quota
values and provider version. A policy maximum age applies independently of provider expiry.
Preparation and result publication use one stable run/workload/workflow-attempt/selection-attempt
path that does not depend on evaluation time or decision ID. Restart recovery verifies the signed
preparation with trusted evidence keys and returns its complete captured request, including
`evaluated_at`, for exact replay. A later request identity for that attempt, concurrent publication,
tampered evidence, cross-attempt substitution, or duplicate legacy/stable evidence fails closed.
Qualification is not allocation or submission. Downstream admission
must reverify the exact source, generated artifact, policy, deployment and bundle bytes. The
checked-in Humana policy remains pending with no selectable profile or fabricated freshness value.

This is deliberate. SMF must not create an accidental production execution path
while the factory is still being developed.

## CLI

```bash
smf execute examples/simple/example.sas out/example/example.py \
  --target pyspark --provider local --out out \
  --run-id run-1 --workload-id example --attempt-id execute-1
```

Databricks configuration check:

```bash
smf execute examples/simple/example.sas out/example/example.py \
  --target pyspark --provider databricks --out out \
  --run-id run-1 --workload-id example --attempt-id execute-1
```

## Evidence

Execution results are written to:

```text
out/runs/<run-id>/workloads/<workload-id>/attempts/<attempt-id>/execution/
  execution.claim.json
  execution.manifest.json
```

Evidence includes:

- execution provider
- workload and attempt identity
- source and generated-artifact SHA-256 digests
- status
- duration
- exit code
- stdout
- stderr
- run/request ID
- workspace host
- warnings
- static-validation status and confidence

The claim is published before provider execution. A prior terminal manifest blocks same-attempt
re-execution, and a claim without a manifest is treated as an unknown outcome that also blocks
retry. After side effects are reconciled, an authorized retry uses a distinct attempt ID and cannot
overwrite the earlier evidence.

## Next increment

The next Databricks execution increment may implement actual remote submission only after validation
workspace details and named-owner compute limits are approved, and only by consuming and reverifying
the DBX-03 decision. Remote submission remains disabled.

That implementation should capture:

- Databricks run ID
- compute identifier / policy
- runtime version
- start and end time
- execution result
- stdout/stderr or task output
- output datasets
- schema evidence
- row counts
- performance metrics
