# DBX-04 bounded runtime-evidence receipts

DBX-04 implements the offline contract mechanics for immutable, reconstructable runtime receipts.
It fully replays the current DBX-01 plan and binds client, deployment, environment, source,
workload, run, attempt, package and evaluation-time identity before publishing evidence.

This increment accepts only the closed `synthetic_contract` observation type. It stores bounded safe
logs and immutable `evidence://` output references, classifies missing logs, missing outputs,
contradictory task states, unknown outcomes and expired references, and always retains
`live_runtime_evidence_required`. Protected-data or secret-shaped logs and references fail before
hashing or persistence. Publication is root-confined, no-follow, atomic, idempotent for exact bytes,
mutation-detecting and isolated by run/workload/attempt.

The contract cannot submit, poll or cancel live work and cannot establish that Databricks executed
anything. Its execution, validation, parity, Humana-readiness, production-readiness and migration
completion claims are always false. A future live adapter requires separately authorized current
provider receipts and customer-environment access; synthetic receipts cannot satisfy that gate.

## Acceptance matrix

| Criterion | Evidence | Bounded result |
| --- | --- | --- |
| DBX-04-AC01 | actual DBX-01 prepare/publication/current-input replay chain, request/plan identity checks, drift negative, stable receipt ID and content digest | Passed offline for synthetic receipts only |
| DBX-04-AC02 | ordered task observations, bounded safe logs, immutable output references, replay and isolated publication tests | Passed offline; no real runtime evidence claimed |
| DBX-04-AC03 | missing/contradictory/unknown/expired classifications plus secret and traversal negatives | Passed fail-closed |
| DBX-04-AC04 | exact plan/package/snapshot bindings, restart/mutation/isolation tests and false-claim schema | Passed contract mechanics; live execution remains blocked |
| HC-01/HC-05 | identity matrix, immutable manifest, adversarial mutation and exact retry tests | Passed bounded mechanics |
| HC-02/HC-03 | no durable-memory or source-conversion dependency | Not applicable to this receipt-only increment |
| HC-04 | protected-data canary rejection before persistence | Passed |

Run `make dbx04-confidence` for the deterministic acceptance suite.
