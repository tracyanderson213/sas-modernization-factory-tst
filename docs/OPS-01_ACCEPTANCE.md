# OPS-01 centralized competition telemetry acceptance

OPS-01 projects immutable, categorical evidence into workload/run/attempt
streams without changing source truth. A versioned policy fixes every expected
stream, source artifact and evidence authority. Missing streams and sequence
gaps remain visible and cannot qualify any stage claim.

## Bounded behavior

- Events are root-confined, no-follow, digest-bound and correlated to exact
  client, cohort, workload, run, attempt and source identities.
- Duplicate identities and sequences fail closed. Out-of-order delivery is
  sorted once, recorded explicitly and never increases the event count.
- Generated, executed, validated, parity-passed, human-assisted, blocked and
  skipped remain separate booleans. Stage progression is monotonic.
- Parity can originate only from a canonical validation `parity_result` event.
  Logs and recalled events cannot set workload truth or a terminal disposition.
- Blocked and skipped events require categorical blocker codes. No free-form
  logs, credentials, source rows or provider errors enter canonical telemetry.
- Complete streams may project observed claims. Gapped or missing streams set
  all qualified claims false and use `ingestion_incomplete`.
- Each result binds the strict categorical event projections and original
  delivery sequence needed to reconstruct stream state during standalone replay.

## Acceptance matrix

| Criterion | Evidence |
| --- | --- |
| OPS-01-AC01 | Canonical event tests preserve source-result bindings and project claims without certifying parity or altering lifecycle truth. |
| OPS-01-AC02 | Policy-bound stream tests correlate workload/run/attempt/schema identities; immutable publication/current replay and missing/gap projections prove durable delivery behavior. |
| OPS-01-AC03 | Duplicate identity/sequence, out-of-order delivery, log/recall parity, non-validation parity, blocker omission and coherent claim escalation tests fail closed without inflating success. |
| OPS-01-AC04 | Source/cohort/authority mismatch, traversal, mutation, replay and two-cohort isolation tests bind the exact offline evidence. No live Humana execution is claimed. |
| HC-01 | Generated, executed, validated, parity, human assistance, blocked/skipped and higher customer claims remain separate. |
| HC-02 | Not applicable by design: OPS-01 consumes current immutable events and has no recall store; recalled events are explicitly non-authorizing. |
| HC-03 | Telemetry does not convert SAS or treat logs/workshop output as an authoritative baseline. |
| HC-04 | Secret-like identifiers and unsafe paths are rejected; the persisted contract allows only categorical safe fields. |
| HC-05 | Positive, negative, adversarial, mutation, retry-order and isolation fixtures preserve blocked, skipped and ingestion-incomplete outcomes. |

The synthetic event contract does not independently qualify the upstream
lifecycle or validation result named by an event. Real competition telemetry
requires the policy to admit independently verified current producer receipts.
This increment establishes no live Humana telemetry, production observability,
parity certification, readiness or migration-completion claim.

Full-suite, vulnerability, combined-train and remote-CI results belong to the
integration boundary and must not be inferred from focused OPS-01 tests.
