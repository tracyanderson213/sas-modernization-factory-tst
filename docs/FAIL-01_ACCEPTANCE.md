# FAIL-01 bounded acceptance evidence

## Implemented boundary

FAIL-01 supplies a versioned, offline failure-classification contract for Day-1 migration
orchestration. It assigns an admitted reason code to exactly one stage, category, owner,
retryability, repairability, blocker class, side-effect state, terminal disposition, and permitted
next action. Those decisions are derived from a closed policy table; callers cannot set retry or
repair flags independently.

The result binds client, source, workload, run, attempt, event, evaluation time, root-confined
no-follow evidence references and verified byte SHA-256 digests, causal references, taxonomy
version, and implementation bytes.
Publication is immutable and root-confined. Replay reconstructs the result from current inputs and
runtime bytes; mutation, overwrite, cross-workload collision, and unsafe identity inputs fail
closed. Telemetry is a strict projection of the canonical result.

This increment classifies already governed failure observations. An evidence reference is not a
substitute for the upstream producer's authenticity or semantic checks. Orchestration must pass the
applicable governed upstream result and preserve it independently.

## Acceptance mapping

| Contract | Evidence |
| --- | --- |
| FAIL-01-AC01 | `test_every_reason_has_a_closed_machine_actionable_policy` covers every stage/reason policy and verifies explicit terminal and retry semantics. |
| FAIL-01-AC02 | Result and telemetry schemas require workload/run/attempt identity, safe evidence digests, owner, escalation action, and causal references. Publication/replay tests bind and reconstruct them. |
| FAIL-01-AC03 | Stage/reason conflicts, wrong evidence classes, self/duplicate causes, unknown fields, unsafe identities, and changed inputs are negative-tested. Unknown execution or AI outcomes explicitly prohibit automatic retry. |
| HC-01 | Result identity binds client/source/workload/run/attempt/event plus descriptor-acquired evidence bytes, cause, implementation, and taxonomy digests. |
| HC-02 | No recall or durable-intelligence service is consumed. Evidence remains attributable and advisory until its upstream contract authenticates it. |
| HC-03 | The classifier does not change source or target artifacts. Lifecycle states distinguish generation, execution, validation, and parity without inferring success. |
| HC-04 | Strict safe identifiers reject protected-data and secret-like canaries without echo. No diagnostic text or credentials are persisted. |
| HC-05 | Positive, negative, mutation, replay, recovery, idempotency, and two-workload isolation tests keep blocked, failed, unsupported, human-pending, and outcome-unknown states visible. |

Run the focused gate with:

```bash
make fail01-confidence
```

## Bounded claims

This foundation does not retry a workload, invoke the AI Gateway or a model provider, contact an
external system, approve an exception, obtain a human decision, execute or validate migration
artifacts, prove parity, or establish Humana, migration, production, or operational readiness.
Unknown external side effects always produce `outcome_unknown_do_not_retry` and require target
read-back before another execution attempt.

Business tolerances, security exceptions, customer owners, live endpoints, credentials, external
authority, and promotion decisions are not supplied or inferred by this contract.
