# ORCH-03 bounded acceptance evidence

ORCH-03 supplies an offline, replay-first restart planner over the immutable ORCH-01 attempt
ledger. A signed attempt inventory is accepted only from a policy-bound synthetic authority, and
every inventory entry is then verified against the complete current ORCH-01 request, policy,
events, result and telemetry. The inventory cannot advance authority: it is classified
`synthetic_contract`, and a caller cannot assert that an attempt ran or that an external side
effect was reconciled.

The planner deterministically selects the next stage for a new attempt, derives an idempotency key
from the exact request, policy, lineage and decision, and never overwrites an earlier attempt. A
stale or over-age lineage snapshot, stale latest-attempt pointer, discontinuous inventory,
exhausted retry budget, cancellation,
terminal validation or pending human decision fails closed. Any `outcome_unknown` in the complete
lineage blocks retry until a separately governed external-effect reconciliation is supplied by a
future authorized runtime contract.

Result and telemetry evidence are immutable and isolated by run, workload and restart. Replay
reacquires the signed lineage and every ORCH-01 input; coherent JSON re-digests cannot forge a
decision. Recovery derives missing telemetry only from a byte-identical result and current inputs.
Protected-data identifiers, traversal, symlinks, swapped roots, cross-workload evidence, future
observations and expired policies are rejected without echoing rejected values.

## Acceptance matrix

| Criterion | Evidence |
| --- | --- |
| ORCH-03-AC01 | Positive lifecycle replay proves deterministic resume selection, new-attempt identity and idempotency. |
| ORCH-03-AC02 | Cancellation, empty-lineage, retry-limit and unknown-side-effect cases prove fail-closed recovery boundaries. |
| ORCH-03-AC03 | Signature, digest, identity, latest-pointer, traversal, symlink and coherent-forgery tests reject stale or caller-authored authority. |
| ORCH-03-AC04 | Immutable publication, current-input replay, telemetry recovery and cross-workload isolation preserve restart evidence. |
| HC-01 / HC-05 | Exact client/deployment/environment/source/artifact/workload/run/attempt/result bindings and implementation digests are sealed. |
| HC-02 / HC-03 / HC-04 | No source behavior is reinterpreted; safe identifiers and no-follow root confinement remain fail closed. |

Run `make orch03-confidence` for the focused gate.

This increment plans only. It does not execute a retry; submit to Databricks or an AI gateway;
reconcile an external side effect; approve an exception, promotion or business decision; establish
Humana validation, semantic parity, production readiness or migration completion; or implement the
later full-modernization workflow.
