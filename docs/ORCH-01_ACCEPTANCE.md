# ORCH-01 bounded acceptance evidence

ORCH-01 supplies a replay-first, attempt-bound workload lifecycle ledger for the minimum Day-1
conversion path. It consumes root-confined immutable evidence, accepts stage success only when an
Ed25519 receipt is signed by a policy-bound synthetic authority permitted for that exact stage, and
consumes failures only after the complete FAIL-01 request and its current upstream bytes replay
successfully. This increment deliberately rejects a caller label that attempts to elevate a stage
authority to governed runtime evidence.

The explicit path is `pending_readiness -> ready -> converted -> executed -> validated`. Separate
states preserve `blocked`, `unsupported`, `failed`, `human_pending`, `outcome_unknown`,
`human_approved`, `human_denied`, and `cancelled`. A bounded repair receipt can return an eligible
conversion failure to `converted`; it cannot repair a failure whose governed next action does not
permit repair. A terminal, cancelled, stale, duplicate, out-of-order, cross-attempt, future-dated,
expired-policy, forged, mutated, traversal, symlinked, or protected-data-bearing event fails closed.

Publication is append-only and isolated by run, workload and attempt. Replay reacquires every stage
receipt and every FAIL-01 source observation. Recovery may derive a missing telemetry projection
only from a byte-identical canonical result and current inputs. Synthetic signing keys prove only
the contract mechanics; their history is visibly classified `synthetic_contract`. The public result
verifier requires the complete current event inputs rather than treating recomputable JSON digests
as authority. Nested FAIL-01 result and observation roots must remain beneath the lifecycle evidence
root, and descriptor-relative no-follow reads reject linked or swapped roots.

## Acceptance matrix

| Criterion | Evidence |
| --- | --- |
| ORCH-01-AC01 | The positive pipeline and publish/replay tests prove explicit immutable attempt-bound transitions. |
| ORCH-01-AC02 | Failure, unknown-side-effect, human/cancel, expiry and terminal-invariant tests prove distinct states and preconditions. |
| ORCH-01-AC03 | Signature forgery, identity, order, terminal resurrection, recomputed-history forgery and nested-root swap tests reject caller-authored or stale advancement. |
| ORCH-01-AC04 / HC-01 / HC-05 | Result history binds client/source/workload/run/attempt, exact evidence digests, policy, authority class and implementation bytes; replay, recovery and two-workload isolation are tested. |
| HC-02 / HC-03 | The lifecycle has no recall dependency and preserves producer evidence by reference; it does not reinterpret source behavior. |
| HC-04 | Safe identifiers, protected-data admission, root confinement and no-follow reads are enforced without echoing rejected values. |

Run `make orch01-confidence` for the focused gate.

This increment does not run conversion, AI, Databricks, Unity Catalog or Humana systems; approve an
exception; authorize a promotion; establish customer validation, semantic parity, production
readiness or migration completion; provide batch scheduling/backpressure; or implement the later
full-modernization workflow. MIGCLI-01 and ORCH-03 remain responsible for operator command wiring
and cross-attempt resume behavior.
