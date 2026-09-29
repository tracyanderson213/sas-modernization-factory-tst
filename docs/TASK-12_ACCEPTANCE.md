# TASK-12 aggregate tolerance acceptance

TASK-12 supplies offline, versioned per-measure/per-group aggregate tolerance mechanics for later
DP-03 composition. It consumes bound observations; it does not query source or target systems.

| Criterion | Evidence | Result |
| --- | --- | --- |
| AC01 | Strict policy/result contracts and boundary tests | Canonical Decimal absolute/relative policy is applied per declared measure and group. |
| AC02 | Missing-group, null, nonfinite and overflow tests | Calculations remain explicit; missing groups and null mismatch fail; overflow blocks. |
| AC03 | Two-group offsetting and just-outside-boundary tests | Every group must pass independently; global cancellation cannot hide errors. |
| AC04 / HC01-05 | Snapshot/run identity, replay, mutation, retry, no-follow publication and isolation tests | Synthetic offline mechanics pass; live customer evidence remains unavailable. |

Passing means only that supplied aggregate observations meet the selected policy. The result cannot
establish row/cell or semantic parity, Humana validation, certification, approval, Databricks
readiness, production promotion, or migration completion. Approved business measures, groupings,
tolerances, owners, and real snapshots remain external inputs. The evaluator is synchronous and has
no pending external operation to cancel.
