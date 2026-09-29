# DP-02 distributed row-count acceptance

DP-02 composes the existing governed row-count tolerance evaluator with a
distributed-capable target count adapter. It binds source and target dataset,
snapshot, scope, run, attempt, adapter and policy identities into immutable,
replayable evidence. The Spark adapter invokes only the distributed `count()`
aggregate; it never collects table rows into local memory.

## Bounded implementation

- The source baseline must be loaded from a root-confined immutable receipt whose
  provider, authority, binding and exact content digest match the governed request.
- The target count must be observed through the exact qualified distributed
  aggregate adapter; arbitrary adapters and caller-authored mode assertions are
  rejected.
- Both scope identifier and scope digest must align before comparison.
- Missing counts, provider failure and scope mismatch remain explicit blocked
  outcomes. A non-qualified or metadata-only target adapter is a rejected
  precondition and cannot emit authoritative result evidence.
- Exact, absolute and relative tolerances reuse the versioned TASK-11 policy.
- Publication and replay reacquire both current inputs. Evidence is no-replace,
  mutation-detecting, request-bound and isolated by client, workload, run and
  attempt.

An equal row count proves only that this check passed. It never proves cell
parity, data parity, certification, Humana validation or migration completion.

## Acceptance matrix

| Criterion | Evidence |
| --- | --- |
| DP-02-AC01 | Unit tests cover exact distributed counts, scope-ID and scope-digest mismatch, and the existing exact/absolute/relative tolerance suite. |
| DP-02-AC02 | Strict composed schemas preserve both observations, counts, identities, the full TASK-11 policy/result contracts, reason, blockers and immutable digests, including empty datasets. |
| DP-02-AC03 | Equal-count tests keep cell/data parity false; mismatch, missing baseline, provider failure and negative/boolean counts fail closed. Forged and unqualified target adapters are rejected before evidence generation. |
| DP-02-AC04 | Forged adapters, source-receipt substitution, target drift, snapshot/scope substitution, coherent-claim mutation, immutable retry and two-workload isolation tests bind the result to current governed inputs. No real Humana execution is claimed. |
| HC-01 | Client, workload, run, attempt, dataset, snapshot, scope, adapter and policy versions are digest-bound; row-count, cell-parity and certification claims remain separate. |
| HC-02 | Not applicable by design: the evaluator consumes current immutable inputs and has no recall, embedding or advisory-memory dependency. |
| HC-03 | DP-02 evaluates counts only and does not consume workshop output, SAS formatting, macro processing or target templates. Cell reconciliation remains independently required. |
| HC-04 | Safe-identifier validation rejects secret-like identities; provider exceptions are reduced to non-authorizing unavailable evidence without persisted error text. |
| HC-05 | Positive, negative, adversarial, mutation, retry and isolation cases are covered; blocked and failed results cannot satisfy parity claims. |

## Record-level verification

From a clean DP-02 worktree with the repository Python 3.12 environment:

```text
python -m ruff format --check src/smf/validation/dp02.py tests/unit/test_dp02_row_count.py
python -m ruff check src/smf/validation/dp02.py tests/unit/test_dp02_row_count.py
python -m mypy src/smf/validation/dp02.py
python -m pytest -q tests/unit/test_dp02_row_count.py tests/unit/test_row_count_tolerance.py tests/unit/test_repository_hygiene.py
```

The focused boundary produced 57 passing tests. Full-suite, vulnerability,
combined-train and remote-CI results belong to the later integration boundary
and must not be inferred from this record-level result.
