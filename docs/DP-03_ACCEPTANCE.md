# DP-03 distributed keyed aggregate reconciliation

DP-03 composes the existing TASK-12 tolerance engine with a bounded distributed
acquisition contract. It consumes an immutable, Ed25519-signed source aggregate
receipt and computes the target aggregate through the exact
`spark-keyed-aggregate` adapter. The adapter performs `groupBy` aggregation in
the dataframe runtime and streams only the bounded grouped result through
`toLocalIterator`. It never calls `collect`, `toPandas`, or materializes the
complete source or target table in local memory.

The request binds client, workload, run, attempt, source and target snapshots,
comparison scope, source receipt, authority, policy, adapter revision, maximum
group count and an externally supplied trust-policy digest. Source receipt and
target execution-observation proofs use separate allowlisted Ed25519 key and
authority domains. The target proof binds the actual adapter output, target
snapshot and complete request digest. Scope mismatch and source group overflow
block before target access. Source input bytes are descriptor-read under a
request-derived bound; target aggregate rows are streamed only through the same
group bound. Provider failure and group-limit exhaustion are categorical
blockers with no provider diagnostic persisted. The source receipt is reread
and its proof reverified after distributed work so a mid-run mutation cannot
authorize a result.

Group identities are inspected with the governed protected-data detector before
publication. SSNs, email addresses, member identifiers, secret canaries and
their supported encodings are replaced with deterministic, non-reversible
HMAC-SHA256 tokens. The token key never enters evidence; only its digest is
bound into the externally supplied trust policy. Raw protected values are
rejected at every receipt and observation serialization boundary.

| Criterion | Evidence | Result |
| --- | --- | --- |
| DP-03-AC01 | `test_distributed_keyed_aggregate_passes_without_collect_or_pandas` and null/tolerance tests | Declared key and measure use explicit Decimal, null-count, absolute and relative policies. |
| DP-03-AC02 | `test_offsetting_group_errors_and_missing_group_do_not_disappear` | Every source and target group/value/difference remains in TASK-12 evidence; offsetting group errors independently fail. |
| DP-03-AC03 | Overflow, null mismatch, missing-group, provider and source/target group-limit boundary tests | Missing groups and null mismatches fail; overflow and both acquisition boundaries block; aggregate pass never asserts cell or data parity. |
| DP-03-AC04 / HC-01 | Strict receipt/result schemas, independent Ed25519 proofs, immutable publication and full reconstruction | Evidence binds exact identities, snapshots, scope, governed trust, source receipt, actual target adapter observation and policy revisions. |
| HC-02 / HC-03 | Direct deterministic composition of DP-02/TASK-12 patterns | No recalled advice, LLM output, target generation, or SAS semantic inference participates. |
| HC-04 | Protected-value, unsafe-identity and categorical-provider-error tests | Protected group values are irreversibly tokenized; secret-like identities reject; provider diagnostics do not enter evidence. |
| HC-05 | Signed coherent-rehash, receipt mutation, cancellation, retry and two-workload isolation tests | Rehashing cannot replace authority proofs; mutation fails closed; cancellation prevents provider work or immutable publication; retry is byte-idempotent; workload paths and evidence remain isolated. |

Telemetry separately records reconciliation execution, validation, aggregate
pass, blocked state and human assistance. `executed=false` means this receipt
does not independently prove source or target workload execution;
`reconciliation_executed` records only the bounded distributed aggregate job.

This increment does not access Humana or Databricks, approve groupings,
measures or tolerances, establish cell-level/full-row/data/SAS semantic parity,
certify a migration, or establish production readiness. Group values entering
this contract must already be canonical strings; typed cross-provider group
canonicalization remains an upstream responsibility. Protected-data
tokenization prevents disclosure but does not authorize a grouping or establish
equivalence. The bounded grouped receipt is not suitable for unbounded
high-cardinality keys and fails closed at the configured maximum.

The synchronous cancellation contract checks before provider work, immediately
after the distributed provider returns, and immediately before immutable
publication. A cancelled attempt raises `InterruptedError` and publishes no
result. The dataframe runtime remains responsible for interrupting work while
its synchronous `groupBy` operation is in flight; DP-03 does not claim a remote
Spark cancellation controller or persist a cancelled result as validation
evidence.

Focused verification:

```text
PYTHONPATH=src .venv/bin/python -m pytest -q tests/unit/test_dp03_*.py tests/unit/test_aggregate_tolerance.py
.venv/bin/python -m ruff check src/smf/validation/dp03.py tests/unit/test_dp03_*.py
.venv/bin/python -m mypy src/smf/validation/dp03.py
```
