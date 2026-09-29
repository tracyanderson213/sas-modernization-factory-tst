# DP-04 Distributed Null and Distribution Profiling

## Bounded implementation

DP-04 implements engine-neutral, distributed profiling and reconciliation over partition iterators.
Each partition is scanned once and discarded. Evidence retains only bounded sufficient statistics:
ordinary-null counts, all 28 SAS missing categories (`.`, `._`, `.A` through `.Z`), numeric
count/sum/sum-of-squares/min/max/declared-bin counts, and declared-category plus `other` counts.
Neither pandas nor whole-table collection is used.

The contract consumes already acquired rows. It does not connect to SAS, Humana, Databricks, or
Unity Catalog, and it does not authorize data access. Provider adapters remain responsible for
streaming partitions into this contract and for binding real runtime receipts.

## Distributed and sampled execution

Partition receipts bind client, workload, source, run, attempt, artifact, snapshot, provider,
policy, side, sampling method, evidence class, governed authority/key and partition identity. Every
receipt is signed with an Ed25519 key selected by the policy for the exact side, authority, provider,
provider version and evidence class. Source and target authority IDs, key IDs and public-key material
must be disjoint; a receipt cannot cross-sign between sides. A recomputed content digest cannot
repair a changed receipt.
Merge order and partition shape do not affect
the aggregate. Deterministic hash sampling uses declared key columns and a seed. Its bounded sample
scope identity combines selected count with modular-sum and XOR accumulators over SHA-256 key
hashes, so source and target can compare the same sampled key multiset without retaining keys or rows.
Sampling keys use a closed, type-tagged canonical representation for nulls, booleans, bounded
integers, strings, finite Decimals and explicit SAS missing categories. Floats, custom objects and
caller-defined string coercion are rejected. Protected or encoded-protected sampling values are
rejected before serialization or hashing.

Exact and sampled profiles cannot be mixed. Different sampling configuration or deterministic
sample scope yields `incompatible`, never a distribution match. Blocked partitions also yield an
incompatible reconciliation.

## Outcome and claims

The closed reconciliation outcomes are:

- `passed`: all missing categories and declared distribution checks pass;
- `failed`: comparable evidence contains a real null/distribution difference; or
- `incompatible`: identity, sampling, prerequisite, or partition evidence is not comparable.

All-null state, shifted distributions, ordinary nulls, and individual SAS missing categories remain
separate checks. Generated, executed, validated, parity-passed, human-assisted, human-approved, and
production-ready claims remain separate. This bounded contract admits only `synthetic_contract`
receipts. They can produce a mechanical `passed` outcome, but their executed, validated and
parity-passed claims are schema-fixed false. A later real-provider integration must introduce and
independently qualify its canonical runtime authority contract; caller-authored evidence-class text
cannot enable runtime claims here. A local synthetic result does not establish Humana parity,
business acceptance, or production readiness.

## Acceptance matrix

| Criterion | Implementation evidence | Bounded result |
|---|---|---|
| DP-04-AC01 | Partition iterators, mergeable numeric/category sufficient statistics, exact null counts | Implemented without table collection |
| DP-04-AC02 | Strict policy records exact/hash method, fraction, seed, keys, bins, categories and tolerances; receipts bind per-column evidence | Implemented; real runtime receipt external |
| DP-04-AC03 | Tests distinguish shifted bins/categories, all-null state and incompatible sampling | Implemented |
| DP-04-AC04 / HC-01 | Source/target snapshots, provider, policy, run/workload/attempt/artifact, evidence class and signed partition receipts bind the result | Implemented mechanically; synthetic claims remain false |
| HC-02 | No recalled or derived knowledge is consumed | Not applicable by design |
| HC-03 | Source and target are independently profiled and reconciled; output cannot self-certify | Implemented |
| HC-04 | Strict IDs/digests, recursive replay sanitization, pre-hash sampling-key rejection, bounded category policy, no-follow governed policy load, immutable publication | Synthetic tests only |
| HC-05 | Positive, shifted, missing-category, sampling, coherent-rehash, replay, retry, pre-publication cancellation and isolation tests | Implemented |

## Replay, retry, and isolation

Strict schemas reject unknown fields. Partition receipts use canonical content digests plus
policy-scoped Ed25519 signatures; final results use canonical content digests. Replay reapplies
protected-data checks, verifies the exact receipt authority/signature, revalidates receipt semantics,
recomputes both aggregates and the complete result, and rejects changed claims or statistics.
Publication checks cancellation before replay and again immediately before the immutable write, so
a cancelled synchronous attempt publishes no canonical result. Once the atomic write begins there
is no exposed pending remote operation to cancel. Publication uses the repository's immutable no-replace
writer under run/workload/attempt paths: identical retry is idempotent, conflicting bytes fail, and
independent workloads do not share mutable state.

## Resource bounds

Policies admit at most 128 columns, 256 numeric-bin boundaries per column, 512 declared categories
per column and 16 sampling-key columns. Reconciliation admits at most 4,096 partition receipts per
side and 1,282 checks; schemas independently cap the corresponding columns, bin counts, category
maps, partition counts and digest/check arrays. Canonical policy, partition and result evidence are
limited to 1 MiB, 2 MiB and 16 MiB respectively, with the limit enforced during validation,
before publication, and while reading governed policy bytes. Boundary and overflow tests cover the
cardinality and byte ceilings.

## Verification

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q tests/unit/test_dp04_profiles.py
.venv/bin/python -m ruff check src/smf/validation/dp04.py tests/unit/test_dp04_profiles.py
.venv/bin/python -m ruff format --check src/smf/validation/dp04.py tests/unit/test_dp04_profiles.py
PYTHONPATH=src .venv/bin/python -m mypy --strict src/smf/validation/dp04.py
git diff --check
```

The focused tests use synthetic in-memory iterators only. Physical SAS/Databricks execution,
customer tolerances, business dispositions, and full migration certification remain external and
must not be inferred from this implementation.
