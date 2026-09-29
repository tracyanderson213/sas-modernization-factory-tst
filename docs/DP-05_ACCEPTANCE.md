# DP-05 deterministic sample comparison

DP-05 provides a deterministic, bounded sample receipt for comparing keyed rows
and cells. It labels every result `assurance_scope=sample_only`; even a passing
sample leaves full-dataset, cell-level, data, and semantic parity claims false.

The versioned policy binds key columns, compared columns, sample size, public
seed, selection algorithm, duplicate policy, and a per-key duplicate bound.
It also explicitly classifies sensitive governed columns. Values in those
columns are transformed with an external-key HMAC before any selection or cell
digest is calculated; the key never enters evidence. Sensitive-looking column
names without that classification fail closed. Other columns continue through
the governed protected-data detector before hashing.
Source and target streams must be ordered by canonical key digest and row
digest. The exact adapter verifies that ordering while streaming, retains only
the bounded sample and current duplicate group, and hashes every admitted key
and cell after protected-data screening. Plain row values and keys are never
written to evidence.

Selection uses `sha256-key-ordinal-v1`: stable key digests plus the governed
duplicate ordinal form a sample identity, and seed-bound scores select the
lowest ordered identities. `reject` makes duplicate keys an explicit failure;
`stable_ordinal` aligns a bounded duplicate group in canonical row-digest order.
Noncanonical input is reported as biased selection rather than silently sorted
locally. Missing/unmatched keys, changed sampled cells, population mismatch,
provider failure, empty input, and snapshot-scope mismatch remain distinct.

The request binds an externally supplied trust policy. Source and target
runtime domains use disjoint authority identities, authority digests and
Ed25519 signing keys. Each signed observation binds its side, request digest,
policy digest, dataset snapshot, exact adapter output and execution identity.
Missing or untrusted authority is a machine-readable blocker. Replay verifies
the external trust policy and both proofs; recomputing embedded digests cannot
authorize changed sample cells.

| Criterion | Evidence | Result |
| --- | --- | --- |
| DP-05-AC01 | Stable-order, duplicate-reject and stable-ordinal tests | Selection is seed/algorithm/key bound; duplicate behavior is explicit and reproducible. |
| DP-05-AC02 | Coverage and alignment assertions plus strict schemas | Evidence retains population/selected/aligned/unmatched/mismatch counts, sample IDs, selection scores and mismatched column names without row values. |
| DP-05-AC03 | Mutation, unmatched-key, biased-stream and duplicate tests | Equal samples assert only sample assurance; duplicate, biased, mutated and unmatched observations fail explicitly. |
| DP-05-AC04 / HC-01 | Request/result identities, disjoint signed runtime observations and immutable publication | Client, workload, run, attempt, snapshots, scope, adapters, authority and policy are externally trust-bound and reconstructable. |
| HC-02 / HC-03 | Deterministic implementation inspection | No LLM, recalled advice, SAS inference or target generation affects selection. |
| HC-04 | Protected canary, classified string/numeric member-ID and unsafe-identity tests | Classified sensitive values are external-key HMAC protected before hashing; unclassified detected values fail; diagnostics, raw cells and keys never persist. |
| HC-05 | Signed coherent-rehash, authority blocker, retry and two-workload isolation tests | Mutated evidence fails proof verification; missing/untrusted runtime authority blocks; retry is byte-idempotent; workload evidence paths remain isolated. |

The adapter consumes a provider-supplied canonical stream; live source/target
acquisition and distributed ordering belong to the separately governed DBX-04
execution boundary. This implementation does not access Humana or Databricks,
approve sample policies or business keys, prove live provider execution, or
replace required distributed full-row reconciliation. The signed contract
proves only that an allowlisted adapter authority issued an observation for the
bound snapshot; external runtime admission remains a prerequisite. Cancellation is a
provider/runtime concern because this synchronous contract has no background
operation or cancellable state.

Focused verification:

```text
PYTHONPATH=src .venv/bin/python -m pytest -q tests/unit/test_dp05_*.py
.venv/bin/python -m ruff check src/smf/validation/dp05.py tests/unit/test_dp05_*.py
.venv/bin/python -m mypy src/smf/validation/dp05.py
```
