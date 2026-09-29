# VAL-01 distributed reconciliation and certification composition

VAL-01 composes the current `SCHEMA-INT-01`, `DP-02`, `DP-03`, `DP-04`,
`DP-05`, and `DBX-04` evidence into a strict full-row/cell reconciliation
contract. Every prerequisite is read from a root-confined regular file, bound
by exact bytes, identity, request scope and freshness, and replayed through its
module's typed current-evidence verifier. Generic lookalikes and blocked,
stale, future-dated or failed evidence cannot be consumed.

The built-in `SparkDataComPyComparator` performs a Spark full outer join and
distributed scalar aggregations. It never converts a complete table to pandas
or collects a complete table to the driver. Only bounded mismatch rows may
cross the driver through `limit(N).toLocalIterator()`; join keys and values are
domain-separated HMAC tokenized before evidence publication.
DataComPy `SparkSQLCompare` runs as an independent comparison over the same
normalized Spark frames and must agree with the primary comparator.

The versioned policy explicitly governs join keys, null keys, duplicate-key
rejection or deterministic unique tie-breaks, per-column types and coercion,
nulls, absolute/relative numeric tolerance, NaN/infinity, SAS special missing
values, UTF-8/string normalization, underlying-value formatting, date/time
timezone and `YEARCUTOFF`, row ordering, nondeterministic exclusions, and
diagnostic bounds. No tolerance or customer rule is inferred.

The implemented numeric rule is serialized in every policy as
`absolute_plus_relative` with `target_absolute` as the relative denominator:
`abs(source-target) <= absolute + relative*abs(target)`. The primary Spark
comparison evaluates that boundary with decimal arithmetic. DataComPy's
float-only tolerance receives a narrowly outward-rounded representation, but
cannot authorize a match by itself; the exact primary result and DataComPy must
both pass. Null equality, NaN equality, infinity equality, directed coercion,
deterministic duplicate alignment, and row ordering are likewise explicit
policy decisions. Directed coercion must round-trip exactly through the source
type; truncation, overflow, decimal precision/scale loss, and noncanonical
string forms fail unsupported. Ambiguous tie-breaks, missing order keys, and
unrecognized Spark type families also fail unsupported. Every runtime receipt
passes the strict receipt verifier before it leaves the adapter; observed
receipts additionally require cryptographic replay, while the sole unsigned
form is the exact unavailable-runtime blocker. Row-presence diagnostics use the
same domain-separated HMAC boundary as cell values.

Runtime and snapshot evidence must match independently governed exact records
and authority allowlists. That complete authority path is not yet available,
so no current execution can authorize a qualified claim. Synthetic receipts
exercise the composition contract but
leave validation and all parity claims false. Certification, human approval,
Humana validation, production readiness, and migration completion are always
false in this increment.

## Acceptance matrix

| Criterion | State | Exact evidence or blocker |
| --- | --- | --- |
| VAL-01-AC01 | Proven mechanics | Policy-negative tests and distributed cases cover absolute/relative tolerance boundaries, null/NaN/infinity policy, directed coercion, deterministic duplicate alignment, exact type families and ordering. YEARCUTOFF and SAS-special-missing runtime semantics remain unsupported pending provider proof. |
| VAL-01-AC02 | Partial / blocked | Distributed full outer code, bounded HMAC locators and typed prerequisite verifier dispatch exist; governed runtime and snapshot receipts do not. |
| VAL-01-AC03 | Proven fail closed | Mismatch, independent disagreement, mutation, unavailable runtime and nonqualifying prerequisite tests. |
| VAL-01-AC04 | Proven mechanics | Strict mirrored schemas, current replay, atomic publication, cancellation, retry and isolation tests. |
| VAL-01-AC05 | Externally blocked | No approved Humana snapshots, SAS oracle, qualified runtime or customer acceptance evidence. |
| HC-01 | Partial / blocked | Exact verifier composition exists; qualified distributed execution is blocked. |
| HC-02 | Proven mechanics | Static checks forbid pandas and full-table collection. |
| HC-03 | Partial / blocked | DataComPy agreement is mandatory; pinned Python 3.12 runtime cannot import it. |
| HC-04 | Proven mechanics | Protected identifiers reject; key/value diagnostics use keyed HMAC with rotation regression. |
| HC-05 | Proven fail closed | Immutable replay, cancellation and prohibited claims; qualification remains false without external authority. |

## Runtime qualification state

The repository pins PySpark `3.5.8` and DataComPy `1.0.4`; VAL-01 adds no
dependency declaration. Local qualification is explicitly two-stage because no
single approved environment currently satisfies both closures. Stage A uses
the Python 3.12 BASE-08/VS-01 reader closure to stream the byte-pinned SAS
fixture into a distinct source Parquet snapshot and the governed VS-01 Delta
target. Stage B uses Python 3.11 with PySpark `3.5.8` and DataComPy `1.0.4` to
read both snapshots distributed. The immutable transfer receipt binds both
file manifests, the VS-01 result and the Stage-A interpreter/package RECORDs.
The Stage-B runtime manifest binds Python/platform and exact installed RECORD
hashes for Spark, Py4J, DataComPy, NumPy, pandas, PyArrow, gRPC and protobuf
support distributions. The Stage-A setuptools compatibility support is loaded
read-only from the canonical repository environment only after its installed
RECORD is resolved and hashed; the shared environment is never modified.

The real isolated cases passed for exact match, cell mutation, unmatched row,
duplicate rejection, absolute and relative tolerance boundary/outside values,
null/NaN/infinity equality and difference, directed coercion and failed-cast
rejection, deterministic duplicate alignment, explicit ordering, null mutation
and type mismatch. Adversarial coverage includes lossy coercions in both
directions, ambiguous tie-breaks, and a changed governed order whose individual
column multisets are unchanged. SAS special-missing normalization and
date/YEARCUTOFF remain
explicitly unsupported: the current canonical temporal contract itself lists
two-digit-year/YEARCUTOFF behavior as unsupported, and no authoritative SAS
missing-value normalizer is approved. Stale snapshot binding rejects. Each
Spark case runs in a fresh OS session so JVM/cache state from an earlier
comparison cannot influence the next case. The qualification environment
passed `pip check` and the governed `pip-audit` reported no known
vulnerabilities; editable SMF itself was the only authorized skip. No
environment was modified.

Run the deterministic contract gate with:

```text
make val01-confidence
```

Once an independently qualified existing runtime closure is available, require
the real Spark/DataComPy integration lane with:

```text
SMF_REQUIRE_VAL01_RUNTIME=1 make val01-confidence
```

That lane is anchored to the approved byte-pinned
`sample_bincompressed.sas7bdat` fixture and existing VS-01 local Delta slice.
It blocks rather than substitute hand-authored frames, fabricated prerequisite
JSON, or driver-collected Python/PyArrow rows. Completion requires real typed
prerequisite results, production-governed providers and signed snapshot
receipts. The two-stage local evidence proves adapter mechanics only and is a
portability/package-closure input to `PKG-QUAL-01`; it is not a single-runtime
production bundle or customer qualification.

Until that lane passes against authoritative source and target snapshots,
VAL-01 establishes contract and built-in adapter mechanics only. It does not
establish Humana data parity, certification, readiness, or migration completion.
