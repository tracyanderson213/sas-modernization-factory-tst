# Data Parity

## Structural schema parity

Structural schema comparison is implemented as an engine-independent foundation. It consumes two
pre-acquired schema snapshots; it does not connect to SAS or Databricks and does not acquire or map
datasets on the caller's behalf.

Each `dataset-schema-snapshot.schema.json` document identifies the logical dataset, ordered columns,
native and normalized logical types, nullability, applicable width/precision/scale attributes, and
authoritative provenance. The `digest` is SHA-256 over canonical JSON (sorted keys and compact
separators) after removing the `digest` property itself. Snapshots contain no records or sampled
values.

The default policy is strict: names are matched with Unicode case folding, column order matters,
logical and native types must match exactly, attributes and nullability must match, and empty schemas
are blocked. Every exception must be declared in a versioned policy conforming to
`structural-parity-policy.schema.json`. Type mappings identify both source and target logical and
native types; unknown logical types never silently degrade to strings.

Bounded native types such as `CHAR` must supply their applicable length, and decimal types must
supply both precision and scale. Missing type-defining attributes block the comparison. Decimal
widening preserves both fractional capacity and integral capacity (`precision - scale`), so an
increase in scale cannot conceal a narrowing of the integer range.
Under `target_may_widen`, a target native `STRING` with no length is explicitly treated as unbounded;
under the default `exact` rule, a bounded source and unbounded target remain different.

Comparison emits a strict `structural-parity-result.schema.json` manifest. Checks include expected and
actual values, applied policy rule, status, a blocking flag, and diagnostics. Missing, tampered,
unauthoritative, ambiguous, or unmapped evidence yields `blocked`; structural differences yield
`failed`. The manifest records a canonical digest of the complete policy, and that digest contributes
to the comparison identity, so policies with reused IDs and versions cannot collide. Neither outcome
is combined with or offset by the static-validation confidence score.

This capability proves only deterministic comparison of supplied schema evidence. Trusted runtime
acquisition, approved enterprise dataset mappings, and broader data and semantic parity remain
separate work.

## Candidate data checks

- schema equality or approved type mappings
- row-count equality/tolerance
- key uniqueness
- null profile
- numeric min/max/mean
- categorical distributions
- aggregate totals
- deterministic checksums where feasible
- sampled record comparison

## Tolerances

Tolerances must be explicit and policy-driven. Floating-point, timestamp, ordering, and distributed-compute differences may require bounded tolerances rather than byte-for-byte equality.

## Evidence

Every parity check records expected value, actual value, tolerance or applied rule, status, and
diagnostic details.
