# BASE-02 governed dataset mapping acceptance

BASE-02 consumes the independently reconciled BASE-04 canonical descriptor and emits a strict,
versioned source-to-target mapping decision. It maps underlying physical values only. It neither
generates nor executes target code, and every result keeps execution authorization false.

## Qualified bounded mapping

The checked-in public-fixture policy binds the exact `ag121a_supp_sample.sas7bdat` snapshot,
BASE-04 descriptor, source and target dataset versions, target namespace, transformation version,
column order and physical types. Its eight columns preserve the provider-observed underlying
values as either UTF-8 strings or non-narrowed binary64 doubles. Declared SAS formats and
informats remain metadata; the executable mapping allowlist remains empty.

One-to-many mappings are representable only as uniquely named, explicitly versioned targets with
an attributable rationale. Every target must independently account for every source column.
Renames require an explicit rationale. Basename similarity never supplies identity or authority.

## Fail-closed boundaries

The following remain unresolved external decisions and cannot be promoted by this record:

- customer mapping authority, business keys and one-to-many business disposition;
- executable format/informat behavior or custom catalog semantics;
- preservation of distinct SAS special-missing values;
- numeric business tolerances and any lossy narrowing;
- timezone, locale and `YEARCUTOFF` where temporal semantics apply;
- authoritative SAS output and target-runtime semantic parity.

Snapshot, descriptor, encoding, column, format, informat, validity-window or identity mismatch
produces a blocked decision. Protected-data or secret-like identities are rejected without echo.
Evidence is request-bound, immutable, no-replace and replayed against current BASE-04 and source
inputs. Cancellation cannot publish a BASE-02 result; retry and workload isolation are tested.

## Acceptance matrix

| Criterion | Evidence |
| --- | --- |
| BASE-02-AC01 | Actual BASE-04 descriptor is mapped with explicit versioned source/target identifiers and complete column policy. |
| BASE-02-AC02 | Unique-target validation and an attributable synthetic one-to-many contract test. |
| BASE-02-AC03 | Snapshot, descriptor, format/informat, incomplete/ambiguous mapping and rename negatives fail closed. |
| BASE-02-AC04 | Real fixture execution, immutable replay/mutation, cancellation/retry, two-workload isolation, strict schemas and independent review. |
| HC-01 | Request, policy, provider descriptor, source snapshot, semantic-policy and transformation versions are digest-bound; all higher-order claims stay false. |
| HC-02 | Not applicable by design: BASE-02 consumes current immutable repository evidence and has no recall, embedding or advisory-memory dependency. |
| HC-03 | Underlying values remain separate from format/informat projection; no workshop code, macro processing, PROC FORMAT execution or target template output is used. |
| HC-04 | Secret-like identity canaries are rejected without echo and no source rows are persisted in mapping evidence. |
| HC-05 | Positive fixture execution plus mismatch, ambiguity, mutation, cancellation/retry and isolation counterexamples remain visible and fail closed. |

Run `make base02-confidence` in the governed vertical-slice environment. The command requires the
exact qualified SCALE-01 artifacts and pinned conversion runtime. Success proves only bounded
mapping mechanics against the licensed public fixture. It does not prove Humana/SAS parity,
custom-format execution, Databricks or Unity Catalog readiness, arbitrary SAS coverage, production
readiness or migration completion.
