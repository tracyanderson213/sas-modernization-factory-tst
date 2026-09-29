# Core SAS Semantic Corpus

CORPUS-02 provides small deterministic SAS programs as precision instruments for exact language behavior. It is separate from the representative public portfolio and from all private-client evidence.

## Provenance model

These files are **SMF-authored semantic fixtures**. They are not represented as client workloads and are not copies of public SAS programs. The manifests retain an Apache-2.0 public SAS reference from the `sascommunities/learning-sas-by-example-2nd` repository because that material was used to confirm that the selected constructs are legitimate SAS 9 programming patterns.

This creates a clean distinction:

- Public artifacts in CORPUS-02A are genuine upstream SAS sample files curated into SMF.
- Semantic fixtures in CORPUS-02B are intentionally small SMF-authored programs designed for precise assertions.
- Representative multi-artifact workloads will compose these constructs later.
- Client-derived workloads remain isolated and private when available.

## Fixture layout and contract

- `workloads/semantic/core/` retains the original five discovery-consumed scenarios.
- `workloads/semantic/adversarial/` contains one-primary-behavior edge cases.
- `workloads/semantic/expected/` contains canonical JSON results.
- `manifests/semantic-*.yaml` bind fingerprinted programs and results to output evidence and a typed `semantic_oracles` comparison contract.

Each oracle pins column order, logical types, lengths and nullability; row comparison as `ordered`, `keyed`, or `unordered-multiset`; explicit numeric tolerances; underlying versus formatted value authority; and SAS session assumptions (`YEARCUTOFF`, locale, encoding, sort sequence, and timezone). Numbers are serialized as `{"number":"..."}` so decimal text is stable. Ordinary and special SAS missing values are serialized as `{"missing":"."}`, `{"missing":"._"}`, or `{"missing":".A"}` through `{"missing":".Z"}`; character missing uses `{"missing":"character"}`. When formatted values are authoritative, `formatted_rows` provides a string projection positionally aligned with `rows` and `columns`; `both` compares both projections.

To add a fixture:

1. Write a standalone, SMF-authored SAS program with one stated primary behavior and deterministic in-program or declared inputs.
2. Add a canonical expected JSON result and fingerprint both artifacts.
3. Declare authoritative, deterministic `declared-synthetic-expectation` output evidence and bind one oracle to it.
4. Add the primary behavior and construct capabilities to the manifest and prove mutation sensitivity in the corpus gate.

The registry validates semantic manifests in deterministic filename order. The comparator reports schema, row, key, multiplicity, missing-value, and cell paths without executing SAS or a target engine.

## Capability coverage

The corpus covers DATA step processing and iteration, informats/formats and coercion, ordinary and special missing values, match merge and duplicate keys, BY groups, FIRST./LAST., RETAIN, conditional LAG queues, macro generation and indirect resolution, many-to-many PROC SQL behavior, date boundaries, floating-point precision, and empty datasets. The `semantic-temporal-literals` fixture additionally records synthetic underlying and formatted projections for the SAS date epoch, a pre-epoch date, a leap day, and a six-digit fractional datetime under an explicit UTC session assumption.

## Evidence boundary

The checked-in expected results are declared SMF expectations, not outputs captured from SAS. They must remain labeled `declared-synthetic-expectation`. A later approved SAS 9 run may supplement or replace them with `sas-executed-baseline` evidence carrying run identity and logs.

The temporal fixture does not authorize conversion or parity and does not expand the implemented
literal subset to its PROC SQL `FORMAT` clauses. It is an independently attributable synthetic
oracle for comparator and mutation testing; trusted Humana qualification still requires approved
SAS-executed evidence and runtime policy.

WLD-03 consumes selected fixtures for deterministic static discovery assertions. A valid fixture and a passing comparator prove only the structural oracle gate. They do not prove that SAS executed the fixture, that a conversion exists, that Databricks executed it, that source and target are equivalent, or that anything is certified.
