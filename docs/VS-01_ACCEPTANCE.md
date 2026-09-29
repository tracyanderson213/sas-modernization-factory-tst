# VS-01 local SAS7BDAT-to-Delta vertical slice

## Demonstrated path

`make vs01-confidence` executes the Apache-2.0 licensed
`Roche/pyreadstat:test_data/basic/sample_bincompressed.sas7bdat` fixture at evaluated revision
`12cc1495d468ae8a170c57cce7557c147b972eac`, SHA-256
`641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c`.

The path is real and local:

1. BASE-08 reads the binary-compressed SAS7BDAT with pyreadstat 1.3.6 and retains raw SAS temporal
   numerics plus their formats and informats.
2. VS-01 maps the fixture descriptor to an actual Spark 3.5.8 `StructType` and materializes the five
   rows in a local Spark DataFrame. The mapping is explicitly fixture-specific and provisional.
3. The Spark rows are handed through Arrow 25.0.1 to delta-rs 1.6.4 and materialized as a real local
   Delta version-0 table.
4. DataComPy 1.0.4 compares canonically sorted full-row multisets at absolute and relative tolerance
   zero. The full-row alignment is not represented as a source business key. Schema, row count,
   per-column null counts, raw temporal columns and row-multiset digests must all match.
5. SMF publishes the already-qualified reader evidence and a no-replace VS-01 result bound to the
source snapshot, run/workload/attempt, exact configuration, installed runtime RECORD digests,
Spark schema, Delta file manifest and reconciliation result. The configuration also binds the exact
upstream revision, fixture path/size/digest, Apache-2.0 disposition and the preserved combined
pyreadstat/ReadStat license-notice digest. Replay re-reads the source and Delta table; source,
target or evidence mutation fails closed.

The runtime performs no network access and writes only beneath the supplied output root. The test
suite proves a real positive path, snapshot mismatch, output/source mutation, retry recovery and
two-workload isolation.

## Acceptance disposition

| Criterion | Evidence |
|---|---|
| VS-01-AC01 | Actual public SAS7BDAT, pyreadstat, Spark StructType/DataFrame, delta-rs table and DataComPy reconciliation execute in `tests/integration/test_vs01_vertical_slice.py`. |
| VS-01-AC02 | Request/config/runtime/source-reader/output-manifest bindings and immutable replay are exercised on every positive run. |
| VS-01-AC03 | Snapshot mismatch, nonzero tolerance, source mutation and Delta-manifest mutation fail closed. |
| HC-01 | Client/workload/source/run/attempt, source bytes, runtime and output identities are explicit. |
| HC-02 | Upstream fixture/revision/license and exact runtime versions are recorded in `config/dependencies/vs01-runtime.json`. |
| HC-03 | Reader, Spark/Delta output and independent DataComPy reconciliation remain separate evidence stages. |
| HC-04 | The fixture is public; durable evidence contains metadata/digests rather than row values. Output stays under a supplied root. |
| HC-05 | Positive, negative, mutation, recovery and isolation cases use actual runtimes, not mocks. |

## Prohibited claims

VS-01 does not establish the BASE-04 canonical cross-provider descriptor, the BASE-02 governed
production semantic mapping, arbitrary SAS coverage, distributed/large-table reconciliation,
Humana validation, Databricks or Unity Catalog execution, production readiness, semantic parity or
migration completion. Temporal fields remain source-faithful SAS numeric values. PKG-QUAL-01 still
owns final offline artifact/hashes qualification.
