# DBPKG-04 restartable Spark-to-Delta ingestion

DBPKG-04 composes existing qualified components for the Day 1 as-is path. It does not implement a
SAS parser or a Delta transaction engine. BASE-04/BASE-02 revalidate the exact BASE-08 and SCALE-01
source observations and bounded underlying-value mapping. SCALE-01 then provides descriptor-
verified private source and JAR snapshots to Spark. Spark writes partitioned Parquet and delta-rs
1.6.4 converts those files to a create-only local Delta version-0 table.

## Restart and evidence contract

The attempt is locked by client/workload/run/attempt identity. An immutable admission checkpoint
binds the source SHA-256 plus BASE-02, BASE-04 and SCALE-01 results. An immutable Delta checkpoint
binds the complete output-file manifest and partition-safe source/target reconciliation. A retry
revalidates current source, policy, provider and artifact bytes before reusing an existing output.
It never appends another Delta version to represent a retry.

Delta output is produced in a private staging directory and renamed only after delta-rs creates a
valid transaction log. Failed staging and mismatched incomplete output move under the attempt's
quarantine directory; they are never reported as success. Source mutation invalidates replay. The
published result and both checkpoints are atomic, no-replace JSON evidence. Two workload/run paths
cannot share checkpoints or Delta output.

Reconciliation scans bounded Arrow record batches from the Delta table and combines duplicate-
sensitive XOR/modulo-sum row digests, row counts and null counts. It does not call `collect`,
`toPandas`, or materialize the full table in local pandas memory. BASE-09 and BASE-11 are not runtime
prerequisites for this common path. Catalogs, views, indexes, encrypted/corrupt datasets and
unsupported encodings publish an actionable blocked exception instead of silently degrading.

## Acceptance matrix

| Criterion | Executed evidence |
| --- | --- |
| DBPKG-04-AC01 | Licensed public SAS7BDAT is read with the qualified SCALE-01 Spark provider, written as partitioned Parquet and converted by delta-rs; no parser/writer engine is added. |
| DBPKG-04-AC02 | Admission/Delta checkpoints and final result bind exact source, configurations, upstream evidence, run/attempt, target manifest and reconciliation digests. |
| DBPKG-04-AC03 | Source/result mutation, identity mismatch, unsupported asset, interruption and replay cases fail closed. |
| DBPKG-04-AC04 | Actual 18,638-row fixture, exact upstream revisions/licenses, Spark/Scala runtime and local Delta bytes are independently reconstructable. |
| HC-01 | Client/workload/source/run/attempt/target plus policy/provider/output identities are bound. |
| HC-02 | Existing BASE-08/SCALE-01 upstream revision, artifact and license evidence is consumed; runtime networking is disabled. |
| HC-03 | Source and Delta summaries are independently obtained and exactly reconciled. |
| HC-04 | Protected-data-like identifiers and paths are rejected without echo; no source rows enter durable JSON evidence. |
| HC-05 | Positive, replay, interruption, mutation, cross-workload and unsupported cases remain explicit. |

Run `make dbpkg04-confidence` in the governed vertical-slice environment. Passing proves only the
licensed public fixture in a local offline runtime. It does not prove live Azure Databricks or Unity
Catalog execution, Humana asset qualification, production readiness, arbitrary SAS support,
semantic parity, promotion authority or migration completion.
