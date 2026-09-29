# SCALE-01 distributed SAS7BDAT reader qualification

SCALE-01 wraps, rather than reimplements, the Apache-licensed `spark-sas7bdat` and Parso readers.
The accepted upstream revision is built reproducibly for the repository runtime combination: Spark
3.5.8, Scala 2.12.18. The published `_2.12` 3.0.0 JAR is rejected because it contains no class
files; the published `_2.13` JAR is incompatible with the repository's Scala 2.12 PySpark runtime.

The confidence gate reads the byte-exact 2.3 MiB upstream SAS7BDAT fixture as three non-empty Spark
partitions and reconciles all 18,638 rows against the upstream CSV oracle. Only one count/null/hash
summary per partition crosses to the driver. Neither `DataFrame.collect()` nor `toPandas()` is used.
The commutative XOR plus modulo-sum SHA-256 evidence preserves duplicate multiplicity alongside the
exact row and null counts. The upstream CSV's decimal serialization and Parso's binary doubles use
the fixture-bound 12-significant-digit projection before byte-exact comparison; reconciliation then
uses zero numeric tolerance. This provisional projection is not a production semantic mapping.

Immutable evidence binds request/run/attempt, source and oracle bytes, exact upstream revisions,
source-built provider and Parso JARs, both Apache-2.0 license texts and redistribution dispositions,
the exact SBT launcher/build receipt, Spark/Scala/configuration identities, every partition summary,
schema, reconciliation, and prohibited claims. Replay re-reads all inputs and reruns the partitioned
reader. Symlinks, traversal, protected/secret-like identities, missing classes, version drift,
artifact/input mutation, partial partition coverage, reconciliation mismatch, evidence mutation,
and cross-workload collision fail closed.

Run the authoritative gate with:

```bash
./scripts/test-scale01-confidence.sh
```

The script fetches only exact build-time upstream revisions and Maven artifacts, verifies hashes,
and builds the provider in an isolated temporary directory. The runtime module itself never
downloads dependencies. Final source-only/offline bundle intake remains `PKG-QUAL-01` scope.

This proves a bounded local Spark compatibility candidate and partition-complete mechanism. It does
not prove a published JAR, live Databricks/Unity Catalog, Humana data, arbitrary SAS coverage,
semantic parity, production readiness, or migration completion.
