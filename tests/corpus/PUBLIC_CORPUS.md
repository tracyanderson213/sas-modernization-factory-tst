# Public corpus tranche 1

CORPUS-02 introduces the first public SAS fixtures into the modernization test
corpus. The initial tranche is intentionally small. Its purpose is to prove
that SMF can carry real public-source SAS through the same provenance,
fingerprint, discovery, and regression machinery as SMF-owned fixtures.

## Included fixtures

- SAS/ACCESS ODBC `bulkload.sas`
- SAS/ACCESS PostgreSQL `bulkload.sas`

Both fixtures originate from the public `sascommunities/sas-access-samples`
repository, which is licensed under Apache 2.0. Each manifest records the
upstream file URL, upstream Git blob SHA, local SHA-256 fingerprint, source ID,
license, and the SAS capabilities the fixture is intended to exercise.

For scenarios classified as untouched public evidence, the local source must match the selected upstream artifact and must not be edited, simplified, or repaired to make SMF pass. The upstream immutable reference preserves source identity and the local SHA-256 detects corpus drift. Any modified public artifact is classified as an SMF-derived fixture and cannot carry untouched-public evidentiary status.

## Why start with SAS/ACCESS

Connectivity is a major modernization concern. Enterprise SAS workloads often
encode assumptions about LIBNAME engines, macro-supplied connection options,
WORK intermediates, database writes, and DBMS-specific loading behavior. Those
patterns are directly relevant to discovery and later target-state planning for
Azure Databricks.

## Public-first portfolio

The corpus will deliberately use multiple independent sources rather than a single blessed repository. Registered candidates include SAS-maintained examples for language breadth, SAS/ACCESS for connectivity patterns, SASjs Core for macro-heavy production code, and CDISC CORE SAS for a multi-artifact SAS 9 application. Registration does not authorize vendoring: each selected tranche still requires license/terms verification, an immutable upstream reference, and a recorded acquisition decision.

Healthcare-shaped public data remains useful, including CMS synthetic public-use assets after the applicable terms are recorded. It complements rather than replaces independently authored SAS workloads.
