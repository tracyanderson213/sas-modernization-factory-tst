# CORPUS-07 Public-First Representative Portfolio

CORPUS-07 admits independently authored public SAS into the SMF regression corpus without
rewriting upstream code to make discovery succeed. Public source is pinned to an immutable
revision, acquired byte-for-byte, fingerprinted locally, and classified by capability.

## Initial portfolio

| Source | Role |
| --- | --- |
| SAS/ACCESS samples | Connectivity, LIBNAME, external database and bulk-load patterns |
| SAS Code Examples | SAS-maintained language and procedure breadth |
| SASjs Core | Production-quality macro dependency and SAS 9 metadata patterns |
| CDISC CORE SAS | Multi-artifact SAS 9.4 application with includes, environment dependencies, Python integration and clinical validation |

The portfolio intentionally combines multiple independent sources. No repository is treated as
representative of an enterprise SAS estate by itself.

## Acquisition contract

`scripts/corpus/acquire-public-portfolio.py` downloads only explicitly selected files from pinned
40-character commit SHAs. The acquired bytes are written directly to `tests/corpus/workloads/public`
and SHA-256 fingerprints are written into the corresponding manifests.

The acquisition process does not format, normalize, patch, trim comments, rewrite paths, or make
other source edits. A workload that SMF cannot fully understand remains valid corpus evidence.

## Important correction to the original Gate C samples

The original SAS/ACCESS manifests described their files as curated and allowed explanatory
comments or spacing to be reduced. That policy is incompatible with the public-first architecture.
CORPUS-07 reacquires both SAS/ACCESS files from their already-pinned upstream revisions and marks
them `untouched-public`. Their new fingerprints therefore describe the actual upstream bytes.

## What CORPUS-07 proves

CORPUS-07 proves that SMF has a reproducible, independently authored realism portfolio and can run
its existing discovery machinery against those bytes. It does not claim semantic equivalence,
trusted SAS execution, Databricks execution, or certification. Unsupported and unresolved behavior
is retained as evidence for later regression promotion and coverage reporting.
