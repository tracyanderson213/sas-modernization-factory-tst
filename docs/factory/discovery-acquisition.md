# Discovery Acquisition and Inventory

## Purpose

Discovery acquisition is the entry point for understanding a SAS estate. SMF
does not require a customer to author a workload manifest before discovery can
begin.

The first implementation supports two acquisition paths:

1. direct read-only filesystem inventory
2. SAS 9.4 Content Assessment Inventory preview ingestion

Both normalize evidence into the Canonical Workload Model.

## Compatibility assumption

SMF currently treats SAS 9.4 as the primary enterprise compatibility target.
The model does not depend on a specific SAS 9.4 maintenance release.

The Content Assessment provider consumes documented Inventory preview CSV
output when it is available. The initial supported contract is `objects.csv`,
with optional `servers.csv`, `deployments.csv`, and `licenses.csv` captured as
assessment metadata.

This is intentionally a provider boundary. SMF does not require SAS Content
Assessment and can acquire evidence directly when assessment output is not
available.

## CLI

Automatic provider detection:

    smf discover /path/to/source

Direct filesystem acquisition:

    smf discover /path/to/sas-estate --provider filesystem

SAS Content Assessment acquisition:

    smf discover /path/to/assessment --provider sas-content-assessment

Persist the normalized discovery model:

    smf discover /path/to/source --out out/discovery.json

## Filesystem behavior

The filesystem provider recursively inventories readable files, assigns stable
artifact identities, captures SHA-256 fingerprints, classifies known artifact
types, and records filesystem evidence. SAS source artifacts are also passed
through deterministic static reference discovery so literal code, dataset, file,
and include relationships can begin populating the canonical dependency graph.

Classification is deliberately conservative. A `.sas` file is treated as a SAS
program unless its location or name provides stronger deterministic evidence
that it is a macro, include, or configuration artifact. Unknown files remain
`other`; they are not discarded.

The source is read-only. SMF does not modify customer files.

## SAS 9.4 Content Assessment behavior

When `auto` discovery finds an `objects.csv`, SMF selects the SAS Content
Assessment provider. Inventory rows become evidence-backed artifacts and retain
the original assessment row in metadata for future enrichment.

The provider captures, when present:

- `objects.csv`
- `servers.csv`
- `deployments.csv`
- `licenses.csv`

The Content Assessment provider does not yet ingest Code Dependencies output.
Filesystem discovery can independently extract a first set of deterministic SAS
source references, but true business workload boundaries still require later
code, data, scheduler, runtime, and consumer graph enrichment.

## Provisional workload boundary

WLD-02 creates a provisional workload container for the acquired source. That
does not mean a filesystem root or Content Assessment inventory equals one
business workload.

Later workload-grouping discovery will use code, data, scheduler, runtime, and
consumer relationships to propose actual workload boundaries.

## Static SAS reference discovery

See [SAS Static Reference Discovery](sas-static-reference-discovery.md) for the deterministic WLD-03 source-analysis contract and current limitations.

## Graph enrichment

After acquisition, filesystem discovery applies deterministic enrichment:

```text
Inventory -> SAS references -> endpoint characterization -> data lineage
                                            \-> scheduler/launch relationships
```

See [Discovery Pipeline Overview](discovery-overview.md), [Data Lineage Graph](data-lineage-graph.md), and [Scheduler and Runtime Dependency Discovery](scheduler-runtime-dependency-discovery.md).
