# Data Lineage Graph

WLD-05 derives evidence-backed data lineage from canonical discovery facts. It is a deterministic graph-enrichment step, not an AI inference step.

## Inputs

WLD-05 consumes the canonical `READS` and `WRITES` relationships produced by discovery. WLD-03 identifies literal SAS references and WLD-04 characterizes the referenced data endpoints.

## Derived edges

For a dataset with a known writer and reader, SMF adds:

- `artifact -> PRODUCES -> dataset`
- `dataset -> CONSUMED_BY -> artifact`
- `producer artifact -> PRECEDES -> consumer artifact`
- `consumer artifact -> DEPENDS_ON -> producer artifact`

Artifact-to-artifact lineage records every dataset used to derive an edge in sorted
`via_dataset_ids` and `via_dataset_names` metadata. The legacy singular keys remain when exactly
one dataset contributes. Evidence and source relationship IDs from every write/read observation
are retained. When a dataset has multiple observed writers, every candidate edge remains visible
with `producer_resolution: multiple`; this is analysis evidence, not a proven runtime order.

## Conservative behavior

SMF does not create an artifact dependency merely because two names look similar. The producer and consumer must resolve to the same canonical dataset identity. Dynamic macro-generated references, unresolved runtime substitutions, scheduler ordering, and cross-workload identity reconciliation remain explicit gaps until additional evidence is available.

This is intentionally different from claiming full enterprise lineage. WLD-05 establishes the deterministic lineage foundation that later discovery providers can enrich with runtime, scheduler, data-system, and human-confirmed evidence.
