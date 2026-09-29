# Workload Grouping and Boundary Detection

## Purpose

WLD-09 proposes workload-system boundaries from the canonical discovery graph.
The goal is not to treat a folder as a workload. The goal is to group artifacts
that are connected by observable execution, code, and data-dependency evidence
while preserving uncertainty and the reason for every grouping decision.

## Boundary derivation

The deterministic foundation builds an undirected connectivity view across
eligible discovered artifacts using artifact-to-artifact relationships:

```text
SAS program -------- INCLUDES --------> macro/include
     |
     +------------- PRECEDES ----------> SAS program
     |
Shell wrapper ------- TRIGGERS --------> SAS program
     |
Scheduler job ------- TRIGGERS --------> shell wrapper
     |
Consumer ------------ DEPENDS_ON ------> producer

                    graph connectivity
                           |
                           v
                WorkloadBoundary proposal
```

`READS`, `WRITES`, `PRODUCES`, and `CONSUMED_BY` relationships contribute
supporting dataset/output context. WLD-05 already derives artifact-to-artifact
`PRECEDES` and `DEPENDS_ON` edges when deterministic data lineage proves that
one artifact consumes another artifact's output, so WLD-09 does not duplicate
lineage logic.

## Explainability

Every boundary proposal carries:

- stable boundary identity;
- member artifact IDs;
- associated dataset IDs;
- associated external-dependency IDs;
- associated output IDs;
- merged discovery evidence;
- confidence;
- counts of the relationship kinds that connected the artifacts;
- unresolved adjacent referenced-only artifacts; and
- an explicit `requires_confirmation` marker.

The proposal can therefore answer both **what was grouped** and **why it was
grouped**.

## Deliberate limits

A connected component is a proposed technical boundary, not automatically a
confirmed business workload. The foundation intentionally does not infer
business ownership, business purpose, regulatory classification, or a final
customer-facing workload name.

Artifacts with `definition_status=referenced_only` are not absorbed into a
boundary. They remain unresolved adjacent evidence so an external scheduler
reference cannot silently merge two workloads.

Generic `OTHER` files such as README files are also excluded from boundary
membership unless future evidence promotes them into a meaningful modeled
artifact type.

Singleton executable artifacts remain valid boundary proposals. A lack of
observed relationships is not proof that the artifact is independent; it is a
candidate requiring additional evidence or confirmation.

## Confidence and confirmation

Multi-artifact components with deterministic evidence are high-confidence
technical grouping proposals. Singleton or weakly evidenced candidates receive
lower confidence. All WLD-09 boundaries still require confirmation because the
current providers do not prove the complete enterprise dependency graph.

Future runtime metadata, enterprise schedulers, catalogs, repositories,
ownership data, and targeted human confirmation can enrich or split/merge these
proposals without changing the canonical contract.
