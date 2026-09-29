# Current-State Workload Topology

## Purpose

WLD-10 projects canonical discovery facts into a navigable current-state topology. It does not create a second source of truth and it does not infer missing enterprise relationships.

```text
Canonical discovery graph
        |
        +-- proposed workload boundaries
        +-- datasets and files
        +-- external dependencies
        +-- referenced-only scheduler/runtime artifacts
        +-- evidence-backed relationships
        |
        v
Current-state topology projection
        |
        +-- navigable nodes
        +-- collapsed boundary-level edges
        +-- provenance retained
        +-- unresolved relationships retained as gaps
```

## Canonical topology contract

A topology contains nodes and edges. A node references an existing canonical entity rather than copying or redefining it. Current node types are workload boundary, dataset, external dependency, and external artifact. An external artifact is currently used for referenced-only scheduler/runtime dependencies observed outside the discovered estate.

Edges are projections of existing canonical relationships. When multiple artifact-level relationships collapse to the same boundary-level edge, the topology retains the contributing relationship IDs and merges their evidence.

## Boundary projection

Artifacts assigned to a proposed `WorkloadBoundary` are represented by the boundary node in topology edges. Internal relationships inside the same boundary are not duplicated as topology edges because the topology is intended to expose system context, not reproduce the entire artifact graph.

```text
extract.sas ----+
transform.sas --+--> [Claims workload boundary] --> claims.monthly
wrapper.sh -----+             |
                              +--> Oracle connection
                              +--> referenced external scheduler job
```

The artifact-level graph remains canonical and available for drill-down.

## Truth and uncertainty

`complete_enterprise_topology` is deliberately `false` for this foundation. A filesystem discovery run cannot prove that every external producer, consumer, scheduler, report, API, or human process has been observed.

Missing endpoints are not invented. Relationships whose endpoints cannot be projected are recorded as unresolved relationship IDs in topology metadata so later providers can enrich them.

## Future enrichment

Runtime metadata, SAS metadata, enterprise schedulers, data catalogs, BI scanners, ownership inventories, and targeted human confirmation can add evidence to the canonical graph. The topology can then be regenerated without changing the downstream contract.
