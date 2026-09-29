# Target-State Pattern Recommendation Inputs

## Purpose

WLD-12 defines the canonical evidence contract that later target-state recommendation logic consumes. It bridges current-state understanding and governed modernization disposition into target-pattern reasoning without selecting a Databricks service or architecture pattern.

## Architectural boundary

```text
Canonical discovery facts
        |
Current-state topology
        |
Modernization disposition input
        |
        v
Target-state pattern recommendation input   <- WLD-12
        |
        v
Future recommendation / assessment logic
        |
        v
Governed target-state pattern
```

WLD-12 is an input model, not a recommendation engine. `target_pattern_selected` is therefore false for discovery-derived inputs.

## Normalized evidence

Each workload boundary receives a stable `TargetStatePatternInput` carrying:

- execution behavior observed from canonical artifacts;
- data behavior observed from canonical relationships and datasets;
- dataset, output, and external-dependency identities;
- relationship kinds relevant to the boundary;
- the linked WLD-11 disposition input and any explicitly governed disposition;
- unresolved consumer, boundary, and adjacent-artifact evidence;
- evidence and boundary confidence.

Unknown execution behavior remains `unknown`. Partial downstream-consumer knowledge remains unresolved. Discovery does not infer a target platform merely because a SAS construct or relationship exists.

## Separation of responsibilities

WLD-12 answers: **What normalized facts should a target-pattern recommender receive?**

It does not answer:

- Which Databricks component should implement the workload?
- Whether batch should become streaming?
- Whether an intermediate dataset should be eliminated?
- Whether two workloads should consolidate?
- Whether a recommendation is approved.

Those are later assessment, modernization, and governance responsibilities.
