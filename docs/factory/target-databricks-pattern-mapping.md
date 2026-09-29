# Target Databricks pattern mapping

MOD-05 maps canonical target-state evidence to **logical Databricks pattern candidates**. It is a recommendation-input layer, not a deployment generator and not proof that a workload can safely use a target pattern.

## Logical patterns

- `WORKFLOW_JOB`: scheduled execution may map to a governed Databricks workflow/job pattern.
- `BATCH_SPARK`: observed read/write transformation behavior may map to a Spark batch transformation pattern.
- `INCREMENTAL_PIPELINE`: a MOD-06 batch-to-incremental opportunity may map to an incremental pipeline candidate, while inheriting change-capture and incremental-semantics blockers.
- `DELTA_TABLE`: persisted data outputs may map to Delta-backed target storage.

These are stable logical patterns. They intentionally avoid choosing cluster/serverless sizing, catalog/schema names, pipeline configuration, scheduling policy, performance settings, or deployment topology.

## Governance boundary

Mappings retain unresolved target-state items and disposition status. RETIRE, REPLACE, and PRESERVE dispositions block a Databricks implementation mapping. Unconfirmed disposition is also a blocker. No mapping proves semantic equivalence or target feasibility, and no pattern is automatically selected.

## Relationship to prior capabilities

WLD-12 supplies normalized target-state inputs. MOD-04 supplies governed disposition context. MOD-06 supplies incremental-opportunity evidence. MOD-05 consumes those contracts without replacing them.
