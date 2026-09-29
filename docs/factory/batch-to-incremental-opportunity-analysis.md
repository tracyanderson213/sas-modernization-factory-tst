# Batch-to-Incremental Opportunity Analysis

MOD-06 identifies workload boundaries whose observed batch execution and data behavior make them reasonable candidates for incremental-design assessment.

## What the analysis proves

The implemented foundation can identify a boundary that has deterministic scheduler evidence plus observed data reads, writes, or produced outputs. It records the signals, blockers, confidence, and provenance as a canonical `BatchIncrementalOpportunity`.

## What the analysis does not prove

An opportunity is not a target architecture recommendation. It does not prove that CDC, timestamps, watermarks, keys, idempotency, late-arriving-data handling, or incremental business semantics exist. It does not select streaming, Structured Streaming, Delta Live Tables/Lakeflow, or any other Databricks implementation pattern.

Every candidate therefore retains explicit blockers for change-capture availability and incremental semantic safety until later evidence resolves them.

## Deterministic signals

Current foundation signals include scheduler presence, cron/fixed-time/calendar schedule metadata, and observed read/write/output behavior. Stronger combinations increase candidate confidence only to `MEDIUM`; they never establish incremental feasibility.

## Governance boundary

The result is assessment evidence. Final modernization disposition, target-state pattern, and implementation design remain governed decisions.
