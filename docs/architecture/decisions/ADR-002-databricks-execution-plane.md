# ADR-002: Databricks as Execution Plane

## Status
Accepted

## Context
Converted workloads target Databricks and require Spark-native execution and validation.

## Decision
Use Databricks for target workload execution, technical validation, performance testing, and production workload hosting.

## Consequences
The factory must expose an execution adapter rather than directly coupling orchestration to cluster implementation details.
