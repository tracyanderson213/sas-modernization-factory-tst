# Databricks Execution Plane

## Responsibilities

Databricks is the target execution and validation environment for migrated workloads.

Expected capabilities include:

- Spark SQL
- PySpark
- Delta Lake
- Unity Catalog
- Databricks Workflows
- target artifact execution
- validation execution
- performance measurement
- promotion into target environments

## Execution Isolation

Factory orchestration should submit or trigger work in Databricks rather than embedding factory control logic inside long-running clusters.

## Validation

Databricks execution evidence should feed the factory validation model, including:

- compile status
- runtime status
- output schemas
- row counts
- aggregates
- checksums
- semantic validation outputs
- runtime and resource characteristics
