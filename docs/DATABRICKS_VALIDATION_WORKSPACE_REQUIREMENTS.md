# Databricks Validation Workspace Requirements

Before enabling remote Execution Validation, define:

- approved workspace URL
- authentication method
- validation catalog
- validation schemas
- approved compute policy
- permitted runtime versions
- network requirements
- Unity Catalog permissions
- read-only source access
- controlled scratch/output locations
- cleanup/retention policy
- job concurrency limits
- execution timeout policy
- PHI/PII handling requirements
- logging and audit requirements

## Write policy

Execution Validation v2 defaults to no write-enabled remote execution.

Write-enabled validation should only target explicitly approved scratch
locations and should never infer permission to write to production datasets.

## Authentication

Developer PATs may be useful for isolated development, but enterprise deployment
should prefer approved workload identity / service-principal mechanisms.
