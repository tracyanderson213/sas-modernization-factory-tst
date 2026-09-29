# Security Policy

## Security Position

The SAS Modernization Factory is designed to operate inside an enterprise-controlled boundary.

Source code, workload metadata, data samples, generated artifacts, prompts, model responses, validation evidence, credentials, and deployment configuration must be handled according to the hosting organization's security requirements.

## Current Enforcement Boundary

Security requirements in this document describe the required production posture. Not every control is enforced by the current local engineering foundation.

Currently present controls include:

- repository guidance prohibiting client production data and committed secrets
- CI dependency auditing
- explicit Databricks write blocking in the current execution-provider boundary
- feature-gating of real remote Databricks execution
- non-operational AI provider scaffolds rather than silently enabled public model calls
- validation/review gates that prevent generated code from being treated as automatically accepted solely because conversion completed

Still-required production controls include runtime enforcement of approved AI endpoints and protected-data policy, enterprise identity/secrets integration, private networking where required, centralized audit telemetry, durable authorization/state controls, and auditable certification/promotion approval.

## Required Production Controls

- Use enterprise identity and least-privilege authorization.
- Store secrets in an approved secrets manager such as Azure Key Vault.
- Do not commit credentials, tokens, connection strings, certificates, `.env` files, Terraform state, or Databricks credentials.
- Prefer private networking for enterprise deployments.
- Use only approved enterprise AI endpoints.
- Do not send protected or production data to unapproved/public AI services.
- Enforce protected-data policy before prompt submission.
- Log model invocation metadata and provenance without unnecessarily logging sensitive payloads.
- Require auditable approval before production promotion.
- Scan dependencies, containers, infrastructure code, and source code before release.
- Treat third-party conversion libraries as untrusted dependencies until reviewed.
- Restrict validation execution to approved compute, catalogs, schemas, and write boundaries.
- Preserve evidence sufficient to reconstruct conversion, validation, review, and promotion decisions.

## AI Provider Safety

AI provider interfaces or dependencies in the repository must not be interpreted as authorization to send SAS source, client metadata, PHI, PII, or production data to those services.

AI execution remains disabled until the deployment has approved endpoint routing, credentials, data classification/redaction behavior, logging policy, prompt/model governance, and validation/escalation controls.

## Databricks Execution Safety

The current Databricks provider establishes a contract/configuration boundary and intentionally blocks writes. Real remote execution must remain feature-gated until the enterprise validation workspace and its authentication, compute, Unity Catalog, schema, and write policies are approved.

## Client Data

No client production data should be added to this repository.

Client-specific examples belong in approved private storage or ignored paths such as:

- `tests/workloads/private/`
- `examples/private/`
- `deployments/*/private/`

Synthetic or appropriately de-identified examples should be used for regression testing whenever possible.

## Reporting

Security issues should be reported through the organization's approved private security channel and should not be disclosed in public issues.
