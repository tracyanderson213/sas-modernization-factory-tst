# Humana SAS Modernization Factory Architecture

## Design intent

The factory is designed to automate the repeatable majority of SAS
modernization while explicitly isolating workloads that require engineering,
data-science, regulatory, or business-owner review.

## Logical stages

SAS Intake
→ Inventory
→ Assessment
→ Routing
→ Conversion
→ Static Validation
→ Data Parity Validation
→ Human Review Gate
→ Databricks Packaging
→ Deployment
→ Operational Verification

## Execution model

The core SMF package remains portable Python. Infrastructure-specific concerns
belong in adapters.

The core control plane uses provider-neutral identity, secret, storage, messaging,
telemetry, and model contracts. Deployment configuration selects approved adapters;
vendor-specific services are not embedded in portable orchestration behavior.

For Humana, the confirmed ecosystem bindings are HashiCorp Vault for secrets,
Microsoft Entra ID / Active Directory for identity, and Anthropic for approved LLM
inference. Exact Vault deployment/authentication flow, scopes, Anthropic endpoint/models,
and owner approvals remain required configuration. Missing bindings fail closed and do
not prevent isolated offline contract development. Databricks remains the execution and
target data platform.

No source SAS code or Humana data should be sent to a public model endpoint by
default. Provider enablement must be policy controlled.

## Factory objective

The target is not "80 percent of code translated by an LLM." The useful
factory metric is the percentage of workloads that can move through assessment,
conversion, validation, and evidence generation without bespoke engineering
intervention.
