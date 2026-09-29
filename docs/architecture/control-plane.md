# Azure Control Plane

## Responsibilities

The Azure control plane coordinates the migration lifecycle without becoming the target runtime for converted workloads.

Expected capabilities include:

- REST/API entry points
- workload state management
- asynchronous queues
- orchestration
- agent invocation
- secrets management
- enterprise identity
- policy enforcement
- telemetry
- exception routing
- CI/CD integration

## Candidate Azure Services

Initial candidates:

- Azure Container Apps for APIs and workers
- Azure Service Bus for work queues
- Azure Database for PostgreSQL or Azure SQL for factory state
- ADLS Gen2 for factory artifacts
- a policy-selected LLM adapter for approved model inference
- a policy-selected enterprise secret provider for credential references
- Microsoft Entra ID / managed identity
- Application Insights and Log Analytics
- Azure DevOps or approved GitHub pipelines for CI/CD

These are reference choices, not hard-coded dependencies.

## Why the Control Plane Is Separate

The migration lifecycle should not depend on a Databricks cluster remaining active. Control-plane separation enables independent scaling, durable orchestration, centralized policy, and easier integration with enterprise systems.
