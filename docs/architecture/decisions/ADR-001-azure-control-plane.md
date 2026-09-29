# ADR-001: Azure as Factory Control Plane

## Status
Accepted

## Context
The migration factory requires durable orchestration, queues, identity, secrets, telemetry, APIs, AI integration, and human exception management.

## Decision
Use Azure as the reference control plane for the enterprise factory. Databricks remains the target execution plane.

## Consequences
Factory lifecycle management is independent of Databricks cluster state. Azure services can be substituted where enterprise standards require equivalent capabilities.
