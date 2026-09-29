# Complexity Model

## Purpose

Complexity is a routing signal, not a guaranteed estimate of migration effort.

## Initial Tiers

### Simple
Typical signals:
- basic PROC SQL
- simple joins, filters, grouping
- straightforward DATA steps
- limited dependencies
- no advanced statistical procedures

### Moderate
Typical signals:
- macros
- multiple related programs
- more complicated DATA steps
- formats
- procedural transformation logic
- moderate dependency chains

### Complex
Typical signals:
- advanced macro behavior
- dynamic code generation
- statistical procedures
- external integrations
- significant dependency chains

### Highly Complex
Typical signals:
- predictive models
- advanced statistics
- bespoke SAS behavior
- poorly documented dependencies
- business-critical or regulatory calculations
- semantic equivalence requirements

## Scoring

Initial scoring should be explainable and rule-based. Over time, telemetry can be used to calibrate complexity against observed remediation effort and validation failure rates.
