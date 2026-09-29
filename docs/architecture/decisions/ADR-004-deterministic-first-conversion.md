# ADR-004: Deterministic-First Conversion

## Status
Accepted

## Context
LLM-only conversion is difficult to reproduce, validate, and govern.

## Decision
Apply deterministic transformation rules before AI-assisted reasoning.

## Consequences
The factory requires a transformation registry, rule versioning, regression tests, and explicit unsupported-pattern handling.
