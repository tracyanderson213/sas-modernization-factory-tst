# ADR-005: Bounded Agent Autonomy

## Status
Accepted

## Context
Autonomous remediation loops can generate uncontrolled cost, inconsistent changes, and difficult-to-audit behavior.

## Decision
All agent workflows use explicit retry limits, structured inputs/outputs, escalation criteria, and tool permissions.

## Consequences
Agent orchestration must support attempt counters, terminal states, and human exception routing.
