# Humana 2026 Competition Execution Direction

## Purpose

This document preserves the durable deployment-specific execution direction established during the September 2026 Humana competition replan. Detailed work-item state, acceptance criteria, and issue bodies live in GitHub and must not be duplicated here as a second source of truth.

## Objective

Maximize reproducible SAS-to-Databricks workloads that execute against real Humana data and pass parity. Generated code alone is not success.

## Execution horizons

- **P0:** competition blocker
- **P1:** winning capability
- **P2:** scale and hardening
- **P3:** long-term factory capability outside the immediate competition critical path

## Critical loop

```text
Discover
  -> Ready
  -> Analyze
  -> Convert
  -> Execute
  -> Validate
  -> Diagnose
  -> Repair
  -> Re-execute
  -> Prove parity
  -> Persist evidence
  -> Learn
```

## Architecture invariants

- Keep bounded task/workload-specific LLM context separate from durable estate-wide intelligence.
- Persist manifests, dependencies, lineage, source/target bindings, transformation/business-rule signatures, reusable patterns, decisions, validation history, failure/repair history, duplicates, complexity, and evidence.
- Preserve secret sanitization, protected paths, isolated worktrees, Architect/Developer/Reviewer gates, bounded repair, and human-controlled final integration.
- Do not create a Humana-only fork of reusable product capabilities.

## Competition capabilities introduced by the replan

The approved replan introduced these backlog capabilities:

- `COMP-01` Humana Competition Execution
- `READY-01` Workload Readiness Qualification Engine
- `VAL-01` Deterministic Cell-Level Parity Engine
- `FAIL-01` Machine-Actionable Factory Failure Taxonomy
- `LOOP-01` Autonomous Convert-Execute-Validate-Repair Controller
- `BENCH-01` Repeatable Competition Benchmark Harness
- `SCORE-01` Competition Scoreboard Event Model
- `LEARN-01` Estate Pattern Learning and Reuse Feedback Loop

The GitHub Project and issues are authoritative for their current status and detailed specifications.

## Approved sequencing

1. Establish the thinnest executable end-to-end loop.
2. Advance readiness qualification, end-to-end orchestration, and Databricks execution in parallel.
3. Add row-count, aggregate, distribution, sample, and deterministic cell-level parity.
4. Add machine-actionable failure classification, bounded remediation, and re-execution.
5. Add concurrency, repeatable benchmarking, and competition scoreboard telemetry.
6. Continue macro/discovery coverage in parallel where it affects real workload throughput.
7. Feed solved patterns and prior evidence into durable estate intelligence.

## Primary measures

Measure migration success using validated evidence, including:

- validated-parity workloads per hour/day by complexity;
- straight-through parity;
- eventual automated parity;
- first-pass parity;
- human intervention rate;
- repair attempts;
- p50/p95 elapsed time;
- stage backlogs;
- failure category and blocker owner;
- model/token/compute use where applicable;
- estimated cost per validated workload.

Do not count generated-only, skipped, blocked, or unvalidated work as migration success.
