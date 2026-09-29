# Modernization Disposition Input Model

## Purpose

WLD-11 creates the canonical decision-input boundary between discovery and modernization assessment. The factory now has enough current-state evidence to describe a workload system, but that evidence must not be confused with a business or architecture decision.

```text
Discovery evidence
      |
      v
Canonical workload + boundary + topology
      |
      v
Modernization disposition input
      |
      +-- evidence context
      +-- unresolved gaps
      +-- candidate dispositions (later assessment/reasoning)
      +-- explicit governed selection (later decision)
      |
      v
Assess -> Plan -> Execute
```

## Dispositions

The canonical model supports exactly six modernization outcomes:

- `RETIRE`
- `CONSOLIDATE`
- `REPLACE`
- `RE_ENGINEER`
- `CONVERT`
- `PRESERVE`

Supporting an outcome in the model does not mean discovery automatically recommends or selects it.

## Decision semantics

Each proposed workload boundary receives a stable `ModernizationDispositionInput`. Discovery summarizes the evidence already known for that boundary, including artifact, dataset, external-dependency and output counts, consumer-resolution gaps, boundary confidence, and unresolved adjacent artifacts.

The initial decision state is always `UNRESOLVED`. Discovery does not populate a selected disposition and does not generate ranked candidates. This is intentional.

Later assessment or reasoning capabilities may add `DispositionCandidate` records with rationale, evidence, confidence, blockers and source. A governed workflow or human decision may then move the decision state to `PROPOSED` or `CONFIRMED` and explicitly select a disposition.

## Architectural boundary

Deterministic discovery answers questions such as what exists, what reads or writes data, what depends on what, what appears to form a workload, and what remains unresolved.

It cannot prove that a workload is obsolete, duplicated, strategically replaceable, or required to be preserved. Those conclusions require assessment evidence, business context, architecture constraints, and potentially human confirmation.

Therefore:

> Discovery informs modernization decisions. It does not autonomously make them.

## Current limitations

WLD-11 is the input model foundation. It does not yet implement disposition scoring, candidate ranking, business-value analysis, human approval workflow, or modernization plan generation.
