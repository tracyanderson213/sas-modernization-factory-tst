# Retire Candidate Detection and Rules

## Purpose

MOD-02 is the first deterministic modernization-assessment capability built on the WLD-11 disposition contract. It produces an evidence-backed `RETIRE` candidate for each assessed workload boundary while deliberately leaving the governed disposition unresolved.

```text
Canonical discovery evidence
        |
        v
WLD-11 disposition input
        |
        v
MOD-02 deterministic RETIRE assessment
        |
        +-- supporting rule IDs
        +-- counter-evidence rule IDs
        +-- unresolved blockers
        +-- confidence
        +-- requires confirmation = true
        |
        v
Governed modernization decision (future)
```

## Safety semantics

A retire candidate is a hypothesis, not a retirement instruction. MOD-02 never sets `selected_disposition`, never changes the decision state to confirmed, and never interprets missing observations as proof of non-use.

In particular, "no observed downstream consumer" is weak evidence when consumer coverage is unresolved or partial. Those conditions remain explicit blockers and cap candidate confidence. A high-confidence candidate requires confirmed downstream-consumer coverage with no observed consumers and no other modeled blocker. Even then, confirmation is still required.

## Deterministic evidence

The initial rule set records supporting evidence, counter-evidence and blockers separately. It considers downstream consumer resolution, observed consumers, scheduler/runtime launch evidence, cross-boundary dependency evidence, unresolved adjacent artifacts, unresolved connections and workload-boundary confirmation state.

Rule identifiers are serialized on the candidate so later assessment, UI and audit capabilities can explain why the candidate exists and what evidence argues against it.

## Architectural boundary

MOD-02 uses `DispositionCandidate` and `ModernizationDispositionInput` from WLD-11. It does not create a parallel decision model. It is also not invoked by filesystem discovery because candidate generation is an assessment concern rather than a discovery fact.

Business ownership, regulatory retention, strategic replacement, contractual obligations, authoritative runtime usage and enterprise-wide consumer evidence are not yet complete. Those gaps must be enriched before a governed retirement decision can be confirmed.
