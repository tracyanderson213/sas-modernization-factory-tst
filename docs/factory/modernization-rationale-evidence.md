# Modernization rationale and evidence

MOD-10 provides an auditable rationale-and-evidence record for each canonical workload boundary. It packages the governed disposition state and references the evidence already produced by discovery and modernization assessment. It does not create a new decision engine.

## Governing boundary

Candidate rationale is not decision rationale. A RETIRE, CONSOLIDATE, CONVERT, RE_ENGINEER, REPLACE, or PRESERVE candidate may explain why that path deserves consideration, but MOD-10 does not promote that explanation into a governed decision. If a disposition is confirmed without an explicit decision rationale, the rationale record preserves that as an unresolved gap.

Each `ModernizationRationaleEvidence` record carries the disposition input ID, selected disposition and decision status, verbatim governed decision rationale when present, candidate IDs, evidence IDs, related modernization record IDs, blockers, and unresolved items. Stable IDs make the record portable and traceable.

Related records can include logic-similarity findings, batch-to-incremental opportunities, intermediate-artifact elimination opportunities, Databricks pattern mappings, migration-wave groups, and the target-state manifest. These references are audit context. Their existence does not prove that a decision is correct.

## Manifest integration

When a MOD-09 target-state manifest exists, MOD-10 links each boundary plan to its rationale record by stable ID. It does not rewrite the selected disposition, choose a Databricks pattern, assign a calendar wave, or manufacture prose.

## Explicit non-goals

MOD-10 does not autonomously confirm dispositions, infer business approval, claim semantic equivalence, suppress blockers, or convert candidate evidence into decision evidence. Human or governed workflow confirmation remains authoritative.
