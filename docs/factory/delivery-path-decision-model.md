# Canonical Delivery-Path Decision Model

MOD-04 provides deterministic assessment inputs for the remaining canonical modernization paths after RETIRE and CONSOLIDATE analysis.

The canonical disposition taxonomy remains:

`RETIRE | CONSOLIDATE | REPLACE | RE_ENGINEER | CONVERT | PRESERVE`

`refactor` is deliberately **not** a seventh disposition. A bounded translation that retains the workload's essential implementation shape is `CONVERT`. A redesign of implementation, orchestration, data movement, or operational behavior is `RE_ENGINEER`. This avoids a parallel vocabulary that would make later planning and reporting ambiguous.

## Candidate semantics

The model adds candidates, never decisions:

- **CONVERT** when executable SAS source exists. Presence of source establishes translation applicability, not semantic parity or suitability for automatic conversion.
- **RE_ENGINEER** when structural evidence indicates orchestration, dynamic data references, or external dependencies that may warrant redesign. These are weak redesign signals, not proof that redesign is required.
- **REPLACE** only when governed evidence supplies an explicit replacement target. The factory does not infer a commercial product or replacement platform from discovery evidence.
- **PRESERVE** only when governed evidence supplies an explicit preservation constraint.

RETIRE candidates remain the responsibility of MOD-02. CONSOLIDATE candidates remain the responsibility of MOD-03, with MOD-08 supplying duplicate/redundant-logic evidence. MOD-04 preserves those candidates when it runs.

## Governance boundary

Every MOD-04 candidate remains unselected and requires confirmation. Unknown consumer coverage, unresolved adjacent artifacts, and unconfirmed workload boundaries are retained as blockers. The model does not choose a disposition, claim semantic equivalence, recommend a target-state architecture, or execute modernization.
