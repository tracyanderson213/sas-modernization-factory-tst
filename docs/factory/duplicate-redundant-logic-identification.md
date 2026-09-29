# Duplicate and Redundant Logic Identification

MOD-08 adds deterministic, evidence-backed cross-workload logic-similarity findings. It is an assessment foundation, not semantic equivalence proof.

## Signals

- **Exact source match:** two SAS artifacts in different workload boundaries have the same source checksum. This is high-confidence evidence of duplicated source content.
- **Structural SAS signature match:** two SAS artifacts expose the same non-empty deterministic static signature (libraries, BY variables, macro definitions/invocations/variables, and dynamic dataset-reference signals). This is low-confidence similarity evidence only.

## Guardrails

A match never establishes business-rule equivalence, never merges workload boundaries, and never selects a modernization disposition. Same-boundary artifacts are excluded from estate-level duplicate findings. Empty signatures are not treated as similarity. Non-SAS artifacts are outside this foundation.

MOD-03 structural consolidation affinity and MOD-08 logic similarity are intentionally separate. Shared data/dependencies can make workloads worth comparing; MOD-08 can add code-level evidence, but governed analysis is still required before consolidation or retirement.

## Future enrichment

Normalized transformation ASTs, SQL/data-step semantic fingerprints, macro-expanded behavior, runtime observations, and business-rule signatures can strengthen this contract later. Those capabilities are not claimed by the current implementation.
