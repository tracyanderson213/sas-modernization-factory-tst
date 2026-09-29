# TASK-25 certification evidence bundle acceptance

TASK-25 implements a bounded offline contract for reconstructing a complete signed
source-to-validation evidence chain. It does not certify a real migration or authorize promotion.

| Criterion | Evidence | Result |
| --- | --- | --- |
| TASK-25-AC01 | complete-chain, immutable publication and replay tests | Exact source, conversion, execution, baseline, validation, reconciliation, provenance and completion-approval references are ordered, signed, version-bound and replayable. |
| TASK-25-AC02 | policy, identity, contract-version, predecessor and expiry tests | The bundle verifies one exact client/workload/source/run/attempt and records missing or nonpassing roles without inferring success. |
| TASK-25-AC03 | omitted baseline, payload mutation, expired approval, cross-run, symlink and caller-claim tests | Missing, stale, substituted, forged or caller-authored success cannot certify. |
| HC-01 / HC-05 | strict schemas, signed records, immutable payload bytes and current-input replay | Claims remain evidence-specific; synthetic contract fixtures cannot establish real certification. |
| HC-02 / HC-03 | canonical role chain and exact payload bindings | No recall service or source reinterpretation is introduced. |
| HC-04 | safe identifiers, protected-content rejection and root-confined no-follow reads | Unsafe metadata or payloads are rejected before durable publication. |

The checked-in policy schema deliberately permits only `synthetic_contract`. Local trust roots prove
cryptographic and lifecycle mechanics, not customer authority. Therefore `certified`,
`approval_verified`, `promoted`, `production_ready` and `migration_complete` remain false, and every
result retains `external_certification_authority_required`. A later governed composition must supply
independently controlled authoritative evidence and approval without weakening this contract.

This increment performs no SAS, Databricks, Unity Catalog, Humana or AI Gateway operation. It makes
no execution, validation, reconciliation, parity, readiness, certification, promotion or migration
completion claim about a real workload.
