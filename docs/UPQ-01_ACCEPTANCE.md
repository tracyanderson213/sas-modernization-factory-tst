# UPQ-01 Acceptance Evidence

## Scope and completion truth

This implementation supplies the bounded offline qualification contract. It does not attest actual
external upstream qualification or authorize implementation use, deployment, merge, issue closure,
or Project lifecycle changes. Synthetic fixtures cannot satisfy AC04.

## Criterion mapping

| Criterion | Concrete implementation and test evidence | Current disposition |
|---|---|---|
| UPQ-01-AC01 | `competition/upstream/approved-inventory.json`; `test_approved_inventory_covers_recovery_report_set`; strict exact-inventory reconciliation | Contract implemented for all 24 recovered upstreams |
| UPQ-01-AC02 / HC-01 | Five separated trust domains, deterministic acquisition/supporting-evidence/receipt/result IDs, exact byte digests, policy/inventory/scope/run/attempt/evaluation-time bindings, signed append-only result, replay verifier | Synthetic contract proven; actual evidence absent |
| UPQ-01-AC03 / HC-05 | Unknown enum/field, optional attestation, disposition broadening, skipped/mock, missing receipt/runtime artifact, untrusted signature, stale/future activity, boundary escape, mutation, duplicate/empty inventory, and denial/pending tests | Fail-closed contract proven |
| UPQ-01-AC04 | Runbook defines actual-source receipt and review requirements | **BLOCKED:** SEC-03 canonical completion and attributable real upstream reacquisition/review are not supplied |
| HC-02 | Projection retains revision, disposition, permitted use, receipt and policy/inventory digests; changed evidence invalidates load | Implemented; downstream workload binding remains consumer-owned |
| HC-03 | All downstream lifecycle claims are schema-fixed false; generated/mock/skipped evidence cannot qualify | Implemented |
| HC-04 | Protected-data rejection, safe identifiers, relative-root confinement, repeated-decoding/traversal and symlink rejection, trusted signatures | Implemented for the offline contract; live client boundary not exercised |

## Durable-pattern self-review

| Pattern | Evidence |
|---|---|
| FAIL_OPEN_OPTIONAL_ATTESTATION | Closed schemas reject `license_approved` and other caller fields; all mandatory trust classes are signed |
| UNBOUND_EVIDENCE | Receipt and result bind origin/revision/bytes, inventory/policy, scope/run/attempt/evaluation time, authority and decision IDs; SEC-03 binds the policy-pinned acceptance digest and reconstructable current decision |
| MALFORMED_ENUM_BYPASS | Closed enums and unknown-field tests fail before evaluation |
| EMPTY_OR_NONCONVERTIBLE_SUCCESS | Empty inventory and zero-byte artifact rejection; inventory must include at least one non-restricted eligible subject |
| TOCTOU_MUTABLE_INPUT | Publication and load rehash every referenced file; mutation test fails |
| ASSERTION_NOT_EVIDENCE | Capability and compatibility claims require separately signed immutable execution, environment, output, negative-case and compatibility records; receipt assertions and file digests are reconciled |
| DENIAL_VS_PENDING | Parameterized prerequisite tests preserve pending, denied and failed outcomes |
| DUPLICATE_IDENTITY | Exact/case-folded upstream and origin/revision duplicates are rejected |
| SKIPPED_AS_SUCCESS | Skipped, not-executed, mocked and generated-only capability evidence removes permitted use and cannot qualify |
| BOUNDARY_ESCAPE | Absolute/traversal/repeated-percent/symlink/cross-root references fail |
| IDEMPOTENT_PERSISTENCE_RECOVERY | Canonical-first append-only write and missing derivative reconstruction test; conflicting bytes fail |

## Required verification commands

```bash
python -m pytest -q tests/unit/test_upstream_qualification.py \
  tests/integration/test_upstream_schema_packaging.py
python -m pytest -q
python -m ruff check .
python -m mypy src
python -m pip_audit
git diff --check
```

Local verification on 2026-09-18:

- focused upstream unit/schema/CLI suite: `36 passed`;
- full repository suite: `1,757 passed`;
- Ruff: passed;
- strict mypy: passed for all 200 source files;
- `git diff --check`: passed;
- `pip-audit`: **blocked** because the restricted environment could not resolve `pypi.org`; no
  vulnerability-success claim is made.

Unavailable tools or external evidence stay blocked rather than waived.

## Actual-source launch check

Before claiming AC04 or completion, an independent Reviewer must reproduce qualification using all
24 exact revisions and immutable artifacts, real license evidence, actual capability/limitation and
compatibility commands, expected/actual outputs, negative results, the canonical SEC-03 completion
record, and immutable review references. Any missing/changed license, upstream, vulnerability,
platform compatibility, Humana intake decision, or rejected review stops the claim.
