# Humana Environment Discovery Checklist

## Scope and current status

HENV-01 implements an offline, fail-closed prerequisite contract. The canonical checklist is the
`prerequisite_checklist` section of each readiness manifest; this document is not an alternate
state store. Repository policy defines required owner roles and client-input references, but does
not claim that a person is assigned, access is granted, a Humana endpoint is reachable, or a real
workload has executed. All real-environment entries are unverified until current governed evidence
is supplied.

The Humana deployment policy requires 14 checks covering SAS baseline access and acquisition,
Databricks workspace/catalog/scratch/output bindings, data read/write scope, network, identity,
runtime, quotas, validation permissions, cleanup/retention, and logging/audit access. A check result
must bind the exact client, deployment, environment, configuration snapshot, workload, run,
attempt, prerequisite, owner assignment, result artifact, validity interval, and governed authority.
The result artifact must be canonical JSON under the evidence bundle's `results/` directory; its
exact bytes, digest, and identity bindings are verified and preserved in the readiness manifest.
The Humana deployment binding also derives the configuration snapshot digest from the active
Databricks, security, and validation files, so mutation blocks admission before provider execution.

## Acceptance evidence matrix

The evidence references below become immutable only after the human-controlled final commit. Test
results report this working-tree execution; they are not Humana runtime evidence.

| Criterion | Test or review artifact | Procedure | Expected and actual result | Safe evidence reference |
|---|---|---|---|---|
| HENV-01-AC01 | Policy inventory and positive/negative checklist tests | `pytest tests/unit/test_readiness_engine.py -q` | Expected complete owned checklist and fail-closed absence; passed locally | `deployments/humana/readiness-policy.yaml`; `test_prerequisite_checklist_requires_reconstructable_bound_evidence` |
| HENV-01-AC02 | Domain inventory; denial/pending/expiry/conflict test | Same focused pytest command | Expected required domains and distinct states; passed locally | `test_prerequisite_denial_pending_expiry_and_conflict_are_distinct` |
| HENV-01-AC03 | Locator/digest/identity, self-assertion and replay tests; conversion guard suite | `pytest tests/unit/test_readiness_engine.py tests/unit/test_readiness_conversion_guard.py -q` | Expected unsafe, missing, expired, mutated, or replayed evidence not ready and provider not called; passed locally | `test_prerequisite_locator_must_resolve_within_authorized_root`; `test_prerequisite_result_must_exist_match_digest_and_identity`; `test_prerequisite_evidence_cannot_be_replayed_across_run_identity` |
| HENV-01-AC04 | Manifest replay/recovery and workload-isolation suite | Same focused pytest command | Expected canonical retry recovery and isolated workload paths; passed locally for offline state; real cancellation and Humana integration remain unverified | `test_manifests_are_append_only_and_workload_isolated`; readiness conversion guard tests |
| HC-01 | Strict schemas, signed references, result-byte and configuration-snapshot binding, deterministic replay | Focused pytest plus schema packaging test | Expected exact identity/version bindings, configuration drift rejection, and replay; passed locally | `schemas/readiness-*.schema.json`; `test_humana_deployment_rejects_mutated_bound_configuration`; replay tests |
| HC-02 | Code review of readiness imports and policy | `rg -n "recall\|memory" src/smf/readiness` | Expected no recall dependency; reviewed locally | `src/smf/readiness/` |
| HC-03 | Existing source, macro, boundary, mapping and baseline tests | Focused readiness and conversion-guard pytest | Expected source-faithful admission and no generated oracle; passed locally | existing readiness and conversion-guard regression tests |
| HC-04 | Attestation, sanitization, boundary and secret-canary tests | Focused pytest and `make verify` | Expected forged authority rejected and canaries absent from persistence; focused tests passed; full gate recorded in delivery handoff | secret sanitization and boundary regression tests |
| HC-05 | Positive, negative, enum mutation, persistence and telemetry tests | Focused pytest and `make verify` | Expected false claims fail and lifecycle flags remain distinct; focused tests passed; full gate recorded in delivery handoff | `test_prerequisite_policy_rejects_duplicate_identity_and_unknown_domain`; readiness telemetry tests |

## Runtime launch blockers

- Actual Humana people/identities for each owner role are not repository facts.
- HC-REQ-01, HC-REQ-02, HC-REQ-04, HC-REQ-05, and HC-REQ-07 remain required client inputs.
- Current workspace, catalog/schema, data, network, identity, quota, validation, retention, and
  audit grants require governed result artifacts; remembered prior access is not accepted.
- Real workload source/target snapshots, policy-approved validation tolerances, cancellation proof,
  and two-workload Humana integration evidence remain unverified.
- Generated-only, submitted, skipped, blocked, unexecuted, or unvalidated outcomes cannot produce
  execution, validation, parity, or certification success.
