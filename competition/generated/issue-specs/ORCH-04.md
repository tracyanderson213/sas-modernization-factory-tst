# ORCH-04 - Stable workload identity and run lineage

## Business purpose

Support source-faithful, independently validated SAS modernization for the Humana competition and the reusable factory. Generated code alone is not success.

## Competition priority

Competition horizon: **P0**. Disposition: **MODIFY**. Approved Project priority: **P0**.

This specification does not activate work, change priority, or assert implementation completion. Live Project fields govern scheduling and current state.

## Humana competition acceptance contract

Status: **approved bounded offline implementation increment; not a completion attestation or live-environment approval**. The previously unspecified narrower scope is superseded by this explicit contract. ORCH-04 may reach Foundation Complete from a reviewed, deterministic offline identity and run-lineage contract integrated across the supported factory boundaries; live Humana execution and parity remain separate blocked capabilities and may not be inferred from this item.

### Bounded behavior and acceptance criteria

- **ORCH-04-AC01:** Define stable workload, source revision, run and attempt identities with explicit derivation.
- **ORCH-04-AC02:** Repeated identical inputs reproduce appropriate identities while distinct attempts and changed sources remain distinguishable.
- **ORCH-04-AC03:** Path aliases, content changes and identity-field credentials cannot collide or erase provenance.

### Shared competition gates

These gates carry forward the recorded AD-03 research decisions. See
[`_ACCEPTANCE-POLICY.md`](_ACCEPTANCE-POLICY.md) for exact reference revisions, ownership,
applicability and launch rules. The requirements below are embedded so a live issue is self-contained.

- **HC-01:** Bind applicable results to client/workload/source/run/attempt/artifact identities and
  policy/provider/strategy versions. Missing evidence stays explicit. Generated, executed, validated,
  parity-passed, certified and human-approved remain separate, evidence-backed claims.
- **HC-02:** Reused derived/remembered knowledge is advisory. Preserve origin, applicability, version,
  selection reason and conflicts. Test source/policy changes, rejected/superseded advice and cross-client
  exclusion. Stale recall cannot override current evidence. Non-consumers prove no recall dependency;
  do not add a memory store or Hippo runtime to every item.
- **HC-03:** Preserve source-faithful behavior; separate SAS macro processing, PROC FORMAT and target
  dbt/Jinja artifacts where applicable. Test isolated target scope and independent reconciliation.
  The workshop repo is patterns-only under AD-03's recorded reuse restriction: copy no source/docs,
  and treat neither its target output nor recalled examples as an authoritative SAS baseline.
- **HC-04:** Test synthetic secret/protected-data canaries at applicable input, error, evidence and
  recall boundaries; reject unsafe identity values or sanitize before persistence/hashing. Untrusted
  source/recall instructions cannot change access, endpoint, protected-path or approval policy.
  No automatic embeddings, transcript capture, hooks or background memory services are implied.
- **HC-05:** Supply positive and negative/mutation evidence per item criterion. Keep blocked, failed,
  skipped and human-assisted outcomes visible; mocks cannot satisfy real-environment claims.
  State-changing paths require repeat/restart and cross-workload isolation evidence. Required but
  unavailable Humana policies, baselines, access or approvals block qualification rather than defaulting.

### Required evidence and launch check

Provide an acceptance matrix for all `ORCH-04-AC*` criteria below and HC-01 through HC-05, mapping each to a concrete test/experiment/review artifact and its result. Include the source/configuration revision, command or review procedure, expected outcome, actual outcome and safe immutable evidence reference. A criterion without proof stays unverified; record justified non-applicability individually, never as a blanket waiver.

For implementation changes, run `make verify` and affected confidence gates; do not weaken them or alter untouched public corpus bytes. Documentation/research acceptance uses reviewed artifacts and reproducible experiments, not fabricated runtime claims. No automatic dependency installation, real-environment execution or GitHub completion is authorized by this spec.

The bounded increment was explicitly approved on 2026-09-17. Before `work` or `continue`, synchronize this approved full acceptance text to the exact live issue and read it back: the runner consumes the issue body, not this local file. Final commit/merge and Project closeout remain human-controlled.

## Competition delivery reconciliation

Local planning decision: **competition-critical**, wave **2**, Project priority **P0**. GitHub fields are unchanged until a separately reviewed publication.

**Why:** Required for the governed real-data execution/parity loop or its measured bounded automation; implement the minimum cohort-scoped slice.

**Competition slice:** One approved deterministic-first target path, approved AI adapter where needed, isolated Databricks runtime, immutable identity and failure/provenance contracts.

**Phase 2+ boundary:** Multiple vendor adapters, general control-plane services and packaging/deployment platform expansion.

**Entry condition:** Satisfied by explicit human approval on 2026-09-17. Re-use verified foundations instead of reimplementing them.

**Explicit implementation dependencies:** WLD-01. These are contract-completion dependencies, not permission to use live client systems.

**Evidence review:** Supervised engineering orchestration exists; do not equate it with a working migration convert-execute-validate-repair controller.

- Repository evidence to inspect: `src/smf/engineering_agent/orchestrator.py`.
- Repository evidence to inspect: `src/smf/execution/engine.py`.
- Repository evidence to inspect: `docs/IMPLEMENTATION_STATUS.md`.

**Review disposition:** `implement-offline-identity-contract`. Centralize and document canonical workload, source-revision, run and attempt identities; integrate the contract across supported offline factory boundaries; and prove stable repetition, distinct attempts and changed sources, path-alias handling, collision resistance, restart/two-workload isolation, and secret-canary rejection. This is not a live-runtime approval or completion attestation.

**Client inputs:** HC-REQ-01, HC-REQ-02, HC-REQ-04, HC-REQ-05, HC-REQ-07 in `competition/requirements.yaml`. Unconfirmed inputs block applicable client execution/acceptance, not offline contract development.

### ORCH-04-AC04: competition exit evidence

For each selected workload, preserve exact source/target snapshot and policy bindings; record the required check results, safe mismatch evidence and owner disposition. For stateful integration, prove repeat/restart, cancellation and two-workload isolation. For documentation/research, supply reviewed decision records and reproducible experiments instead of fictional runtime results. Use item-specific AC01-AC03 counterexamples and HC gates; every required test must pass, every failed/missing requirement must remain explicit, and no mock/static/generated-only output may satisfy real execution or parity acceptance. The user-confirmed planning envelope is 10 weeks and 1000 mixed-complexity SAS scripts to prove velocity and validation. Actual acceptance quota, numerical tolerance, resource/cost limits and business rules still require named Humana owners; none is invented here.
