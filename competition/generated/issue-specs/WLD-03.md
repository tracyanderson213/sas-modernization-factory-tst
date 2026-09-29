# WLD-03 - Code dependency graph

## Business purpose

Support source-faithful, independently validated SAS modernization for the Humana competition and the reusable factory. Generated code alone is not success.

## Competition priority

Competition horizon: **P0**. Disposition: **MODIFY**. Planned Project priority: **P0**.

This specification does not publish work, change live fields, or assert implementation completion.

## Humana competition acceptance contract

Status: **local review draft; not a completion attestation or launch approval**. Existing narrower scope is preserved. For completed items, assess new requirements as follow-up gaps without rewriting historical approvals.

### Bounded behavior and acceptance criteria

- **WLD-03-AC01:** Extract typed code dependencies with exact source references and unresolved candidates.
- **WLD-03-AC02:** Preserve includes, calls, cycles and ambiguity separately from data lineage and runtime scheduling.
- **WLD-03-AC03:** Quoted/commented calls and dynamic names cannot fabricate resolved code edges; source revision changes invalidate derived relationships.

### Recovery integration acceptance

Accepted recovery scope: complete code/include/call closure with unresolved runtime edges. This scope is additive to the existing item-specific criteria below and does not erase historical evidence or approvals.

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

Provide an acceptance matrix for all `WLD-03-AC*` criteria below and HC-01 through HC-05, mapping each to a concrete test/experiment/review artifact and its result. Include the source/configuration revision, command or review procedure, expected outcome, actual outcome and safe immutable evidence reference. A criterion without proof stays unverified; record justified non-applicability individually, never as a blanket waiver.

For implementation changes, run `make verify` and affected confidence gates; do not weaken them or alter untouched public corpus bytes. Documentation/research acceptance uses reviewed artifacts and reproducible experiments, not fabricated runtime claims. No automatic dependency installation, real-environment execution or GitHub completion is authorized by this spec.

Before `work` or `continue`, resolve conflicts with earlier scope, identify missing contract dependencies and obtain approval for the bounded increment. Synchronize the approved full acceptance text to the exact live issue and read it back: the runner consumes the issue body, not this local file. Final commit/merge and Project closeout remain human-controlled.

## Competition delivery reconciliation

Local planning decision: **competition-critical**, wave **1**, Project priority **P0**. GitHub fields are unchanged until a separately reviewed publication.

**Why:** Required by the approved open-source-first recovery program and its dependency-safe P0 path.

**Recovery scope:** complete code/include/call closure with unresolved runtime edges.

**Competition slice:** Implement only the bounded recovery scope recorded for this item, preserving independent validation, provenance, security boundaries and separate human approvals.

**Phase 2+ boundary:** Broader enterprise scale, alternate providers and production promotion remain outside this recovery increment unless separately approved.

**Entry condition:** Run only after every declared dependency is canonically complete and the item is published and separately authorized for implementation.

**Explicit implementation dependencies:** `WLD-01`, `TASK-03`, `SEC-05`. These are contract-completion dependencies, not permission to use live client systems.

**Evidence review:** Static source-located discovery is implemented; runtime lineage and executable SAS macro expansion are not proved.

- Repository evidence to inspect: `src/smf/workload/models.py`.
- Repository evidence to inspect: `tests/unit/test_workload_identity.py`.
- Repository evidence to inspect: `docs/IMPLEMENTATION_STATUS.md`.

**Review disposition:** `implement-or-close-evidence-gap`. This is not a new completion attestation. Existing evidence and historical approvals remain intact.

### WLD-03-AC04: competition exit evidence

For each selected workload, preserve exact source/target snapshot and policy bindings; record the required check results, safe mismatch evidence and owner disposition. For stateful integration, prove repeat/restart, cancellation and two-workload isolation. For documentation/research, supply reviewed decision records and reproducible experiments instead of fictional runtime results. Use item-specific AC01-AC03 counterexamples and HC gates; every required test must pass, every failed/missing requirement must remain explicit, and no mock/static/generated-only output may satisfy real execution or parity acceptance. The user-confirmed planning envelope is 10 weeks and 1000 mixed-complexity SAS scripts to prove velocity and validation. Actual acceptance quota, numerical tolerance, resource/cost limits and business rules still require named Humana owners; none is invented here.
