# TASK-06 - Create synthetic complexity-tier corpus

## Business purpose

Support source-faithful, independently validated SAS modernization for the Humana competition and the reusable factory. Generated code alone is not success.

## Competition priority

Competition horizon: **P2**. Disposition: **DEFER**. Planned Project priority: **P2**.

This specification does not publish work, change live fields, or assert implementation completion. Preserve Status `Todo`, Implementation State `Partial`, all historical evidence, and the dirty TASK-06 worktree pending separately approved disposition.

## Humana competition acceptance contract

Status: **approved bounded follow-up; not a new AD-04 completion attestation**. Preserve AD-04's historical completion and add only reproducible synthetic complexity-tier corpus evidence. Do not treat file count alone as semantic complexity or alter public/client baselines.

### Bounded behavior and acceptance criteria

- **TASK-06-AC01:** Create reproducible synthetic complexity-tier workloads with declared dimension targets.
- **TASK-06-AC02:** Record generator seed, tier policy and observed dimensions; keep synthetic evidence separate from public and client baselines.
- **TASK-06-AC03:** A high file count alone cannot establish high semantic complexity; missing dimension evidence and duplicate artifacts cannot distort tier assignment.

### Recovery integration acceptance

Accepted recovery scope: set deferred/Todo lifecycle and P2 while preserving Implementation State Partial, all historical evidence, and the dirty worktree pending separately approved disposition. This scope is additive to the existing item-specific criteria below and does not erase historical evidence or approvals.

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

Provide an acceptance matrix for all `TASK-06-AC*` criteria below and HC-01 through HC-05, mapping each to a concrete test/experiment/review artifact and its result. Include the source/configuration revision, command or review procedure, expected outcome, actual outcome and safe immutable evidence reference. A criterion without proof stays unverified; record justified non-applicability individually, never as a blanket waiver.

For implementation changes, run `make verify` and affected confidence gates; do not weaken them or alter untouched public corpus bytes. Documentation/research acceptance uses reviewed artifacts and reproducible experiments, not fabricated runtime claims. No automatic dependency installation, real-environment execution or GitHub completion is authorized by this spec.

The historical bounded follow-up approval remains part of the evidence record but is superseded for scheduling by the current deferral. Do not run `work` or `continue`, publish a lifecycle change, or alter the existing dirty worktree until its disposition is separately approved. Preserve AD-04's historical completion and all TASK-06 evidence.

## Competition delivery reconciliation

Local planning decision: **phase2**, wave **6**, Project priority **P2**. GitHub fields are unchanged until a separately reviewed publication.

**Why:** Preserve historical Partial implementation evidence while this record is deferred from the recovery execution path.

**Recovery scope:** set deferred/Todo lifecycle and P2 while preserving Implementation State Partial, all historical evidence, and the dirty worktree pending separately approved disposition.

**Competition slice:** Deliver only as an evidence-linked part of AD-04; do not schedule a second competing implementation. Reuse and qualify existing intake/discovery/corpus/readiness foundations; add only missing governed SAS baseline, snapshot and mapping acquisition for the selected cohort. Approved SAS exports are acceptable if provenance is independently verified.

**Phase 2+ boundary:** Estate-wide connector federation, unattended baseline acquisition at scale and comprehensive SAS parsing.

**Entry condition:** Do not launch or alter the existing worktree until its disposition is separately approved.

**Explicit implementation dependencies:** None. These are contract-completion dependencies, not permission to use live client systems.

**Evidence review:** Static source-located discovery is implemented; runtime lineage and executable SAS macro expansion are not proved.

- Repository evidence to inspect: `src/smf/discovery/macro_strategy.py`.
- Repository evidence to inspect: `tests/unit/test_macro_strategy.py`.
- Repository evidence to inspect: `docs/IMPLEMENTATION_STATUS.md`.

**Review disposition:** `implement-or-close-evidence-gap`. This is not a new completion attestation. Existing evidence and historical approvals remain intact.

### TASK-06-AC04: competition exit evidence

For each selected workload, preserve exact source/target snapshot and policy bindings; record the required check results, safe mismatch evidence and owner disposition. For stateful integration, prove repeat/restart, cancellation and two-workload isolation. For documentation/research, supply reviewed decision records and reproducible experiments instead of fictional runtime results. Use item-specific AC01-AC03 counterexamples and HC gates; every required test must pass, every failed/missing requirement must remain explicit, and no mock/static/generated-only output may satisfy real execution or parity acceptance. The user-confirmed planning envelope is 10 weeks and 1000 mixed-complexity SAS scripts to prove velocity and validation. Actual acceptance quota, numerical tolerance, resource/cost limits and business rules still require named Humana owners; none is invented here.
