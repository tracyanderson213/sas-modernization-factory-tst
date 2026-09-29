# OPS-03 - Operator and incident runbooks

## Business purpose

Support source-faithful, independently validated SAS modernization for the Humana competition and the reusable factory. Generated code alone is not success.

## Competition priority

Competition horizon: **P0**. Disposition: **MODIFY**. Approved Project priority: **P0**.

This specification does not activate work, change priority, or assert implementation completion. Live Project fields govern scheduling and current state.

## Humana competition acceptance contract

Status: **approved bounded offline implementation increment; not a completion attestation or live-environment approval**. The previously unspecified narrower scope is superseded by this explicit contract. OPS-03 may reach Foundation Complete from reviewed runbooks and deterministic documentation-contract evidence; live Humana execution and parity remain separate blocked capabilities and may not be inferred from this item.

### Bounded behavior and acceptance criteria

- **OPS-03-AC01:** Provide operator/incident procedures for supported CLI flows, evidence collection and recovery.
- **OPS-03-AC02:** Validate commands against current code and record safe stop/escalation paths without requiring a new workspace.
- **OPS-03-AC03:** Exercise missing permissions, stopped runs and partial failures; procedures must not bypass approval, erase evidence or fabricate completion.

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

Provide an acceptance matrix for all `OPS-03-AC*` criteria below and HC-01 through HC-05, mapping each to a concrete test/experiment/review artifact and its result. Include the source/configuration revision, command or review procedure, expected outcome, actual outcome and safe immutable evidence reference. A criterion without proof stays unverified; record justified non-applicability individually, never as a blanket waiver.

For implementation changes, run `make verify` and affected confidence gates; do not weaken them or alter untouched public corpus bytes. Documentation/research acceptance uses reviewed artifacts and reproducible experiments, not fabricated runtime claims. No automatic dependency installation, real-environment execution or GitHub completion is authorized by this spec.

Before `work` or `continue`, resolve conflicts with earlier scope, identify missing contract dependencies and obtain approval for the bounded increment. Synchronize the approved full acceptance text to the exact live issue and read it back: the runner consumes the issue body, not this local file. Final commit/merge and Project closeout remain human-controlled.

## Competition delivery reconciliation

Approved implementation decision: **active competition work**, Project priority **P0**. This decision authorizes the bounded offline runbook increment only and does not authorize live client-system access.

**Why:** Platform breadth, enterprise operationalization or alternate delivery capability; not needed for the minimum documented competition loop.

**Competition slice:** Implement and deterministically verify the operator and incident runbook foundation against current supported CLI, engineering-agent and Project lifecycle behavior, without expanding runtime claims.

**Live-environment boundary:** Humana execution, runtime parity, client-specific incident procedures and protected operational contacts remain blocked pending approved client inputs and are not prerequisites for this offline documentation foundation.

**Entry condition:** Satisfied by the explicit human approval recorded on 2026-09-17 for the P0 offline operator/runbook foundation.

**Explicit implementation dependencies:** None imposed by this plan. These are contract-completion dependencies, not permission to use live client systems.

**Evidence review:** No item-specific runtime implementation proof was established in this reconciliation; validate the contract against code before claiming completion.

- Repository evidence to inspect: `docs/IMPLEMENTATION_STATUS.md`.

**Review disposition:** `implement-offline-foundation`. Foundation Complete requires reviewed runbooks, deterministic command/documentation evidence and all applicable repository gates. It does not establish live Humana execution, parity or production readiness.

**Client inputs:** HC-REQ-01, HC-REQ-02, HC-REQ-04 in `competition/requirements.yaml`. Unconfirmed inputs block applicable client execution/acceptance, not offline contract development.

### OPS-03-AC04: competition exit evidence

For this documentation foundation, supply reviewed decision records, deterministic command/documentation tests and reproducible failure/recovery experiments instead of fictional runtime results. Where a selected workload is used as an offline example, preserve exact source/target snapshot and policy bindings and record safe mismatch evidence; do not claim that example as live execution or parity. Stateful procedures must preserve the existing attempt/worktree, distinguish cancellation from unknown outcome and demonstrate two-workload isolation through existing deterministic evidence where applicable. Use item-specific AC01-AC03 counterexamples and HC gates; every applicable offline test must pass and every live-environment requirement must remain explicitly blocked. Live Humana workload evidence is not required to close OPS-03 and cannot be manufactured from mocks, static checks or generated-only output. The user-confirmed planning envelope is 10 weeks and 1000 mixed-complexity SAS scripts to prove velocity and validation. Actual acceptance quota, numerical tolerance, resource/cost limits and business rules still require named Humana owners; none is invented here.
