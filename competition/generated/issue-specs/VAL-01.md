# VAL-01 - Deterministic cell-level parity engine

## Business purpose
Humana's paid competition is won on successfully converted AND validated SAS workloads against real Humana data. Generated code alone is not success.

## Competition priority

Competition horizon: **P0**. Disposition: **NEW**. Planned Project priority: **P0**.

This specification does not publish work, change live fields, or assert implementation completion.
## Desired behavior
Compare authoritative SAS and Databricks outputs at cell level with explicit schema/key/row alignment, numeric tolerance, floating-point, null, date/time, ordering, duplicate, coercion, formatting and nondeterminism policies.

## Architecture
Preserve bounded task-specific LLM context separately from durable estate-wide intelligence. Reuse canonical identity, dependency/lineage evidence, provenance, secret sanitization, protected paths, isolated worktrees and Architect/Developer/Reviewer gates. No Humana-only fork.

## Inputs and outputs
Consume canonical workload/run identity, required source/dependency evidence, relevant durable estate intelligence, configured runtime bindings and prior-attempt evidence. Emit deterministic machine-readable state/evidence for orchestration, validation, benchmarking, audit reconstruction, competition telemetry and 2027 scale.

## Failure, retry and concurrency
Fail closed on missing prerequisites. Separate Humana/environment blockers from conversion, execution and validation defects. Never count blocked, skipped, generated-only or unvalidated work as parity success. Independent workloads must not require global serialization. Retries are bounded and idempotent where applicable.

## Security and evidence
Preserve secret/PHI/PII controls. Credentials are references, never plaintext evidence. Capture workload/run/attempt IDs, source hashes, strategy/provider/model versions when applicable, generated hashes, execution result, validation policy/result, repairs, elapsed/machine time, human intervention, complexity, blockers and terminal disposition.

## Non-goals
No hard-coded demo outcomes, weakened validation, hidden differences, fabricated parity, skipped-as-success behavior or parallel Humana product architecture.

## Acceptance criteria
1. Positive, negative and adversarial fixtures prove behavior.
2. Every terminal outcome is machine-readable and reconstructable.
3. One workload failure cannot corrupt another.
4. Missing prerequisites become explicit blocked/unresolved outcomes.
5. Security regression tests remain green and secrets never persist in canonical evidence.
6. Public corpus source bytes remain untouched.
7. `make verify` and affected confidence gates pass.
8. Telemetry distinguishes generated, executed, validated, parity-passed, human-assisted and blocked outcomes.
9. Idempotency/restart behavior is tested where lifecycle state changes.
10. Bounded-context/durable-intelligence separation is preserved.

## Required tests
Unit, integration, negative/adversarial, evidence/provenance, security, restart/idempotency and concurrency tests as applicable, including a mutation test proving false claims fail.

## Definition of done
Implementation, tests, docs and evidence gates complete; no gate weakened; Reviewer accepts; final integration remains human-controlled.

## Humana competition acceptance contract

Status: **local review draft; not a completion attestation or launch approval**. Existing narrower scope is preserved. For completed items, assess new requirements as follow-up gaps without rewriting historical approvals.

### Bounded behavior and acceptance criteria

- **VAL-01-AC01:** Compare aligned source/target cells using versioned schema, key, duplicate, null, numeric and ordering policies.
- **VAL-01-AC02:** Persist counts and safe mismatch references tied to authoritative SAS and actual target snapshots; repeat the comparison deterministically.
- **VAL-01-AC03:** Mutated cells, duplicate keys, unmatched rows, tolerance boundaries and absent baselines fail; do not infer whole-data parity from aggregates or samples.

### Recovery integration acceptance

Accepted recovery scope: DataComPy/Spark-backed full-row certification; require partitioned/distributed execution for large tables; prohibit whole-table pandas collection. This scope is additive to the existing item-specific criteria below and does not erase historical evidence or approvals.

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

Provide an acceptance matrix for all `VAL-01-AC*` criteria below and HC-01 through HC-05, mapping each to a concrete test/experiment/review artifact and its result. Include the source/configuration revision, command or review procedure, expected outcome, actual outcome and safe immutable evidence reference. A criterion without proof stays unverified; record justified non-applicability individually, never as a blanket waiver.

For implementation changes, run `make verify` and affected confidence gates; do not weaken them or alter untouched public corpus bytes. Documentation/research acceptance uses reviewed artifacts and reproducible experiments, not fabricated runtime claims. No automatic dependency installation, real-environment execution or GitHub completion is authorized by this spec.

Before `work` or `continue`, resolve conflicts with earlier scope, identify missing contract dependencies and obtain approval for the bounded increment. Synchronize the approved full acceptance text to the exact live issue and read it back: the runner consumes the issue body, not this local file. Final commit/merge and Project closeout remain human-controlled.

## Competition delivery reconciliation

Local planning decision: **competition-critical**, wave **3**, Project priority **P0**. GitHub fields are unchanged until a separately reviewed publication.

**Why:** Required by the approved open-source-first recovery program and its dependency-safe P0 path.

**Recovery scope:** DataComPy/Spark-backed full-row certification; require partitioned/distributed execution for large tables; prohibit whole-table pandas collection.

**Competition slice:** Implement only the bounded recovery scope recorded for this item, preserving independent validation, provenance, security boundaries and separate human approvals.

**Phase 2+ boundary:** Broader enterprise scale, alternate providers and production promotion remain outside this recovery increment unless separately approved.

**Entry condition:** Run only after every declared dependency is canonically complete and the item is published and separately authorized for implementation.

**Explicit implementation dependencies:** `SCHEMA-INT-01`, `DP-02`, `DP-03`, `DP-04`, `DP-05`, `DBX-04`. These are contract-completion dependencies, not permission to use live client systems.

**Evidence review:** Structural comparison and synthetic semantic comparators exist; live dataset acquisition/alignment and cell-level Humana parity are not established.

- Repository evidence to inspect: `src/smf/corpus/oracle.py`.
- Repository evidence to inspect: `src/smf/validation/structural.py`.
- Repository evidence to inspect: `docs/validation/data-parity.md`.

**Review disposition:** `implement-or-close-evidence-gap`. This is not a new completion attestation. Existing evidence and historical approvals remain intact.

### VAL-01-AC04: competition exit evidence

For each selected workload, preserve exact source/target snapshot and policy bindings; record the required check results, safe mismatch evidence and owner disposition. For stateful integration, prove repeat/restart, cancellation and two-workload isolation. For documentation/research, supply reviewed decision records and reproducible experiments instead of fictional runtime results. Use item-specific AC01-AC03 counterexamples and HC gates; every required test must pass, every failed/missing requirement must remain explicit, and no mock/static/generated-only output may satisfy real execution or parity acceptance. The user-confirmed planning envelope is 10 weeks and 1000 mixed-complexity SAS scripts to prove velocity and validation. Actual acceptance quota, numerical tolerance, resource/cost limits and business rules still require named Humana owners; none is invented here.

### VAL-01-AC05: ten-week competition proof

Run against attributable SAS baseline and actual target snapshots with approved output alignment, keys and tolerance rules. Detect seeded missing rows, duplicate-key ambiguity, wrong values, missing-value/type/date differences and stale snapshot bindings. Missing approved policy blocks applicable acceptance; no inferred zero-tolerance or permissive default.
