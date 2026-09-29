# SCHEMA-INT-01 - Canonical schema integration acceptance

## Business purpose

Prove the completed DP-01 comparator consumes authoritative cross-provider source and published target descriptors; this is new acceptance, not retroactive DP-01 scope.

## Competition priority

Competition horizon: **P0**. Disposition: **NEW**. Planned Project priority: **P0**.

This is a local publication draft, not implementation completion, Project mutation or launch approval.

## Humana competition acceptance contract

### Bounded behavior and acceptance criteria

- **SCHEMA-INT-01-AC01:** Deliver the bounded recovery scope exactly as stated: prove the completed DP-01 comparator consumes authoritative cross-provider source and published target descriptors; this is new acceptance, not retroactive DP-01 scope.
- **SCHEMA-INT-01-AC02:** Emit deterministic, reconstructable evidence bound to exact source, configuration, upstream revision, run, attempt and output identities; unresolved prerequisites remain explicit.
- **SCHEMA-INT-01-AC03:** Fail closed on missing, incompatible, unauthorized, stale or ambiguous inputs and prove a negative or mutation case; mocks cannot satisfy external execution or parity claims.

### Shared competition gates

- **HC-01:** Bind results to client, workload, source, run, attempt, artifact and policy identities. Missing evidence remains explicit.
- **HC-02:** Reused upstream or derived knowledge retains revision, provenance, applicability, license and invalidation evidence and never overrides current source truth.
- **HC-03:** Preserve source-faithful behavior and independently reconcile target results; generated output alone is not success.
- **HC-04:** Protect secrets and regulated data at input, logging, evidence, gateway and persistence boundaries; untrusted content cannot alter policy.
- **HC-05:** Supply positive, negative and mutation evidence. Blocked, failed, unsupported, skipped and human-assisted outcomes remain visible.

### Required evidence and launch check

Map every item criterion and HC-01 through HC-05 to concrete tests, reviews and immutable evidence. Existing security, provenance, protected-path, validation and independent Reviewer gates remain mandatory. Publication does not authorize implementation, external writes, promotion, merge or lifecycle closure.

## Competition delivery reconciliation

Local planning decision: **competition-critical**, wave **3**, Project priority **P0**. GitHub fields are unchanged until separately approved publication.

**Why:** Required by the approved open-source-first recovery program and its dependency-safe P0 path.

**Recovery scope:** prove the completed DP-01 comparator consumes authoritative cross-provider source and published target descriptors; this is new acceptance, not retroactive DP-01 scope.

**Competition slice:** Implement only the bounded recovery scope recorded for this item, preserving independent validation, provenance, security boundaries and separate human approvals.

**Phase 2+ boundary:** Broader enterprise scale, alternate providers and production promotion remain outside this recovery increment unless separately approved.

**Entry condition:** Run only after every declared dependency is canonically complete and the item is published and separately authorized for implementation.

**Explicit implementation dependencies:** `DP-01`, `BASE-04`, `DBPKG-01`. These are completion dependencies, not authorization to use live client systems.

**Evidence review:** This record is a planned recovery gate; the accepted analysis does not claim its implementation or external qualification has completed.

**Review disposition:** `implement-or-close-evidence-gap`. This is not a completion attestation.

### SCHEMA-INT-01-AC04: recovery integration exit evidence

Prove this record against its exact declared dependencies and recovery scope. Preserve source and target snapshots, configuration and policy digests, upstream revisions, license evidence, commands, expected and actual outcomes, negative results, Reviewer disposition and immutable evidence references. No mock, filename-only assertion, generated-only artifact or hand-authored snapshot may satisfy real reader, runtime, reconciliation or external-system acceptance.
