# Trusted SAS Baseline Acquisition

`smf acquire-baseline` implements the provider-neutral BASE-01 acquisition contract. The implemented
provider imports an approved SAS export package. It does not connect to SAS, execute SAS, validate a
target, establish parity, certify a workload, or approve production promotion.

## Trust boundary

An acquired baseline requires all of the following:

- a replay-valid admitted workload snapshot from `smf intake-batch`;
- exactly one canonical workload boundary with at least one output;
- a strict acquisition policy loaded from deployment-controlled configuration;
- an Ed25519-signed producer receipt bound to the client, workload revision, complete source
  closure, input snapshots, boundary, run, attempt, SAS execution, runtime configuration, output
  inventory, and acquisition-policy digest;
- a separately signed and attributable approval over the complete receipt subject;
- non-empty output bytes whose size and SHA-256 match the producer receipt.

Producer and approval proofs must use different trusted keys. Caller-supplied authority labels,
checksums, pass booleans, target-generated outputs, synthetic fixtures, stale exports, absent output
bytes, unknown modes, and mutable or escaping paths cannot authorize acquisition.

`sas_execution` is a closed mode but has no installed provider. It produces an explicit blocked result
with `sas_execution_provider_unavailable`. This is the required fail-closed behavior until a deployment
binding and provider are approved.

## Lifecycle semantics

- `acquired`: both proofs and every byte/binding check passed.
- `needs_evidence`: the export package or a current approval is absent.
- `human_required`: a valid attributable approval decision is pending.
- `blocked`: an attributable denial or unavailable direct-execution provider prevents acquisition.
- malformed, untrusted, unsafe, or integrity-invalid input is rejected and is not persisted as trusted
  evidence.

The canonical result and content-addressed outputs are immutable. Telemetry and readiness evidence are
recoverable derivatives. Recovery replays the stored proofs and output hashes and does not contact the
provider or reread the original export package.

## Readiness handoff

The generated `readiness-evidence.json` is a projection, not an authority by itself. Readiness requires
the exact acquisition-policy digest plus its distinct producer and approval authorities, key IDs, and
public keys to be independently allowlisted by deployment readiness policy. It resolves
`baseline.result.json` beneath the configured evidence root, replays both acquisition proofs, checks
exact workload/boundary/run/attempt/output bindings, and hashes the canonical artifact. A locator,
signature label, producer-selected approval trust root, or copied projection alone cannot pass.
Conflicting replay-valid baseline decisions for one dataset/run/attempt subject block readiness;
byte-identical redelivery of the same evidence ID is deterministically deduplicated.

## Current boundary

Checked-in tests use synthetic signed packages only. They prove the deterministic contract, negative
controls, isolation paths, and recovery behavior; they do not prove Humana SAS access or acquisition.
HC-REQ-03, selected cohort identities, current acquisition/retention permissions, and a reviewed real
signed export remain required before competition qualification. Consequently this repository increment
must not be represented as BASE-01 `Foundation Complete` or as parity success.
