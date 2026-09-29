# Workload Readiness Qualification

The readiness engine is a deterministic admission gate between discovery and conversion. It
evaluates supplied canonical discovery facts and explicit assessment, mapping, baseline, runtime,
environment, and approval evidence. It does not acquire those facts or call Humana systems.

## Classifications

The default precedence is `UNSUPPORTED`, `BLOCKED`, `NEEDS_EVIDENCE`, `HUMAN_REQUIRED`, then
`READY`. `UNSUPPORTED` means a confirmed construct or capability is outside the policy. `BLOCKED`
means evidence proves a remediable prerequisite failed. `NEEDS_EVIDENCE` covers absent, stale,
ambiguous, unresolved, or unattributable facts. `HUMAN_REQUIRED` is used only after technical
prerequisites pass and policy requires a decision. Every finding is retained even when precedence
selects another terminal classification.

`READY` requires a governed discovery snapshot whose signed workload digest binds the complete
canonical artifact, dataset, relationship, output, boundary, external-dependency, and dependency-
graph inventory. Changing or omitting any of those facts invalidates the snapshot. It also requires at
least one convertible SAS program with a canonical SHA-256 and canonical discovery provenance, a
dependency graph, and a governed assessment for each SAS entry point whose source checksum matches
that exact artifact. Assessment complexity uses the canonical `simple`, `moderate`, `complex`, and
`highly_complex` values; unknown values are rejected, and the Humana policy requires review for
`highly_complex`. Passing assessments must explicitly record `complexity`, `risk_factors`, and
`unsupported_constructs`; missing outputs persist as attributable `NEEDS_EVIDENCE` rather than
behaving as benign defaults. Confirmed failures and unsupported constructs remain visible and retain
their stronger classification when other assessment outputs are missing. Relationship kinds must be
canonical so unknown lineage cannot hide required input or output evidence. Every observed input and
output needs an approved mapping that identifies its target dataset, catalog, and schema; carries the
governed mapping digest and decision ID; and matches policy-trusted authority and acquisition-source
bindings. Multiple trusted records may corroborate one mapping decision, but disagreement in decision identity,
target dataset, target catalog/schema, or mapping digest is `BLOCKED` and retains every conflicting
evidence ID. No implicit multi-target policy is assumed. Outputs need
authoritative source-executed baselines and confirmed downstream-consumer lineage with concrete
consumer identities. A baseline must be attested to the exact qualified workload digest and selected
boundary so an
older execution cannot authorize a changed source or boundary revision. It must also include an immutable retrievable artifact locator, matching
content digest, schema digest, non-empty measurement set, and source execution linkage; a signed
checksum or pass assertion alone is not reconstructable evidence. All policy-required runtime and
environment checks must pass. A policy may use the legacy named-check lists or the first-class
prerequisite contract, but never both. The Humana policy uses the latter and requires SAS baseline
runtime and acquisition access, Databricks workspace/catalog/scratch/output bindings, source and
target data scope, network/private connectivity, workload identity, runtime compatibility, quotas,
validation execution/result permissions, cleanup/retention approval, and logging/audit access.
Each ordered checklist entry records its domain, named owner role and assignment reference,
attributable evidence/result IDs and digests, validity window, next action, and one of `pass`,
`denied`, `pending`, `missing`, `expired`, or `conflicting`. Expected or generated outputs are not
baseline evidence. The Humana binding additionally requires the `sas-executed-baseline` authority
and a `source_execution_id`.

BASE-01 acquisition projections follow the stronger canonical-result path. The projection identifies
the acquisition result, policy, receipt, input snapshot, runtime configuration, output, run, and
attempt. Qualification resolves the result beneath `result_root`, rejects traversal and symlinks,
requires the readiness policy to anchor the exact acquisition-policy digest and its distinct producer
and approval authorities, key IDs, and public keys, replays both proofs, checks the exact workload/
boundary/output bindings, and hashes the immutable acquired artifact. A producer-controlled approval
root, copied projection, or signed locator cannot pass without that canonical result and artifact.
Multiple verified decisions for one dataset/run/attempt subject must have one canonical identity and
technical result; disagreement blocks readiness as an explicit conflict. Exact repeated delivery of
the same evidence record is deduplicated before evaluation.

Every legacy discovery snapshot, assessment, mapping, baseline, runtime, environment, and approval
record must carry an Ed25519 proof over its complete canonical content. A BASE-01 baseline projection
instead replays the two signed canonical acquisition records described above. The policy binds each evidence kind to allowed
authority, acquisition source, key ID, public verification key, and exact policy digest. Runtime and
environment prerequisite records also bind the exact client, deployment, environment,
configuration digest, workload, run, attempt, prerequisite, owner assignment, check execution or
decision, and an immutable result URI/digest. A signed pass boolean without that result is missing
evidence. The URI must be a canonical relative `results/*.json` path beneath the evidence-bundle
directory. Qualification reads the file without following a symlink, verifies its exact canonical
bytes and SHA-256, checks every workload/run/attempt/configuration/authority binding, and embeds the
verified result in the immutable manifest for deterministic replay. Traversal, remote schemes,
missing files, noncanonical JSON, digest drift, or identity drift remain `NEEDS_EVIDENCE`.

The deployment readiness binding separately lists the active Databricks, security, and validation
configuration files. Their ordered path-and-byte digests must equal the prerequisite policy's
`configuration_digest`; qualification/admission through that binding fails closed after any file
mutation until a reviewed policy and new attempt-scoped prerequisite evidence bind the new snapshot.
Explicit denial is `BLOCKED`; pending owner action is `HUMAN_REQUIRED`; absence, expiry,
or a binding mismatch is `NEEDS_EVIDENCE`; conflicting current grant and denial records are
`BLOCKED`. Human approvals identify the decision and
approver and bind the exact workload digest, pre-approval qualification digest, run, attempt, and
boundary. Reusing approval bytes for a different qualification remains `HUMAN_REQUIRED`. Missing or
invalid proofs remain reconstructable candidate evidence but produce `NEEDS_EVIDENCE`; caller-
supplied labels and pass/fail booleans cannot produce `READY` or human-assisted telemetry.

A missing trusted human decision is `HUMAN_REQUIRED`; an exact-bound attributable governed denial is
`BLOCKED` even when assessment complexity or risk did not independently request review. The two
states remain distinct in readiness outcomes and blocker evidence. A governed failed discovery
snapshot also blocks admission and cannot be hidden by supplying a conflicting passing snapshot.

For selected SAS artifacts, readiness also requires a complete canonical macro analysis whose
workload, artifact inventory, source checksums, byte locations, strategy snapshot, version, and
digest match `smf-sas-macro-discovery/1.0`. Missing analysis, duplicate identities, incomplete
coverage, changed source bytes, a changed strategy, or an expansion claim produces
`NEEDS_EVIDENCE`. Typed macro blockers use the governed unresolved-dependency policy;
recursive/cyclic and limit outcomes are `BLOCKED`, runtime/dynamic outcomes need evidence, and
unsupported behavior is `UNSUPPORTED`. A caller-supplied `macro_complete` assertion cannot satisfy
this requirement because the signed discovery snapshot must bind the complete analysis.

When a canonical boundary is selected, qualification evaluates only that boundary's artifact,
dataset, output, external-dependency, relationship, and unresolved-dependency scope. Workload-level
runtime/environment checks remain shared prerequisites. Evidence for another boundary is validated
as belonging to the workload but cannot change the selected boundary's decision. Conversion binds
the source artifact to the same boundary recorded by the readiness manifest. A selected boundary
must be closed over discovered relationship endpoints and output-to-dataset links; incomplete
boundaries are rejected instead of silently dropping facts.

## Persistence and retries

Results are schema-validated, content-digested, deterministically replay-verified, and atomically
published at:

```text
out/runs/<run-id>/workloads/<workload-id>/attempts/<attempt-id>/readiness.manifest.json
```

Identity components are validated against path traversal. An existing attempt is canonical when its
identity and qualification-input digest match; it is never overwritten by reevaluation-only timing.
If publication stopped after the manifest was written, retry validates that canonical manifest and
recreates its deterministic telemetry projection. A new qualification attempt uses a new attempt ID,
preserving earlier blockers and isolating each workload. Reload validates schema and digest,
then replays the qualification and compares its result ID, classification, checks, blockers,
missing evidence, next actions, evidence references, validity, and terminal disposition before a
manifest can admit conversion. Each manifest retains the sanitized canonical workload,
complete in-scope evidence records, and a normalized policy snapshot so baseline checksums, mapping
directions and approvals, assessment findings, and runtime/environment check IDs can be reconstructed
after restart. It does not copy secrets or unrelated estate-wide context.

A bounded `readiness.telemetry.json` event is atomically persisted beside the manifest. It reports
the readiness classification, explicit blocked flag, prerequisite states, and blocker ownership
while explicitly leaving generated, executed,
validated, and parity-passed outcomes false. `human_assisted` is true only when explicit approval
evidence satisfied a policy-required human review on that attempt.

## CLI

```bash
smf ready discovery.json readiness-evidence.json \
  --policy deployments/humana/readiness-policy.yaml \
  --run-id run-2026-09-10 --attempt-id 1 --workload-id WL-123 --boundary-id WB-123 \
  --out out --json
```

The evidence file is an object containing `workload_id` and an `evidence` array. Evidence records
carry an evidence ID, workload and subject IDs, kind, status, timestamp, and kind-specific fields.
The command persists every valid evaluation. It exits `0` only for `READY`, `2` for a valid non-ready
classification, and `1` for malformed or unsafe input.

Every conversion API and CLI request requires an authoritative deployment binding that mandates
readiness and supplies the policy and verification keys. The Humana factory binding is one such
binding. Conversion consumes it with `--deployment-config deployments/humana/factory.yaml`; no
separate opt-in flag is needed. Admission also requires
`--source-artifact-id`; that canonical artifact must belong to the qualified workload, represent a
SAS program, and have a SHA-256 checksum matching the exact source bytes being converted. That file
is copied to an isolated admitted snapshot after digest verification; assessment and conversion use
that same snapshot so later mutation of the original path cannot change the qualified source.
Conversion outputs are collision-rejecting and isolated under
`out/runs/<run-id>/workloads/<workload-id>/attempts/<attempt-id>/conversion/<artifact-id>/`.
The deployment policy contains only requirements, owners, and actions; endpoints, credentials,
client data, and fixed competition outcomes are excluded. Approval produces new evidence and a new
attempt rather than mutating a prior result.

The checked-in Humana owner-assignment references identify required client inputs; they do not name
people or prove that access has been granted. Until current signed result artifacts for every entry
are supplied by the named Humana roles, pilot execution remains non-ready.
