# Upstream Qualification

## Boundary

`smf upstream qualify` is an offline, provider-neutral qualification gate for the pinned
upstreams recovered in `competition/SAS_MIGRATION_RECOVERY_REPORT.md`. It validates exact revisions,
artifact bytes, acquisition provenance, engineering license evidence, activity observations,
capability and limitation evidence, compatibility, and the governed adoption disposition. It does
not download, install, execute, approve, promote, or modify an upstream or any GitHub/Project state.

The governed inventory is `competition/upstream/approved-inventory.json`. It contains all 24
upstreams in sections 3.1 and 3.2 of the accepted recovery report. A later recovered upstream must be
reviewed into that inventory before qualification; the command never invents or silently adds one.

## Inputs and trust domains

The command requires:

- a strict policy with an approved activity-age/future-skew contract and distinct Ed25519
  acquisition, observation, supporting-evidence, qualification, and prerequisite trust domains;
- the governed expected inventory;
- an evidence root containing `receipts/<upstream_id>.json`, every referenced immutable artifact and
  license file, and the configured SEC-03 prerequisite record;
- a qualification private key whose public key and key ID are trusted by the policy; and
- explicit global program scope, run, attempt, and RFC 3339 evaluation-time identities.

Acquisition evidence signs the exact origin, revision, artifact locator, byte count, and SHA-256.
Observation evidence binds that acquisition to the policy and inventory digests, scope, run,
attempt, activity source, licenses, capability commands/tests, expected and actual outcomes,
environment/output digests, limitations, compatibility, permitted use, and disposition. Capability
and compatibility claims must also reference separately signed, immutable execution, environment,
output, negative-case, and compatibility records. The final qualification authority signs the
deterministic whole-inventory result.

SEC-03 prerequisite evidence is not an optional success assertion. Only the exact canonical state
`Done` plus `Foundation Complete`, in a current trusted signed record bound to the policy-pinned
acceptance digest and a reconstructable scope/run/attempt decision identity, allows qualification.
Pending, denied, failed, and superseded evidence remain distinct from canonical completion.

## Command

```bash
smf upstream qualify \
  --policy /approved/upstream-policy.json \
  --inventory competition/upstream/approved-inventory.json \
  --evidence-root /approved/upstream-evidence \
  --scope-id humana-recovery \
  --run-id upq-2026-09-18 \
  --attempt-id attempt-1 \
  --evaluation-time 2026-09-18T12:00:00Z \
  --signing-key /protected/qualification-key.pem \
  --signing-key-id qualification-key-2026 \
  --signing-authority qualification-service \
  --out out --json
```

Exit status is `0` only when the complete inventory is qualified, `2` for a valid blocked, pending,
denied, incompatible, stale, unsupported, or failed result, and `1` for malformed, unsafe, ambiguous,
or unverifiable input.

## Evidence layout and retry

The canonical result is published first at:

```text
<out>/runs/<run>/upstream/<scope>/attempts/<attempt>/qualification.result.json
```

`consumer.projection.json` and `telemetry.json` are deterministic derivatives. Publication is
append-only. An identical retry preserves canonical bytes and can reconstruct a missing derivative.
A conflicting retry, including a changed evaluation time, fails. The CLI loads and verifies an
existing canonical result before any new evaluation; it does not reevaluate mutable inputs under
the same decision identity.

Publication and every downstream load rehash all referenced artifact, license, supporting-evidence,
prerequisite, and receipt bytes. Mutation, deletion, truncation, or symlink substitution therefore
blocks both publication and later consumption. Paths are relative to the evidence root and repeated
percent-decoding, traversal, absolute paths, cross-root references, and symlink components are
rejected.

## Consumer rules

The consumer projection is allowlist-only and retains the result/digest, policy/inventory, scope,
run/attempt, upstream, revision, outcome, disposition, receipt digest, and permitted-use bindings.
Non-qualified entries have no permitted use. `patterns_only` and `reject` never authorize execution.
Copying is exposed only for a qualified `reuse_selected_licensed_components` entry whose permitted
use explicitly includes `licensed_component`.

Every workload-specific consumer must add its own workload/source/run/attempt binding to the exact
UPQ result and independently enforce its provider, license, security, validation, and parity gates.
UPQ never claims installed, security-cleared, legally approved, executed, validated, parity-passed,
certified, promoted, or human-approved.

## Current limitation

The automated suite uses generated keys and synthetic bytes solely to prove the contract and its
negative/mutation behavior. No checked-in result qualifies the real upstreams. Actual UPQ-01 AC04
evidence remains blocked until SEC-03 is canonically complete and the pinned repositories/packages,
licenses, commands, outputs, environments, and independent Reviewer disposition are reacquired and
preserved through the approved evidence process.
