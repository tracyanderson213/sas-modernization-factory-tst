# Batch Workload Intake

## Boundary

AD-01 supplies a bounded offline admission mechanism for a versioned script inventory. It reuses the
canonical workload/discovery graph and security sanitization boundaries. The signed manifest is the
declared inventory, but it cannot authorize its own success: intake re-reads source bytes, verifies
size and digest, snapshots those bytes, runs discovery from the snapshot, and reconciles the result.

Logical workload identity is stable across revisions. Workload revision identity binds the logical
identity, exact source closure, intake-policy digest, manifest version, provider version, and discovery
strategy version. Batch revision identity binds the signed manifest and trusted policy. Result identity
adds run and attempt. A changed source or policy therefore creates a new revision without overwriting
earlier evidence.

Per-workload decisions are `admitted` or `blocked`; the batch disposition is `admitted`, `partial`, or
`blocked`. Missing readiness prerequisites are retained as `missing`. Intake never upgrades those
records to passed and never asserts generation, execution, validation, parity, certification, or
human approval.

## Persistence and recovery

Canonical results live below:

```text
runs/<run-id>/batch-intakes/<batch-id>/revisions/<batch-revision-id>/attempts/<attempt-id>/
```

Snapshot files are published without overwrite and made read-only before the authoritative result.
Existing equal bytes are reused; conflicting or writable bytes fail closed. Protected-data or secret
canaries are rejected before snapshot publication. Re-publishing an existing canonical result only reconstructs
missing readiness-input and telemetry projections. The downstream verifier requires one exact admitted
workload; matches workload revision, closure, run, attempt, signed manifest, trusted policy, and current
snapshot bytes; then returns a frozen, path-free, in-memory source-byte handoff. Downstream conversion
must consume that verified byte set rather than reopen a mutable filesystem path.

## Acceptance evidence matrix

| Criterion | Procedure | Expected and actual result | Safe evidence reference |
|---|---|---|---|
| AD-01-AC01 | `python -m pytest tests/unit/test_batch_intake.py` | Distinct manifests, identities, snapshots, and closure evidence; **PASS** | `tests/unit/test_batch_intake.py` |
| AD-01-AC02 | Repeat intake, then change source bytes/version | Repeat is byte-idempotent; changed source creates a new revision and preserves the prior result; **PASS** | `test_repeat_is_idempotent_and_changed_bytes_create_revision` |
| AD-01-AC03 | Mixed valid/invalid batch plus path, enum, duplicate, orphan, and identity canaries | Invalid workload blocks without corrupting the valid workload; duplicate aliases and unmapped scripts remain explicit; unsafe envelope data is rejected; **PASS** | `tests/unit/test_batch_intake_adversarial.py` |
| AD-01-AC04 | Reload, exact-binding verification, snapshot mutation, and fabricated claim mutation | Exact replay succeeds; mutation and false lifecycle claims fail closed; **PASS** | `test_mutated_snapshot_and_fabricated_success_are_rejected` |
| AD-01-AC05 | Reconcile signed manifest denominator and preserve unprocessable records | Unique inventory plus explicit unprocessable records retains the original denominator; focused proof is automated; real Humana 1,000-script evidence is **BLOCKED** pending the governed client manifest | `test_thousand_script_denominator_is_preserved` |
| HC-01 | Mutate result, workload revision, closure, run, attempt, snapshots, manifest, or any policy field | Loader/verifier rejects unbound or stale-digest evidence; **PASS** | `src/smf/intake/manifest.py` and adversarial tests |
| HC-02 | Inspect policy/result schemas and no-recall test path | No recall input, store, or dependency exists; **PASS (not a recall consumer)** | `src/smf/schemas/batch-intake-*.schema.json` |
| HC-03 | Run discovery from immutable SAS snapshots and reject unresolved code closure | Source and canonical discovery remain distinct; no target artifact or parity oracle is invented; **PASS** | `src/smf/intake/engine.py` |
| HC-04 | Exercise protected identity/content, traversal, encoded traversal, URL, symlink, and secret controls | Secret/PHI/PII source canaries fail before snapshot publication and diagnostics use bounded reason codes; **PASS** | `test_boundary_escape_blocks_without_echo`, `test_protected_source_is_blocked_before_snapshot` |
| HC-05 | Mutate enum and lifecycle claims; load hand-authored/tampered evidence | Unknown values, nonconvertible entrypoints, mutable evidence, and skipped-as-success claims fail; **PASS** | `tests/unit/test_batch_intake_adversarial.py` |

The implementation was evaluated from base revision
`09ef1330462a40623b70bc4a41b1c140e1da4a5f` with per-test generated Ed25519 policy/configuration
fixtures; no live client configuration was used. Review-run results:

- `python -m ruff check src tests`: **PASS**.
- `python -m mypy src`: **PASS**.
- `python -m pytest`: **PASS**, 1,191 tests.
- `./scripts/test-discovery-confidence.sh`: **PASS**, all three gates.
- `make pilot-confidence`: **PASS**, 34 tests.
- `python -m pip_audit`: **PASS**, no known vulnerabilities found in auditable dependencies; the
  local `sas-modernization-factory` package is not published on PyPI and is reported as skipped.

Focused procedures use only generated temporary fixtures. These results do not claim live Humana
execution, parity, acceptance, or completion.
