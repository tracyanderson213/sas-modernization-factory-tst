# PROV-01 offline provenance-chain acceptance

## Scope and truth statement

This increment implements a deterministic offline graph and verifier over immutable producer
evidence. It does not execute workloads or establish Humana semantic parity, certification, approval,
deployment readiness, production completeness, or final integration. Those claims remain unavailable.

The verifier consumes a canonical ORCH-04 lineage, exact source snapshot, signed stage envelopes that
bind original producer evidence and artifact bytes, and a trust policy whose digest is already bound
into the lineage. Lifecycle telemetry is reconstructed by the verifier. It is never accepted from a
caller or recalled summary.

## Acceptance matrix

| Criterion | Deterministic proof | Expected and actual result | Safe evidence reference |
|---|---|---|---|
| PROV-01-AC01 | Complete-chain, all-proper-policy-subsets and two-entry-point regressions | The full canonical stage sequence is mandatory and every stage binds the contract's sole eligible entry point; incomplete or multi-entry-point scopes cannot validate; passed | `tests/unit/test_provenance_chain.py` |
| PROV-01-AC02 | Complete-chain replay, missing-stage, retry recovery and tampered-summary tests | Identities and bindings reproduce; missing nodes stay explicit; derived telemetry recovers; passed | `tests/unit/test_provenance_chain.py` |
| PROV-01-AC03 | Original/artifact/source mutations, cross-run substitution, forged-publication and summary-only mutations | Every substitution, missing original, caller-authored chain or edited summary invalidates the claim before publication; passed | `tests/unit/test_provenance_chain.py` |
| PROV-01-AC04 | Exact snapshot bindings, immutable retry/recovery, cancellation enum and isolation-by-canonical output hierarchy | Offline contract behavior proved; live quota, tolerance and Humana runtime evidence unavailable and not claimed | `src/smf/provenance/engine.py`; `tests/unit/test_provenance_chain.py` |
| HC-01 | Context equality, lineage/policy/configuration/strategy bindings, signed producer identity and exact artifact digests | Unbound evidence rejected; passed | `test_cross_run_substitution_and_secret_identity_are_rejected` |
| HC-02 | No recall field or dependency exists; stored summaries are rederived from originals | Recalled or edited summary cannot authorize a claim; passed | `test_tampered_summary_cannot_replace_original_evidence` |
| HC-03 | Separate source, generated, execution-result and validation evidence bindings | Generated output cannot serve as source oracle or parity proof; passed for offline contract | `test_complete_chain_is_reconstructable_and_non_authorizing` |
| HC-04 | Safe identities/references, root confinement, publication symlink rejection, recursive source lineage checks and canary probe | Unsafe or protected identifiers and traversal variants fail before chain publication; passed | `test_cross_run_substitution_and_secret_identity_are_rejected`; `test_publication_rejects_unsafe_identity_paths`; `test_publication_rejects_symlink_boundary` |
| HC-05 | Positive, negative, mutation, missing-stage, denial/pending/expiry and recovery tests | False claims and skipped prerequisites stay failed or blocked; passed | `tests/unit/test_provenance_chain.py` |

## Reproduction

Repository revision: the reviewed working-tree revision containing this document. No commit, merge,
issue closure or Project state change is implied.

```bash
make prov01-confidence
make verify
```

`make prov01-confidence` runs the provenance contract, schema packaging, ORCH-04 lineage, batch
intake, deterministic conversion, false-evidence regression, execution retry/unknown-outcome,
validation, readiness binding, private-corpus isolation and public-corpus immutability checks. The
command also runs `git diff --check`. The final handoff records the actual gate results; an unavailable
dependency audit or CI environment remains a blocker rather than a waiver.

Observed local results on 2026-09-17:

- `make prov01-confidence`: 215 passed.
- `python -m ruff check src tests`: passed.
- `python -m mypy src`: passed for 189 source files.
- `python -m pytest`: 1,537 passed.
- `python -m pip_audit`: not completed because the restricted environment could not resolve
  `pypi.org`; dependency-vulnerability status therefore remains unverified.

## Durable-pattern self-review

- Optional or caller-authored attestations cannot manufacture success: every node requires a trusted
  producer signature fixed by the lineage-bound policy, lifecycle claims are derived, and publication
  independently reconstructs the supplied chain from original evidence.
- Evidence binds exact source bytes, original evidence, artifacts, identities, policy,
  configuration, strategy, provider, producer and decision.
- Unknown enum values and extra fields fail schema or semantic verification.
- ORCH-04 rejects empty closures and requires a non-empty SAS entry point; generated evidence must
  contain non-empty bytes.
- Source, original evidence and artifacts are rehashed on every replay, closing mutable-input gaps.
- Missing, pending, denied and expired human decisions remain distinct terminal states.
- Duplicate references, node IDs and active stage identities fail closed.
- Missing execution or validation cannot produce validated terminal success.
- Every policy must require all eight canonical stages, and the bounded graph rejects workloads with
  more than one eligible entry point rather than allowing partial subject coverage.
- Absolute, traversal, symlink and cross-context references fail closed.
- Canonical publication is immutable; byte-identical retry recovers a missing telemetry projection
  without invoking producer work or changing decision identity.
