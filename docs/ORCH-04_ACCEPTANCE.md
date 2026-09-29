# ORCH-04 acceptance evidence

## Scope and evidence authority

This matrix covers the bounded offline stable workload identity and run-lineage increment at source
revision `26da46dd96b420b4064c599c522ce8991c93e279`. It is not
a completion attestation, live-environment approval, parity result, certification, or Project-state
change. Commands below use synthetic local fixtures. Git revision is the reviewed checkout revision;
the working-tree implementation is intentionally uncommitted pending human review.

| Criterion | Procedure and expected outcome | Actual local result | Evidence reference |
|---|---|---|---|
| ORCH-04-AC01 | `PYTHONPATH=.:src pytest -q tests/unit/test_run_lineage.py`; each identity is domain/version separated and semantic verification rederives it. | PASS: derivation, strict schema, mutation, and publication tests passed. | `tests/unit/test_run_lineage.py`; `src/smf/workload/lineage.py`; `schemas/run-lineage.schema.json` |
| ORCH-04-AC02 | Same focused suite plus batch-intake tests; identical input repeats, a new attempt changes attempt/lineage only, changed bytes change source/run/attempt, retry rebuilds a deleted projection, and two workload roots remain isolated. | PASS in local synthetic tests. | `tests/unit/test_run_lineage.py`; `tests/unit/test_batch_intake.py` |
| ORCH-04-AC03 | Mutate locators, bytes, subjects, case-folded paths, enums, protected fields, envelopes, and idempotency-key bindings; inject plain, percent-encoded, and base64url-encoded secret canaries at every persisted string boundary; all ambiguity or unsafe material blocks before hashing or persistence and locator-only change cannot erase canonical provenance. | PASS in local synthetic tests. Direct construction/publication and integrated intake reject without echoing the canary or creating durable files. | `tests/unit/test_run_lineage.py`; `tests/unit/test_batch_intake_adversarial.py` |
| ORCH-04-AC04 | Preserve exact selected snapshots and policy bindings; prove local repeat/restart and two-workload isolation; keep unavailable cancellation, live snapshots, parity, and owner disposition explicit. | PARTIAL: offline identity/restart/isolation proven. Live Humana execution, cancellation, parity, tolerances, quota, and owner disposition remain blocked. | This matrix; `docs/IMPLEMENTATION_STATUS.md` |
| HC-01 | Inspect each envelope for client/workload/source/run/attempt plus policy/strategy/configuration/provider bindings; reject mutated identities. | PASS for the offline lineage envelope. No later-stage success is inferred. | `RunLineage`; mutation tests |
| HC-02 | Search the change for recall/memory dependencies; operation must remain deterministic without recall. | PASS: no recall store, embedding, transcript capture, hook, or background service added. | Changed-file review |
| HC-03 | Verify source closure identity is byte-bound and separate from locators and later generated/executed/validated claims. | PASS for source identity and claim separation; no semantic parity claim. | Lineage derivation tests; status/CLI docs |
| HC-04 | Inject plain/encoded synthetic secret canaries plus password/token/SSN/email values across identity, provenance, input, and path boundaries; reject without returning the unsafe value. | PASS in local synthetic tests. Canary-bearing client/workload/run/attempt/provider/subject/path/locator values are rejected before identity derivation or persistence; intake protected-source and boundary tests remain passing. | Protected-identity, lineage-publication, and intake adversarial tests |
| HC-05 | Run positive and mutation tests, preserve blocked states, and require immutable replay/recovery rather than caller assertions. | PASS for this offline increment; unavailable real-environment evidence remains blocked. | Focused suites and required-gate record below |

## Derivation contract

- `workload_id` binds the governed client and logical workload key.
- `source_revision_id` binds the workload and complete sorted canonical source closure. Acquisition
  locators are deliberately excluded from source identity but retained in the lineage envelope.
- `run_id` binds source revision, operation, target, policy/strategy/configuration digests, and the
  idempotency key.
- `attempt_id` binds the run, attempt key, provider/version, and exact qualified input digests.
- `lineage_id` binds the complete envelope, including locator provenance.

The contract is canonical JSON with explicit `smf.run-lineage` domain and version tags. Identifiers
contain the full SHA-256 digest. Reusing a run key with changed run material or an attempt key with a
changed envelope is an immutable conflict.

## Required-gate record

| Command | Actual result |
|---|---|
| `PYTHONPATH=.:src pytest -q tests/unit/test_run_lineage.py tests/unit/test_batch_intake.py tests/unit/test_batch_intake_adversarial.py` | PASS: 108 passed |
| `mypy src/smf/workload/lineage.py src/smf/intake/manifest.py` | PASS |
| `ruff check` on changed Python files | PASS |
| `bash scripts/test-discovery-confidence.sh` | PASS: 1 controlled, 15 adversarial, and 16 untouched-public-corpus tests passed |
| `bash scripts/ops03-affected-regressions.sh` | PASS: 141 passed |
| `bash scripts/test-dbx02-confidence.sh` | PASS: 52 passed after removing a reproduced circular-import regression |
| `git diff --check` | PASS |
| `make verify` | PARTIAL: Ruff passed; strict mypy passed for 187 source files; 1,508 tests passed. Final `pip-audit` could not resolve `pypi.org` because network/DNS is unavailable, so the required security gate remains blocked rather than waived. |

Local output is reproducible developer evidence, not an immutable reviewed CI artifact. No live Humana
environment was accessed and no GitHub Issue, Project field, commit, merge, or deployment was changed.
