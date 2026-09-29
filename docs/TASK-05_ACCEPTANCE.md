# TASK-05 acceptance evidence

Status: candidate offline fixture evidence; not a completion, launch, runtime, parity, or human
approval attestation.

Candidate base revision: `fbb83a3fae2a4d024151a85d7432868d185f7c7c`.

Fixture manifest: `tests/fixtures/macro-regression/manifest.json`, SHA-256
`cc5ca5c35cab589acb05a921a5ed9c9905e40d9be5dcd61697abc099b9f6bfbe`. The bound macro
strategy digest is `7a6a2259f7e36df48ee94f9eb814765a6ab1715d961b64629d71cd4e4cb5034c`.

The fixture loader recomputes each declared source size and SHA-256 during qualification. Before
analysis, the qualified-discovery boundary revalidates the complete mutable source inventory,
analyzes an isolated snapshot built only from the qualified bytes, and requires exact analyzed and
qualified path/size/SHA-256 inventory equality. The manifest is a test oracle, not production
evidence or an authorization input. All source locations, span digests, artifact/workload
identities, strategy bindings, definitions, observations, resolutions, and blockers asserted below
are freshly derived from those bound fixture bytes.

## Acceptance matrix

| Criterion | Procedure and expected result | Actual candidate result | Evidence / remaining boundary |
|---|---|---|---|
| TASK-05-AC01 | Run `python -m pytest tests/unit/test_macro_regression_fixtures.py -q`; strategy-only positive, negative, and adversarial scenarios must match fresh analysis and retain `expansion_mode="none"`. | PASS: 22 tests. No production strategy change. | `test_checked_in_macro_fixtures_match_fresh_static_analysis`; manifest and synthetic sources under `tests/fixtures/macro-regression/`. |
| TASK-05-AC02 | The same suite must cover unique definitions/repeated calls, PROC FORMAT separation, variables, literal includes, and byte mutation invalidation without changing public sources. | PASS in the fixture suite. `git diff --name-only -- tests/corpus/workloads/public` returned no paths. | `test_positive_fixture_keeps_macro_format_and_include_evidence_separate`; `test_discovery_rejects_source_mutation_after_fixture_qualification`; `test_discovery_rejects_content_not_bound_to_qualified_digest`. |
| TASK-05-AC03 | Dynamic calls, protected quoting, comments/strings, recursion/cycles, and duplicate definitions must not produce `CALLS`; a forged unique-resolution oracle must fail. | PASS in the fixture suite. | `test_false_positive_oracle_mutation_is_detected`; `adversarial-false-resolution`; `adversarial-include-cycle`. No fixture asserts expansion. |
| TASK-05-AC04 | Bind synthetic workload/source snapshots and strategy; exercise replay and two-workload isolation; preserve unavailable live target, runtime, cancellation, owner, tolerance, and disposition evidence as unavailable/not applicable. | PASS for deterministic replay, source mutation, and concurrent offline isolation. Live competition exit remains unverified. Cancellation and persistence recovery are not applicable because this task publishes no state. | `test_concurrent_failure_is_isolated_and_restart_is_deterministic`; source/span verification in the parametrized fixture test. Humana acceptance quota, tolerances, runtime, baseline, and owner disposition remain external blockers. |
| HC-01 | Verify exact workload/artifact/source path/size/checksum/span/strategy/observation/definition bindings; do not infer runtime claims. | PASS in focused tests; qualified content must match its digest, qualified and analyzed inventories must be exactly equal, and the serialized macro payload has no generated, executed, validated, parity, certification, approval, or expansion-success fields. | `test_checked_in_macro_fixtures_match_fresh_static_analysis`; `test_discovery_rejects_content_not_bound_to_qualified_digest`. Run/attempt identities are not applicable to non-persisting static test execution. |
| HC-02 | Prove the acceptance path consumes no recalled/durable intelligence and that source changes invalidate identities. | PASS by code review and mutation test. | Loader and tests use only checked-in manifest/source bytes and fresh discovery. No memory, embeddings, transcript, hook, or background service was added. |
| HC-03 | Separate SAS macro, PROC FORMAT, and target-template families; permit only uniquely resolved static macro calls to project edges. | PASS. The same-name PROC FORMAT and target-template artifacts cannot satisfy SAS macro calls. | Positive and adversarial scenario assertions; existing `tests/unit/test_macro_call_projection.py`. |
| HC-04 | Reject traversal, undeclared files, symlinks, unknown identity/type values, and success attestations; keep a synthetic sensitive canary out of macro evidence. | PASS in focused tests. | `test_fixture_manifest_rejects_attestations_unknown_types_and_ambiguous_identity`; `test_fixture_qualification_rejects_drift_and_undeclared_files`; `test_synthetic_sensitive_canary_does_not_become_macro_evidence`. |
| HC-05 | Supply positive/negative/mutation proof; keep missing, dynamic, unsupported, ambiguous, recursive, cyclic, and runtime-dependent outcomes visible; do not count ineligible input as success. | PASS locally, including the mandatory dependency audit; supported-version CI remains required. | All four manifest scenarios; `test_empty_or_non_sas_workload_has_no_eligible_macro_subject`; false-oracle mutation test; gate record below. |

## Gate record

| Gate | Candidate result |
|---|---|
| Macro fixtures, macro strategy, and call projection: `python -m pytest tests/unit/test_macro_regression_fixtures.py tests/unit/test_macro_strategy.py tests/unit/test_macro_call_projection.py -q` | PASS: 39 tests |
| Focused lint: `python -m ruff check tests/macro_fixture_loader.py tests/unit/test_macro_regression_fixtures.py` | PASS |
| Affected readiness, conversion, include, security, complexity, dependency, boundary, and topology suites | PASS: 134 tests |
| `./scripts/test-discovery-confidence.sh` | PASS: Gate A 1, Gate B 15, Gate C 16 tests |
| Public corpus base/worktree aggregate SHA-256 comparison | PASS: both `1dd036142b701d6601603c66bd1f68a3c7e7d2fee19a4bb138e4b384c2027fc1`; no public-source diff |
| `make verify` | PASS in the network-enabled repository environment: Ruff passed, mypy passed across 189 source files, all 1,595 tests passed in 174.12 seconds, and `pip_audit` reported no known vulnerabilities. The isolated Reviewer sandbox remained unable to resolve `pypi.org`; no gate was bypassed or weakened. |
| Python 3.11/3.12 CI | Unavailable locally; required before completion |
| Independent Reviewer acceptance | BF-001 independently reproduced, repaired, and verified closed. Reviewer sandbox retained BF-002 only because its dependency audit could not resolve PyPI; the exact final tree subsequently passed the network-enabled gate above. |

## Non-claims and blockers

The checked-in results are synthetic static regression evidence. They do not establish executable
macro expansion, conversion, SAS or Databricks execution, validation, parity, certification,
competition exit, or human approval. HC-REQ-01, HC-REQ-02, and HC-REQ-04 and the named Humana
acceptance owners remain required for applicable live qualification. No Project field, issue,
approval, commit, merge, or launch state is changed by this evidence.
