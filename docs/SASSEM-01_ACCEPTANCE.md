# SASSEM-01 Acceptance Evidence

## Scope and authority

This record covers the offline, deterministic SAS date/datetime literal increment at repository
base revision `af88ec8` plus the uncommitted SASSEM-01 working-tree changes. Final commit, merge,
issue lifecycle, deployment, and Humana acceptance remain human-controlled. Checked-in semantic
results are `declared-synthetic-expectation`; no row below claims a trusted SAS execution, live
Databricks execution, Humana parity, certification, or production readiness.

The configured behavior is limited to explicit date and UTC datetime literals inside the existing
qualified single-statement PROC SQL route. The package policy is represented by
`examples/policies/sas-temporal-utc.json` and validated against
`schemas/sas-temporal-policy.schema.json`.

## Acceptance matrix

| Criterion | Test or review procedure | Expected outcome | Actual outcome | Evidence reference and authority | Remaining blocker / applicability |
|---|---|---|---|---|---|
| SASSEM-01-AC01 | `pytest -q tests/unit/test_sas_temporal_semantics.py` | Prove both SAS quote forms, 1960 epoch, day/second units, Gregorian boundaries, exact fractional precision, UTC requirement, projections, strict policy enums, and exact Spark emission. | Passed locally. | `tests/unit/test_sas_temporal_semantics.py`; package-authored deterministic test. Policy schema and example bind the configuration revision. | Humana timezone and formatting policy is not owner-approved; the example policy cannot supply that approval. |
| SASSEM-01-AC02 | `pytest -q tests/unit/test_sas_temporal_semantics.py tests/unit/test_corpus_semantic_oracle.py` | Preserve literal spans/digests and emitted mapping provenance; load the independently attributable underlying/formatted synthetic oracle and prove comparator mutation sensitivity. | Passed locally. | `tests/corpus/manifests/semantic-temporal-literals.yaml` binds source and expected-output SHA-256 values to `declared-synthetic-expectation`; `tests/unit/test_corpus_semantic_oracle.py` supplies corpus-wide mutation probes. | No `sas-executed-baseline` exists, so trusted semantic parity remains unverified. |
| SASSEM-01-AC03 | `pytest -q tests/unit/test_sas_temporal_semantics.py` | Invalid dates/clocks, leap seconds, excess precision, time-only/unknown suffixes, two-digit years, absent/non-UTC policy, and source mutation fail closed. | Passed locally. | Parameterized negative tests and replay mutation test in `tests/unit/test_sas_temporal_semantics.py`; package-authored deterministic evidence. | Named zones, offsets, DST, locale parsing, and broader functions are intentionally unsupported. |
| SASSEM-01-AC04 | `pytest -q tests/unit/test_readiness_conversion_guard.py` | Preserve exact source/policy/generated bindings, retry recovery, tamper rejection, and workload isolation without counting generation as parity. | Passed locally for offline publication/retry/isolation. | Temporal mapping recovery/tamper test plus existing immutable-source, concurrency, telemetry, and two-workload tests in `tests/unit/test_readiness_conversion_guard.py`. | No selected Humana cohort, trusted baseline, runtime execution, cancellation-capable remote operation, tolerance, quota, cost rule, or owner disposition was supplied. Synchronous offline conversion has no exposed pending operation to cancel. Competition exit remains unverified. |
| HC-01 | Inspect `temporal-mappings.json` schema and canonical loader; run temporal and readiness tests. | Bind policy, strategy, source bytes/span, workload, artifact, run, attempt, plan, registry, and generated digest; keep lifecycle claims distinct. | Passed locally. | `schemas/sas-temporal-mapping.schema.json`, `src/smf/conversion/engine.py`, and bound-evidence tests. | Trusted validation/baseline identities remain external because this increment does not claim validation or parity. |
| HC-02 | Review imports and run focused tests without any recall service. | Acceptance must not depend on remembered/derived advice and must add no memory subsystem. | Applicable non-consumer behavior confirmed by code review. | `src/smf/conversion/temporal.py` and `src/smf/conversion/registry.py` have deterministic local inputs only. | Governed reusable estate learning is out of scope and not implemented here. |
| HC-03 | Run temporal, registry, and corpus tests. | Separate macro, PROC FORMAT/informat, target templates, source evidence, generated artifacts, and synthetic oracle evidence. | Passed locally. | Existing registry separation tests plus temporal negative tests; semantic manifest retains synthetic origin. | General FORMAT/informat, macro expansion, DATA-step translation, and target templates remain unsupported. |
| HC-04 | Run secret-canary, unsafe identity/path, raw-literal suppression, and mapping-boundary tests in the focused suites. | Sensitive canaries cannot authorize or leak through errors/evidence; paths and spans remain bounded. | Passed locally. | `test_comment_only_false_entrypoint_and_secret_canary_fail_closed`, temporal invalid-literal tests, and readiness boundary tests. | Live PHI/PII was not used; evidence is synthetic only. |
| HC-05 | Run all focused positive, negative, mutation, retry, tamper, and telemetry tests, then `make verify`. | Generated, executed, validated, parity-passed, human-assisted, blocked, unsupported, and failed remain separate; no mock/static output becomes parity. | Focused suites, Ruff, strict mypy, and the current 1,635-test suite passed. The final `pip-audit` step of `make verify` was blocked because the restricted environment could not resolve `pypi.org`. | Focused test paths above and local gate output; no security result is claimed for the unavailable network-dependent audit. | Dependency vulnerability audit remains unverified until rerun with approved network/cache access. Live execution and parity proof remain blocked, and final integration remains human-controlled. |

## Required commands

```text
pytest -q tests/unit/test_sas_temporal_semantics.py
pytest -q tests/unit/test_conversion_rule_registry.py
pytest -q tests/unit/test_corpus_semantic_oracle.py
pytest -q tests/unit/test_corpus_regression_evidence.py
pytest -q tests/unit/test_cv03_golden_regression.py
./scripts/test-corpus-confidence.sh
make verify
```

The final gate record must retain failures or unavailable prerequisites as explicit blockers; it
must not relabel generated-only or synthetic evidence as executed, validated, or parity-passed.
