# CV-03 acceptance evidence

## Scope and authority

Source revision: `ad3e8e8` plus the uncommitted CV-03 candidate tree. The implemented boundary is an
offline, SMF-owned deterministic regression capability. It does not use Humana data or runtime
access and does not claim SAS execution, Databricks execution, semantic parity, certification,
competition acceptance, or human approval.

The immutable repository fixture is
`tests/corpus/manifests/cv03-golden-conversion.yaml`; its declared SHA-256 values bind the exact
source and expected target bytes. Attempt evidence produced by tests is intentionally temporary and
is verified through content digests, canonical run/workload/attempt paths, and reload tests rather
than checked into the repository.

Candidate evidence references: manifest SHA-256
`1d376d1b3d8fb8fbb6099c4034e745eb3f42e9c790c7cc6781d91efaa03a783d`; positive source
SHA-256 `97aa37a250637ba7f2b757b371c3409435d839579d146bcefc9a28d0b65928ea`; expected target
SHA-256 `26e325b035c741496680c3399b9cd15725c782acfdfa04d091283d3d3eaa789f`; package behavioral
evidence digest `e3781abbeabfb462e12b67c616200ad4db286d4ee50f22ed58c78de6b461fe34`.

## Reproducible commands

```bash
bash scripts/test-cv03-golden-confidence.sh
bash scripts/test-corpus-confidence.sh
make verify
```

## Acceptance matrix

| Criterion | Concrete proof | Expected outcome | Actual outcome | Safe evidence reference |
|---|---|---|---|---|
| CV-03-AC01 | Positive fixture, strict manifest contract, package-reconstructed producer evidence, descriptor-bound behavioral qualification, and static validation | Versioned exact-byte golden match remains distinct from validation/parity | Passed locally | `test_positive_golden_is_exact_and_does_not_claim_parity`; `schemas/corpus-golden-comparison.schema.json` |
| CV-03-AC02 | Manifest binds provider/strategy and package behavioral evidence digests; plan/application evidence binds the exact attempt; promotion v2 records change provenance | Caller-authored labels, plan metadata, or coordinated file changes cannot qualify | Passed locally | `test_caller_authored_conversion_decision_cannot_manufacture_match`; `test_caller_authored_plan_metadata_cannot_manufacture_match`; `test_fabricated_review_and_unresolved_behavior_digest_cannot_authorize_golden` |
| CV-03-AC03 | PROC FORMAT and macro negative fixtures, SAS date/time rejection, corrupted output, and coordinated source/golden mutations | Construct families remain separate; SAS-only semantics and semantic drift fail closed | Passed locally | `test_construct_families_match_expected_non_generation_without_success_claim`; `test_coordinated_source_and_golden_change_cannot_bless_sas_date_semantics`; `test_coordinated_supported_source_and_golden_change_still_needs_behavioral_evidence` |
| CV-03-AC04 | Exact snapshots, policy/provider/strategy bindings, retry/concurrency test, and explicit offline limitation | Comparison is reconstructable and idempotent; unavailable client/runtime claims remain unverified | Passed for offline slice; Humana execution/parity blocked | `test_comparison_retry_and_concurrency_preserve_one_decision`; this document's scope statement |
| HC-01 | Qualification, producer stage, golden contract and result identity/digest verification | Replay or mutation across identities fails | Passed locally | `src/smf/corpus/golden.py`; existing corpus evidence replay tests |
| HC-02 | Golden comparison consumes no recalled/advisory memory | Acceptance has no recall dependency | Passed; not applicable to runtime recall | No memory subsystem or recall input in golden schema/API |
| HC-03 | Descriptor-bound package qualification, exact target comparison, PROC FORMAT/macro separation, and SAS date/time rejection | Textual stability cannot silently imply source semantics | Passed locally | CV-03 focused tests; `src/smf/conversion/registry.py` |
| HC-04 | Shared loader rejects private-client material; canonical sanitization remains on stage artifacts; snapshot traversal rules reused | Secrets/private bytes and boundary escapes fail closed | Passed locally | corpus security/isolation tests included by repository verification |
| HC-05 | Positive, negative, mutation, provider-spoof, TOCTOU, retry and concurrency tests | Missing/skipped/unvalidated work cannot become success or parity | Passed locally | `tests/unit/test_cv03_golden_regression.py`; `tests/unit/test_corpus_regression_evidence.py` |

## Gate results

- `bash scripts/test-cv03-golden-confidence.sh`: **PASS**, 133 tests.
- `bash scripts/test-corpus-confidence.sh`: **PASS**, 72 tests.
- `make verify`: Ruff **PASS**; strict mypy **PASS** for 182 source files; pytest **PASS** at the
  gate checkpoint. After the final fail-open hardening, the complete pytest rerun **PASS**ed all
  1,375 tests. `pip-audit` remains **BLOCKED** because the restricted environment could not resolve
  `pypi.org`. The dependency audit is not waived and must be rerun in an approved networked
  environment before final integration.

## Remaining external blockers

Humana source snapshots, approved baselines, numerical tolerances, business-rule owners, runtime
access, acceptance quota, cost/resource limits, and final evidence approval are not configured.
Those prerequisites block client execution and parity qualification, but not this offline regression
contract. Final commit, merge, Issue closeout, and Project-state change remain human-controlled.
