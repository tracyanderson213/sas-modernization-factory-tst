# TASK-04 Acceptance Evidence

## Scope and claim boundary

This record covers the bounded offline implementation of static SAS dataset producer/consumer
lineage. It does not claim SAS execution, runtime ordering, macro expansion, parity, certification,
human approval, live Humana access, or competition completion. Project state and Issue #109 remain
human-controlled.

The implementation binds literal DATA/SET/MERGE, PROC, PROC SQL, INFILE, and FILE accesses to exact
UTF-8 source spans, acquired artifact SHA-256 revisions, qualified dataset identities, the workload
source closure, and a versioned lineage policy. Multiple writers remain conflicting; missing and
unqualified producers remain explicit blockers.

## Reproducible evidence

| Acceptance | Procedure | Expected result | Actual local result | Evidence reference |
|---|---|---|---|---|
| TASK-04-AC01 | `python -m pytest tests/unit/test_task04_dataset_lineage.py -q` | Qualified identity and source/revision-bound producer/consumer observations | Pass: 24 tests | `tests/unit/test_task04_dataset_lineage.py`; `DataLineageAnalysis.policy_digest` and `source_closure_digest` in discovery JSON |
| TASK-04-AC02 | Focused TASK-04 and affected-consumer command recorded below | Preserve role, artifact revision, repeated accesses, all producer candidates, and output/graph projections | Pass: included in 58-test focused run | Test IDs `test_accesses_are_occurrence_and_revision_bound`, `test_repeated_write_in_one_artifact_remains_conflicting_observations`, `test_evidence_free_accesses_never_become_canonical_lineage`, and `test_lineage_does_not_select_from_multiple_producers` |
| TASK-04-AC03 | Same focused suite | Separate libraries/locations; conflicting overwrites and missing producers remain unresolved | Pass | Test IDs `test_same_member_in_different_libraries_never_connects`, `test_same_libref_rebound_per_artifact_does_not_connect`, `test_relative_external_files_are_source_scoped_and_unresolved`, `test_conflicting_producers_are_retained_without_selected_dependency`, and `test_missing_and_unresolved_producers_are_explicit` |
| TASK-04-AC04 | `./scripts/test-discovery-confidence.sh`; full repository tests; review this record | Offline source/configuration bindings and negative/mutation results are reproducible; live client claims stay blocked | Discovery confidence pass; 1,573 repository tests pass. Live Humana evidence remains blocked | This file, `docs/IMPLEMENTATION_STATUS.md`, and test output for the candidate tree at base revision `4433280679264f532c5af1826da9e01ef34baa25` |
| HC-01 | Inspect serialized `data_lineage_analysis` and occurrence records | Workload, source closure, artifact revision, access, dataset, and policy identities are bound | Pass for offline discovery | `src/smf/discovery/lineage.py`; `test_accesses_are_occurrence_and_revision_bound` |
| HC-02 | Search TASK-04 implementation imports and run focused tests without recall services | No memory/recall subsystem is consumed | Pass; deterministic local code only | `src/smf/discovery/lineage.py` imports and focused test command |
| HC-03 | Exercise dynamic, unbound, and multiple-writer cases | No macro expansion, runtime order, or target behavior is inferred | Pass | `test_missing_and_unresolved_producers_are_explicit`; `test_repeated_write_in_one_artifact_remains_conflicting_observations` |
| HC-04 | Run unsafe identity and boundary-oriented discovery tests | Credential-bearing identity is rejected before hashing; filesystem locations are evidence only | Pass for offline probes | `test_secret_bearing_dataset_identity_is_rejected_before_hashing`; discovery confidence Gate B |
| HC-05 | Run positive, negative, mutation, confidence, and repository suites | Blocked/ambiguous/missing work cannot become complete lineage | Pass locally, including the mandatory dependency audit; supported-version CI pending | `test_empty_or_non_sas_inventory_cannot_claim_complete_lineage`; `test_lineage_rejects_source_checksum_mismatch`; gate output below |

## Durable-pattern review

- `FAIL_OPEN_OPTIONAL_ATTESTATION` / `ASSERTION_NOT_EVIDENCE`: lineage state is recomputed from
  canonical relationships and occurrence evidence. Caller metadata cannot select a producer or set
  `complete`.
- `UNBOUND_EVIDENCE` / `TOCTOU_MUTABLE_INPUT`: access identity includes workload, artifact ID and
  revision, exact byte range and span digest, dataset identity, and policy digest. Derivation rejects
  source/artifact checksum disagreement and requires the immutable acquired bytes to reconstruct the
  span, digest, line, column, observed token, access identity, and relationship identity.
- `MALFORMED_ENUM_BYPASS` / `DUPLICATE_IDENTITY`: unknown dataset, relationship, and resolution
  values and duplicate canonical artifact/dataset/relationship/access identities fail deterministically.
- `EMPTY_OR_NONCONVERTIBLE_SUCCESS` / `SKIPPED_AS_SUCCESS`: no eligible access produces a blocker
  and `complete=false`; dynamic, unresolved, and evidence-free references do not create resolved
  lineage, downstream-output, or dependency-graph edges.
- `DENIAL_VS_PENDING`: TASK-04 has no human-approval decision input. Missing producer, unresolved
  identity, and conflicting producers use distinct typed states; no human state is synthesized.
- `BOUNDARY_ESCAPE`: library/file locations are retained as evidence strings and are never opened by
  lineage resolution. Unresolved librefs remain per-artifact scoped. Relative external files use a
  provisional source-directory scope, so equal literals in different source directories remain
  distinct and cannot create producer/consumer connectivity.
- `IDEMPOTENT_PERSISTENCE_RECOVERY`: discovery publication remains governed by the existing
  immutable CLI path. The analysis is deterministic and repeated derivation produces identical
  relationships and identities; TASK-04 adds no second store or side effect.

## Local gate record

The focused result used `python -m pytest -q tests/unit/test_task04_dataset_lineage.py
tests/unit/test_data_lineage.py tests/unit/test_sas_data_discovery.py
tests/unit/test_downstream_discovery.py tests/unit/test_workload_boundaries.py
tests/unit/test_current_state_topology.py tests/unit/test_modernization_disposition.py
tests/unit/test_target_state_pattern_inputs.py`.

| Gate | Result |
|---|---|
| Focused TASK-04 and affected-consumer suite | 58 passed |
| Ruff | Passed |
| Strict mypy | Passed for 189 source files |
| Full pytest | 1,573 passed |
| `make verify` | Passed in the network-enabled repository environment: Ruff passed, strict mypy passed for 189 source files, all 1,573 tests passed in 173.96 seconds, and `pip-audit` reported no known vulnerabilities. The isolated reviewer sandbox remained unable to resolve `pypi.org`; no gate was weakened or bypassed |
| Discovery confidence Gate A | 1 passed |
| Discovery confidence Gate B | 15 passed |
| Discovery confidence Gate C | 16 passed; untouched public corpus |
| Python 3.11 / 3.12 CI | Pending external CI; no claim |
| Live Humana execution and owner disposition | Blocked on HC-REQ-01, HC-REQ-02, and HC-REQ-04 |

The source revision for this record is the human-reviewed candidate tree based on the repository
revision reported by `git rev-parse HEAD`. A final immutable commit SHA and supported-version CI URLs
must be added by the human-controlled integration process before TASK-04 closeout.
