# Offline pilot cohort selection

HPILOT-01 provides a provider-neutral selection and admission contract. It consumes a signed,
versioned inventory plus an explicit selection policy. It does not acquire a private inventory,
choose business thresholds, contact a provider, or execute a workload.

The policy supplies cohort capacity, the expected inventory denominator, mandatory coverage across
complexity, constructs, macro behavior, dependencies, data access, and validation difficulty,
permitted origins, prerequisite policy digests, dependency grouping, deterministic ordering,
validity, and accountable owner roles. There are no competition-significant defaults.

The inventory binds every candidate to its canonical workload and boundary, script identities,
entry point and complete source closure, discovery snapshot, assessment, prerequisites, origin, and
run/attempt. The selector independently reconstructs the entry point and boundary artifact inventory
from canonical discovery, compares artifact IDs, logical paths and checksums, and traverses the
canonical dependency graph from the entry point. A candidate cannot authorize a substituted file or
omit a dependency merely by recomputing its own closure, assessment, or inventory signature.
Inventory attestation, exact bytes, digests, safe paths, symlinks, duplicate identities,
secret-bearing input, denominator reconciliation, and meaningful SAS entry points are checked before
selection. Unprocessable records remain in the denominator and block qualification. Policy YAML is
loaded with duplicate-key rejection before schema and digest validation.

Selection is deterministic and records every candidate as included or excluded separately from its
eligible, blocked, pending, or denied admission state. Mandatory coverage cannot be silently relaxed.
Dependency-coupled units are kept atomic when policy requires it. Blocked representative members may
occupy planned slots only when the policy explicitly says so, and the overall result remains
non-qualified.

Canonical inventory, policy, manifest, and bounded telemetry files are published without overwrite
under the run/selection/attempt hierarchy. Reload verifies both snapshots and deterministically
replays the result. An identical retry repairs missing telemetry; changed bytes or identities are
rejected. Downstream admission reloads the canonical manifest and rechecks workload, boundary,
source-closure, run, attempt, membership, and eligibility. It never substitutes for readiness.

All lifecycle claims remain false: selection does not mean generated, executed, validated,
parity-passed, certified, human-approved, or human-assisted. Synthetic tests may produce an offline
`qualified` selection contract; that is not a Humana cohort, runtime result, or competition proof.

## Acceptance evidence

Candidate base revision: `7566e88`. The evidence below is local and synthetic. The integration commit
is the future immutable source reference; no governed Humana evidence exists in this increment.

| Criterion | Source/config revision | Exact procedure | Expected outcome | Actual outcome | Safe immutable evidence reference |
|---|---|---|---|---|---|
| HPILOT-01-AC01 | `7566e88` + candidate tree; explicit test policy | Run `test_representative_selection_is_deterministic_and_not_easy_only` and anti-cherry-pick tests | Explicit complexity, construct, macro, dependency, data-access and validation criteria drive deterministic selection | Passed locally | Integration commit pending; `tests/unit/test_pilot_selection.py` |
| HPILOT-01-AC02 | Same candidate/test fixtures | Run focused unit suite, canonical substitution/omission tests, and inspect manifest decisions | Every candidate records membership, admission, dimensions, reasons and owners; candidate-local recomputation cannot replace canonical closure evidence | Passed locally | Integration commit pending; `test_candidate_cannot_substitute_canonical_entry_artifact`, `test_candidate_cannot_omit_canonical_dependency_closure`, and manifest assertions |
| HPILOT-01-AC03 | Same candidate/test fixtures | Run anti-cherry-pick, origin, denominator, prerequisite and private-corpus tests | Easy-only fallback cannot qualify; unavailable inputs remain blockers; synthetic evidence is test-only | Passed locally; real Humana cohort unverified | Integration commit pending; focused confidence suite |
| HPILOT-01-AC04 | Same candidate/test fixtures | Run source mutation, replay/recovery, downstream admission and readiness-binding tests | Changed source/snapshots fail; restart is stable; selection cannot authorize conversion | Passed locally; live execution unverified | Integration commit pending; `tests/integration/test_pilot_readiness_binding.py` and persistence tests |
| HPILOT-01-AC05 | Same candidate/test fixtures; synthetic denominator 2 | Run representative and denominator mutation tests | Versioned inventory denominator is preserved; caller count mutation fails | Passed locally; 1,000-script inventory unverified | Integration commit pending; `test_anti_cherry_pick_and_denominator_mutations_block_or_reject` |
| HC-01 | Same candidate/test fixtures | Run manifest replay and admission tests | Result binds client, inventory, policy, workload, boundary, source closure, run and attempt | Passed locally | Integration commit pending; manifest and admission tests |
| HC-02 | Candidate tree review | Inspect `src/smf/pilot` inputs/imports | No recalled knowledge participates in selection | Not applicable: no recall consumer exists | Local review only |
| HC-03 | Candidate tree review | `git diff --name-only -- tests/corpus/workloads/public` before and after confidence suite | Public source bytes remain unchanged; selection does not transform SAS | No paths returned | Working-tree check; integration commit pending |
| HC-04 | Same candidate/test fixtures | Run secret canary, safe-path, symlink, duplicate identity, duplicate-policy-key and private-corpus isolation tests | Unsafe or ambiguous content is rejected and absent from persisted evidence | Passed locally | Integration commit pending; focused security tests and `test_policy_yaml_rejects_duplicate_keys_before_digest_validation` |
| HC-05 | Same candidate/test fixtures | Run exact commands below | Positive, negative, mutation, restart and isolation tests pass without lifecycle overclaim | 34 pilot-confidence tests passed; full repository gate pending orchestrator | Integration commit and full-gate artifact pending |

Reproduce the focused checks:

```bash
python -m pytest -q -p no:cacheprovider \
  tests/unit/test_pilot_selection.py \
  tests/integration/test_cli_pilot_selection.py \
  tests/integration/test_pilot_readiness_binding.py \
  tests/integration/test_pilot_schema_packaging.py \
  tests/unit/test_private_corpus_isolation.py
ruff format --check src/smf/pilot tests/unit/test_pilot_selection.py tests/integration/test_*pilot*.py
ruff check src/smf/pilot tests/unit/test_pilot_selection.py tests/integration/test_*pilot*.py
mypy --strict src/smf/pilot
make pilot-confidence
```

`make verify` remains required and is not claimed by this local focused evidence record. Real Humana
inventory, owner policy, prerequisites, environment execution, validation, parity, and competition
acceptance remain unverified.
