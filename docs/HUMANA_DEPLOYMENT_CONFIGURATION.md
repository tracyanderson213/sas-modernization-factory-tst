# Humana Deployment Configuration Skeleton

## Implemented boundary

HENV-02 provides a strict, offline deployment-configuration contract. The checked-in Humana
configuration binds the reusable factory to explicit Databricks workspace, identity,
secret-provider, Unity Catalog, isolated scratch/output, source read, runtime, compute/network,
resource-limit, retention, audit, and validation-policy bindings. Required client values remain
`placeholder` or `pending`; none is inferred.

The loader rejects unknown fields and enum values, duplicate YAML keys and canonical binding IDs,
mixed client/deployment/environment identities, incomplete or escaping file scopes, symlinks,
embedded credential patterns, and active bindings without meaningful values. Its immutable snapshot
records the ordered file inventory, every raw SHA-256, the HENV-01 configuration digest, and a
bundle digest.

The HENV-01 configuration digest covers the exact bytes of `factory.yaml`, `databricks.yaml`,
`security-policy.yaml`, and `validation-policy.yaml`. The separate readiness policy digest covers
the readiness policy. Changing a covered binding invalidates previously qualified evidence.

## Offline commands

```bash
smf deployment-config init --template humana --out out/humana
smf deployment-config preflight --config out/humana/factory.yaml --json
```

Generation is idempotent for identical bytes, refuses collisions, and performs no authentication,
network request, provider construction, infrastructure mutation, or deployment.

The checked-in template exits `2` with an `unresolved` result and individual placeholder/pending
blockers. A `denied` binding produces `blocked`. All-active configuration still remains unresolved
unless `--readiness-manifest` names a replay-valid HENV-01 `READY` manifest with matching client,
deployment, environment, configuration digest, current readiness policy ID/version/digest, complete
passing prerequisite checklist, and explicit `--workload-id`, `--run-id`, and `--attempt-id` context.
The result records the consumed readiness result ID and manifest digest for reconstruction.

`preflight_qualified` is only a configuration-lifecycle claim. Workload `generated`, `executed`,
`validated`, `parity_passed`, `certified`, and `human_approved` claims stay false. Preflight neither
authorizes nor performs Databricks execution.

## Remaining activation inputs

Humana owners must provide inputs tracked by HC-REQ-02, HC-REQ-04, HC-REQ-05, and HC-REQ-07 plus
attributable HENV-01 prerequisite results. This implementation supplies no Humana endpoint,
credential, catalog/schema name, runtime, quota, retention value, validation tolerance, live
access, deployment, execution, or parity evidence.

## Acceptance evidence

Candidate base: `a367f6a`. The following is offline synthetic evidence only. Safe local test nodes are
attributable but are not immutable external evidence until the integration commit is published.
The focused command below completed with `61 passed` on 2026-09-15.

| Criterion | Source/config revision | Exact procedure | Expected outcome | Actual outcome | Safe immutable evidence reference |
|---|---|---|---|---|---|
| HENV-02-AC01 | `a367f6a` + candidate tree and packaged schema | Run focused command below; inspect `test_schema_copy_is_packaged_identically` | Schema-validated skeleton loads; schema copies match | Passed locally | Integration commit pending; local node `tests/unit/test_deployment_configuration.py::test_schema_copy_is_packaged_identically` |
| HENV-02-AC02 | `a367f6a` + candidate tree | Run checked-in skeleton, unknown-state and secret-bearing key/value tests | Only explicit placeholders or opaque references survive; credential canaries fail before hashing | Passed locally | Integration commit pending; local nodes `test_checked_in_humana_skeleton_is_valid_but_fails_closed`, `test_embedded_credentials_are_rejected_without_echo`, `test_secret_bearing_mapping_keys_are_rejected_before_hashing` |
| HENV-02-AC03 | `a367f6a` + candidate tree | Run mixed-identity, path, collision, missing-evidence and template-generation tests | Unsafe/missing inputs fail closed; generation performs no deployment | Passed locally | Integration commit pending; local file `tests/unit/test_deployment_configuration.py` |
| HENV-02-AC04 | `a367f6a` + candidate tree with generated synthetic HENV-01 manifest | Run positive, manifest-tamper, stale-policy and cross-context replay nodes | Valid all-active synthetic bundle qualifies; changed digest/policy/context cannot replay; no runtime success claims are set | Passed locally; live Humana qualification unverified | Integration commit pending; local nodes `test_all_active_synthetic_bundle_with_valid_ready_manifest_qualifies`, `test_tampered_manifest_identity_or_digest_cannot_qualify`, `test_ready_manifest_cannot_qualify_against_stale_readiness_policy`, `test_ready_manifest_cannot_replay_across_preflight_context` |
| HC-01 | `a367f6a` + candidate tree | Inspect qualified result and run HENV-02-AC04 tests | Result binds client/deployment/environment, workload/run/attempt, configuration and current policy, plus consumed result/manifest digest | Passed locally | Integration commit pending; `DeploymentPreflightResult.readiness_evidence` and HENV-02-AC04 nodes |
| HC-02 | Candidate tree | Review deployment module inputs/imports | No recalled knowledge participates; current config and manifest are authoritative | Not applicable: this path has no recall consumer | Local review of `src/smf/deployment/`; no external artifact |
| HC-03 | Candidate tree | `git diff --name-only -- tests/corpus` | Public corpus source is untouched; conversion/validation semantics remain outside this item | No paths returned | Working-tree inspection only; immutable reference pending integration commit |
| HC-04 | `a367f6a` + candidate tree | Run secret-key/value, traversal, symlink and mixed-identity nodes | Unsafe content is rejected without echo or hashing into durable identity | Passed locally | Integration commit pending; named HENV-02 security nodes above |
| HC-05 | `a367f6a` + candidate tree | Run exact focused command below | Positive, negative, mutation, idempotency and replay evidence passes; qualification remains distinct from execution/parity | 61 focused tests passed; full `make verify` pending orchestrator rerun | Integration commit and full-gate artifact pending; live environment evidence unavailable |

Reproduce the focused evidence with:

```bash
python -m pytest -p no:cacheprovider tests/unit/test_deployment_configuration.py \
  tests/unit/test_readiness_conversion_guard.py \
  tests/integration/test_readiness_schema_packaging.py -q
```

Focused formatting/lint procedure: `ruff format --check` and `ruff check` over
`src/smf/deployment`, `src/smf/cli/main.py`, and the three focused test files. Focused type procedure:
`mypy --strict src/smf/deployment src/smf/cli/main.py`.

The orchestrator must still run `make verify`. This document is not a live-environment attestation,
launch approval, Databricks execution result, or parity claim.
