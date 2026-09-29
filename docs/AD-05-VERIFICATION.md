# AD-05 verification record

Status: reusable offline implementation verified; Humana activation and competition proof blocked.

Repository base revision: `b6580eea8ae7a05429bd563a9b4f6f16fe95fb55`. These changes are intentionally
uncommitted. No issue, Project field, approval, deployment, or completion state was changed.

## Commands and results

| Command | Actual result |
|---|---|
| `python -m pytest tests/unit/test_workload_complexity.py -q` | 16 passed |
| Affected workload/pilot unit and integration suites | 42 passed |
| `make pilot-confidence` | 36 passed |
| `make verify` | Ruff passed; mypy passed; all 1,209 tests passed; `pip-audit` could not resolve `pypi.org` in this network-restricted environment |

## Acceptance matrix

| Criterion | Evidence and result |
|---|---|
| AD-05-AC01 | Versioned policy/result schemas, known-vector replay, weight mutation, and exact macro inventory checksum/source-span mutation tests pass. Humana weights remain pending and zero. |
| AD-05-AC02 | Results expose observations, unknowns, sensitivity, and fixed false authorization claims. Pilot/readiness tests preserve independence. |
| AD-05-AC03 | Required-unknown and duplicate-identity tests pass; unknown never becomes simple and duplicate evidence cannot add points. |
| AD-05-AC04 | Exact binding, mutation, boundary escape, append-only recovery, pre-publication byte recheck, and two-candidate isolation tests pass for synthetic/offline operation. |
| AD-05-AC05 | Deterministic estate reporting accepts only schema-valid, digest-valid, policy-bound, signed, semantically reconstructed results whose source bytes still match. Official distribution, source-owner cohort review, and ten-week proof remain blocked on Humana inputs and approvals. |
| HC-01 | Cross-policy signature replay, stale macro-source evidence, and pilot client/discovery/workload/boundary/source/run/attempt binding tests pass. |
| HC-02 | Advisory recall changes the discovery digest but cannot change score or tier. No recall infrastructure is added. |
| HC-03 | SAS macro evidence and format-catalog features remain distinct and target output is not an oracle. Runtime macro expansion and parity remain outside scope. |
| HC-04 | Protected identity/source/snapshot, traversal, symlink, remote reference, and secret canary tests pass. |
| HC-05 | Positive, negative, enum, mutation, unsigned, self-authored-result, unknown, denied/pending/expired, recovery, and projection-forgery tests pass. Dependency audit remains blocked only by network resolution. |

## Safe immutable references

- `tests/unit/test_workload_complexity.py`: SHA-256 `823a82c84e921dd0b196a314c1f18a3fd6792ab503bce72a069c51c7bf55ec8b`
- `tests/unit/test_pilot_selection.py`: SHA-256 `686d577459c93b0d5e2d75701bae6613ec746410fe538fa21856160ed556c91a`
- `tests/integration/test_cli_pilot_selection.py`: SHA-256 `3c8e628a9179ef01f77e7ce792c88938b5bf3ada185eb7b9fab5f42621bf7eff`
- `tests/integration/test_pilot_readiness_binding.py`: SHA-256 `e3a24c87b7cb4c34c3d9dd7025c7f360dbcb6e4370260a82a5f61ae1e3e69cc9`
- `schemas/workload-complexity-policy.schema.json`: SHA-256 `59252f7c0284adad1ade4106789e94596a838b4e025a542403a3148365772b95`
- `schemas/workload-complexity-result.schema.json`: SHA-256 `c9bd37520ae4e5d7330049c120e25e80bfa0a2d9248161b53e95e954e70f335d`
- `deployments/humana/complexity.yaml`: SHA-256 `e96e51825f405998fcece40e93b25e83a67308fb259884acea8545b3b35ae5e6`
