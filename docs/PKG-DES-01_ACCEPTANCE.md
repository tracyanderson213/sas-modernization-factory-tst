# PKG-DES-01 Offline Portability Design Gate

## Bounded result

This increment implements strict, offline contract mechanics for the runtime matrix, dependency
lock, source-only eligibility preflight and offline artifact intake plan. It does not download,
install, compile or qualify dependencies and does not replace `PKG-QUAL-01` final qualification.

Source-only eligibility requires exact evidence that every locked component is present at the
required version, platform, runtime-matrix digest and SHA-256 with an authority binding. Governed
evaluation time and maximum age independently classify future or stale observations. A missing, incompatible,
unapproved, stale or ambiguous component blocks and names its required offline artifact. An offline
artifact result names its filename, kind, version, full OS/architecture/Python/JVM/Scala/Spark/DBR
coordinates, SHA-256, source revision, license, NOTICE, SBOM, provenance, vulnerability result and
intake state.
An absent plan is recorded as `missing_offline_artifact_plan:<component>` without creating a
partial descriptor, but that diagnostic result is non-publishable and fails verification and
loading. Closed schemas reject incomplete plan entries, and lock-mismatched entries are blocked
and excluded from the structured required-artifact projection.

## Evidence and replay

The packaged schemas reject unknown fields and open-ended states. The loader rejects duplicate JSON
keys, symlinks, non-files, traversal, protected values and unsafe identities. Matrix, dependency
lock and artifact-plan digests are reconstructed before evaluation. Immutable result publication is
confined to `runs/<run>/workloads/<workload>/attempts/<attempt>/` and every read replays the exact
decision against the original contract.

Only synthetic fixtures can return `contract_pass`. Every real contract remains blocked in this
increment, and all installation, distribution, runtime, final-bundle and Humana-readiness claims
are fixed false.

## Verification

```bash
python -m pytest -q tests/unit/test_portability_design.py \
  tests/integration/test_portability_schema_packaging.py
python -m ruff check src/smf/portability tests/unit/test_portability_design.py \
  tests/integration/test_portability_schema_packaging.py
python -m ruff format --check src/smf/portability tests/unit/test_portability_design.py \
  tests/integration/test_portability_schema_packaging.py
python -m mypy src/smf/portability
git diff --check
```

No test fixture authorizes a real component, license, vulnerability disposition, intake decision,
runtime, environment, deployment, migration, reconciliation, readiness or parity claim.
