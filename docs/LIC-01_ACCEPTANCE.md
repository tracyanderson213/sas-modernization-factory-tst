# LIC-01 Offline Compliance Contract

## Bounded result

This increment implements offline, non-fetching contract mechanics for license, NOTICE, SBOM,
provenance, UPQ-01, SEC-03, advisory, finding, exception, expiry, and authority evidence. It does
not approve a real package, wheel, JAR, native component, vulnerability exception, Humana
distribution profile, deployment, or lifecycle transition.

The current SEC-03 source is intentionally unresolved. Its AC01-AC03 scope requires SBOM and
dependency scanning, while its reconciled competition slice describes baseline/snapshot/mapping
acquisition. A policy containing both current acceptance digests produces
`ambiguous` / `sec03_acceptance_contract_inconsistent`; SEC-03 Project completion cannot replace
the exact signed acceptance evidence.

## Acceptance map

| Gate | Implementation and evidence | Disposition |
|---|---|---|
| LIC-01-AC01 | `smf.compliance` strict policy/evidence/result/projection contracts bind licenses, NOTICE files, SBOM, provenance, vulnerabilities and both prerequisites | Offline mechanics implemented; real acceptance blocked |
| LIC-01-AC02 / HC-01 | Stable bundle/result/decision identities bind client, workload, source digest, run, attempt, evaluation time, policy, profile, resolution, installed environment, SBOM, UPQ-01, SEC-03 and signed trust domains. Each signed legal record additionally binds component ID, version, artifact type/digest, source revision and UPQ-01 result. | Synthetic tests only |
| LIC-01-AC03 / HC-05 | Closed enums/schemas; duplicate, mutation, unsupported status, empty resolution, default-deny license, unavailable scanner, denial/pending, mismatch, immutable retry and signed scan-time freshness tests | Fail closed |
| LIC-01-AC04 | Canonical-first immutable publication, deterministic replay, non-authorizing projection, derivative recovery, conflict rejection and workload-scoped paths | Contract mechanics implemented; dependency exit evidence unresolved |
| HC-02 | Component provenance retains source revision, artifact digest and exact UPQ-01 result digest | Implemented mechanically |
| HC-03 | Resolution, installed environment and SBOM component sets/digests must match exactly; no filename or generated-only inference | Implemented mechanically |
| HC-04 | Client boundary, safe identities/paths, protected-data rejection and six distinct signed trust domains | Synthetic tests only |

## Durable-pattern review

- Optional approval booleans and unknown fields are rejected; legal, scanner, prerequisite,
  exception, collector and evaluator evidence use distinct policy-trusted keys.
- Empty resolution cannot pass. Duplicate/case-ambiguous components, advisories, findings,
  exceptions and NOTICE identities fail closed. Component IDs are canonical across versions and
  artifact types, so duplicate IDs cannot hide an unlicensed artifact behind dictionary collapse;
  NOTICE evidence cannot reference a component outside the qualified resolution.
- The signed evidence bundle and reconstructed digests close mutable-input substitution. Signed
  legal evidence is reconciled to the exact resolved artifact tuple and provenance revision. Signed
  scanner time, rather than a newer collector wrapper time, controls scan freshness; future-dated
  scans are ambiguous and the exact maximum-age boundary remains valid. Vulnerability exceptions
  must remain unexpired at decision time, not merely at collection time. Canonical publication
  independently reconstructs the complete decision before accepting a signed result.
- `blocked`, `pending`, `denied`, `failed`, `ambiguous`, `incompatible`, `stale`, and
  `unavailable_scanner` remain distinct. Real evidence is always blocked by this authorized
  increment, and every lifecycle/approval claim is fixed false.
- Publication is confined to run/workload/attempt paths. Identical retry recovers a missing
  projection without changing the canonical decision; conflicting canonical bytes fail.

## Verification

Run:

```bash
python -m pytest -q tests/unit/test_license_compliance.py \
  tests/integration/test_license_compliance_schema_packaging.py
make verify
git diff --check
```

In the restricted developer environment, the focused suite, full suite, Ruff, mypy and diff checks
must pass. If `pip-audit` cannot reach its advisory source, `make verify` remains blocked and no
vulnerability-clean claim may be made.

Current repair run (2026-09-19): the focused compliance suite passed 30 tests; repository Ruff and
mypy passed; all 1,880 tests passed; schema-bearing wheel construction and package inspection
passed; and `git diff --check` passed. `make verify` then stopped at the mandatory `pip-audit` step
because the restricted environment could not resolve `pypi.org`. No dependency-audit result or
complete-gate claim is recorded. Rerun the unchanged gate in an authorized network-enabled
environment, or with a governed freshness-bound offline advisory database, before acceptance.

No dependency download, installation, network scan, Legal/Security approval, or client execution is
part of this contract. The independent Reviewer must determine whether the bounded mechanics are
sufficient; the missing Architect artifact and unresolved SEC-03 acceptance source remain explicit.
