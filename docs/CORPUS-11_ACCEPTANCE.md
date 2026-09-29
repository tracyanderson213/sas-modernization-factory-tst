# CORPUS-11 Governed Binary Fixture Qualification

## Bounded result

This increment implements an offline fixture qualification contract. It distinguishes licensed,
evaluation-only, customer-controlled, and prohibited SAS binary assets; reconciles optional local
bytes to signed manifest identity; and publishes signed, immutable, workload-scoped results.

It does not acquire a binary, accept a license, authorize redistribution or customer access,
qualify a real upstream asset, validate a reader, execute a migration, prove parity, or establish
Humana or production readiness. The included fixtures are synthetic contract bytes, not SAS data.

## Acceptance map

| Gate | Evidence | Bounded disposition |
|---|---|---|
| CORPUS-11-AC01 | Closed `asset_class` enum and purpose-specific rules for all four required classes | Contract mechanics only |
| CORPUS-11-AC02 / HC-01 | Independently signed immutable policy, signed manifest, signed UPQ-01/LIC-01 receipts, result signature, exact source/run/attempt and byte bindings | Reconstructable synthetic evidence |
| CORPUS-11-AC03 / HC-05 | Missing bytes, stale evidence, prohibited assets, customer authority, mutation, duplicate-key, collision and cross-workload tests | Fail closed |
| CORPUS-11-AC04 / HC-02 | Producer/version, SAS artifact/version, source revision, license evidence, provenance digest, authority and prerequisite result digests retained | No filename-only qualification |
| HC-03 | Local bytes are independently length/digest reconciled; all reader, migration, parity and readiness claims remain false | No execution claim |
| HC-04 | Root-confined no-follow reads, strict schemas, key-ID and Ed25519-material trust-domain separation, and workload-scoped immutable paths | Synthetic/local only |

## Result semantics

The closed result enum is exactly `qualified_contract`, `blocked`, `denied`, `incompatible`, and
`stale`. `qualified_contract` means only that the declared fixture-use contract passed. It is not legal
approval and the result schema fixes customer-access, redistribution, reader-validation,
migration, parity, and production-readiness claims to false. Inputs outside the closed schemas are
rejected; no separate `ambiguous` or `unsupported` result is claimed. No exception or implicit
approval is available.

## Verification

```bash
python -m pytest -q tests/unit/test_corpus11_fixture_qualification.py \
  tests/integration/test_corpus11_schema_packaging.py
python -m ruff check src/smf/corpus tests/unit/test_corpus11_fixture_qualification.py \
  tests/integration/test_corpus11_schema_packaging.py
python -m ruff format --check src/smf/corpus tests/unit/test_corpus11_fixture_qualification.py \
  tests/integration/test_corpus11_schema_packaging.py
python -m mypy --strict src/smf/corpus/fixture_qualification.py
git diff --check
```

An independent Reviewer must confirm this bounded disposition before any local commit. Real fixture
qualification, customer authority, license approval, downloads, reader execution, or lifecycle
completion require their own evidence and authorization.
