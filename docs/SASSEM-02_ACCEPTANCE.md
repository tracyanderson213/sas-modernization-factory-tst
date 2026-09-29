# SASSEM-02 acceptance evidence

## Scope and status

This increment implements an offline, deterministic compatibility-policy slice. It does not attest
SAS or Databricks execution, Humana validation, parity, certification, owner approval, or production
readiness. Ordinary, special, and character missing behavior remains explicit and unresolved. Only
exact bounded character-to-numeric coercion between self-typed literals in supported binary
comparisons can generate output, and only when the value is exactly representable as a SAS
IEEE-754 numeric. Implicit arithmetic and other unproved coercion contexts remain unsupported.

## Acceptance matrix

| Criterion | Evidence | Expected and observed result |
|---|---|---|
| SASSEM-02-AC01 | `tests/unit/test_sas_value_semantics.py`; strict policy schemas and checked-in example | Explicit policy and deterministic positive/negative tests pass. |
| SASSEM-02-AC02 | missing-category, exact-coercion, numeric-boundary and arithmetic tests | Categories, byte spans and token digests are preserved; non-representable or operation-unproved behavior is unresolved without output. |
| SASSEM-02-AC03 | malformed/lossy, `BETWEEN`, concatenation and attestation-field mutation tests | Malformed strings, special missing categories, unsupported coercion forms, and caller assertions cannot become null-equivalence or success. |
| SASSEM-02-AC04 | readiness conversion guard and this matrix | Source/target policy bindings, safe mismatch evidence, restart recovery and attempt isolation are implemented; live owner disposition remains unavailable and unverified. |
| HC-01 | plan, rule application and `value-mappings.json` replay tests | Evidence binds client/deployment/environment, workload, source artifact/digest/span, run, attempt, plan, policy, strategy, registry and generated digest. |
| HC-02 | no recall dependency in implementation or acceptance path | Not applicable: this bounded classifier consumes no cached or recalled knowledge and adds no recall subsystem. |
| HC-03 | unsupported missing, arithmetic, non-binary coercion and schema-dependent tests | Source bytes remain authoritative; target output exists only for the qualified comparison subset. |
| HC-04 | policy/source secret-canary rejection and safe identifiers inherited from conversion admission | Protected values cannot be persisted through source or policy; existing protected-path and authority controls are unchanged. |
| HC-05 | focused tests, conversion guard, telemetry assertions and required gates | Blocked/unsupported/generated/executed/validated/parity/human states remain distinct; generation does not imply execution or parity. |

## Reproducible commands

```text
pytest -q tests/unit/test_sas_value_semantics.py
pytest -q tests/unit/test_conversion_rule_registry.py
pytest -q tests/unit/test_readiness_conversion_guard.py
pytest -q tests/unit/test_corpus_semantic_oracle.py
pytest -q tests/unit/test_semantic_corpus.py
pytest -q tests/integration/test_cli_conversion_validation.py
./scripts/test-corpus-confidence.sh
make verify
```

The qualified registry digest is
`a4fb771a44f65f0a0c7efdfc1143b67aa8889847391da0262c0f848a14ec34df`; the example policy digest is
`2b44972f3bdbbccc5cd6edda3dbba78e9bd1891b49959a323194be1b973064ea`. No immutable source-revision
reference exists until the human-controlled commit. The working-tree paths and gate runs are
reproducible evidence, but are not a commit, live runtime result, or human integration approval.

## Observed local gate results

- Final focused affected suites: `178 passed`.
- Corpus confidence: `72 passed`.
- `make verify`: Ruff passed, mypy passed over 191 source files, and pytest passed all `1705` tests.
  The final `pip_audit` step could not query PyPI because DNS/network access was unavailable. The
  security audit therefore remains unverified; it was not skipped, weakened, or relabeled as a pass.

## Remaining blockers

- Humana source/target representation for ordinary and special missing values.
- Authoritative source schemas for variable and column coercion.
- Runtime conversion-note/error policy, output keys, tolerances, and business rules.
- Trusted SAS baseline, authorized Databricks execution, selected workload cohort, and named owner
  disposition.
