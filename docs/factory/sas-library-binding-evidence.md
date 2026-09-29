# BASE-06 acceptance evidence

This matrix covers the bounded offline BASE-06 implementation. It is candidate
evidence for independent review, not a Humana runtime, readiness, migration, or
parity claim. The source revision is the review candidate based on
`075d16897710dbffe9c8e913e80a0b80ad1238f9`; the final candidate commit and tree
must be recorded by the integration workflow.

| Criterion | Procedure | Expected and observed result | Evidence |
|---|---|---|---|
| BASE-06-AC01 | Run focused tests for documented literal forms and source locations | Supported assignments produce occurrence-bound logical bindings; path existence and authorization remain false | `tests/unit/test_base06_library_binding.py::test_documented_literal_forms_are_source_located_without_path_authority` |
| BASE-06-AC02 | Run dynamic, unsupported-engine, concatenated-path, and governed-runtime tests | Literal forms are documented; unsupported/dynamic forms expose blockers; only request-bound runtime evidence selects an occurrence | focused BASE-06 suite and `docs/factory/sas-library-binding-contract.md` |
| BASE-06-AC03 | Run comment/quote, reassignment, clear, and missing-macro tests | Hidden tokens are excluded; reassignment is ambiguous; clear remains cleared; missing macro remains dynamic | focused BASE-06 suite |
| BASE-06-AC04 | Inspect result bindings and prohibited claims | Source, workload, policy, run, attempt, occurrences and immutable result identity are retained; execution/readiness/parity claims remain false | schema validation and deterministic-result tests |
| HC-01 | Compare two evaluations and validate the packaged schema | Stable result/projection identities bind current inputs and policy | deterministic and schema-packaging tests |
| HC-02 | Inspect contract dependencies | No memory or recalled advice participates in a binding decision | `src/smf/library_binding/engine.py` |
| HC-03 | Inspect emitted claims | Static SAS binding classification is separated from execution and target generation | focused BASE-06 suite |
| HC-04 | Run protected-data canary, signed authority/revision/freshness, and cross-boundary evidence mutation tests | Unsafe persisted fields are rejected without echo; unsigned, stale, future, wrong-revision and cross-workload/policy/run evidence is rejected | focused BASE-06 suite |
| HC-05 | Run immutable publication recomputation, replay, nested-schema, and mutation tests | Prepared evidence is recomputed before first write; same bytes replay safely; changed or structurally extended bytes fail closed | focused BASE-06 suite |

Reproducible commands:

```text
PYTHONPATH=src .venv/bin/python -m pytest tests/unit/test_base06_library_binding.py tests/integration/test_library_binding_schema_packaging.py
.venv/bin/python -m ruff check src/smf/library_binding tests/unit/test_base06_library_binding.py tests/integration/test_library_binding_schema_packaging.py
.venv/bin/python -m mypy src/smf/library_binding
```

The shared repository virtual environment is used read-only. The tests use only
synthetic in-memory source and local temporary evidence roots. No SAS, Humana,
Azure, Databricks, Vault, AI Gateway, or external provider is contacted.
