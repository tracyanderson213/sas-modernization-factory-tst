# Testing and Evidence Strategy

SMF testing is layered. A green unit-test count is engineering evidence, not proof that a SAS workload has been successfully modernized.

## Confidence ladder

```text
Level 1  Unit tests
            |
            v
Level 2  Repository integration tests
            |
            v
Level 3  Controlled discovery E2E
            |
            v
Level 4  Adversarial / torture discovery
            |
            v
Level 5  Untouched public SAS corpus
            |
            v
Level 6  Real SAS baseline execution             FUTURE
            |
            v
Level 7  Real Databricks target execution        FUTURE
            |
            v
Level 8  SAS <-> Databricks parity               FUTURE
            |
            v
Level 9  Representative Humana pilot workloads   FUTURE
```

## What exists now

### Repository gate

Run the canonical engineering gate from the activated project `.venv`:

```bash
make format
make verify
```

`make verify` runs Ruff, strict mypy, pytest, and `pip-audit` through the repository Makefile.

### Discovery confidence gates

Run:

```bash
./scripts/test-discovery-confidence.sh
```

The command separates three different forms of discovery evidence:

```text
Gate A: CONTROLLED ACCEPTANCE
Known topology -> did SMF construct the expected graph?

Gate B: ADVERSARIAL
Ugly/ambiguous inputs -> does SMF avoid false claims and fail safely?

Gate C: PUBLIC CORPUS
SAS not authored for this parser -> what can SMF defensibly discover?
```

Gate B includes negative assertions such as SAS-looking text inside quoted strings not creating fabricated lineage, unresolved dependencies remaining unresolved, and credentials not leaking into normalized evidence.

## What these tests do not prove

Current local tests do not prove:

- successful execution of source workloads on a real SAS runtime;
- successful remote execution on Databricks;
- source-to-target row, schema, aggregate, semantic, or performance parity;
- enterprise scheduler API connectivity;
- full SAS macro/runtime resolution;
- compatibility with Humana production workloads.

Those claims require stronger evidence layers and real environments. Never translate a statement such as `74 tests passed` into `74 SAS workloads migrated`.

## Failure policy

A failing adversarial or public-corpus assertion is evidence to investigate. Do not weaken an assertion merely to make a gate green. Classify the result as an implementation defect, a known unsupported construct that must remain explicit, or an invalid test expectation.
