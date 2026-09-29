# Assessment Engine v1

Assessment Engine v1 establishes the first structured migration-factory decision point.

## Responsibilities

The engine:

- inventories SAS constructs
- extracts basic dataset dependencies
- identifies `%INCLUDE` dependencies
- identifies macro definitions and custom macro invocations
- calculates an explainable complexity score
- classifies workload complexity
- recommends an automation route
- recommends a validation level
- identifies risk factors
- identifies currently unsupported advanced procedures
- emits JSON that validates against `schemas/assessment.schema.json`

## CLI

Human-readable assessment:

```bash
smf assess examples/simple/example.sas
```

Machine-readable assessment:

```bash
smf assess examples/simple/example.sas --json
```

Explainable score:

```bash
smf assess examples/simple/example.sas --explain
```

## Current Limitation

v1 is intentionally a static-analysis engine. It does not yet perform full SAS parsing or macro expansion. Its output is designed to be deterministic, testable, and sufficient to drive the next factory stage.

The canonical discovery `macro_analysis` is the decision-authoritative macro dependency
contract. Assessment may use its classifications for complexity and routing, but must not
reinterpret a unique static definition as SAS macro execution or override an unresolved state.

The conversion engine and future parser integrations should consume the assessment contract rather than bypassing it.

## Governed workload complexity

AD-05 adds a separate workload-level contract under `smf.assessment`. Unlike the legacy per-file
score, it resolves one canonical workload boundary, re-hashes the complete eligible source closure,
checks dependency and macro-analysis bindings, and applies one digest-bound policy. It exposes every
counted observation, unknown dimension, cap, sensitivity range, tier, and non-authorizing claim.

Required unknown dimensions yield an `unknown` tier. Repeated observations are deduplicated by a
canonical identity and duplicate source, graph, macro, or boundary identities are rejected. Signed
results may be consumed by pilot selection only when the exact policy digest is allowlisted and all
candidate projections match. See [WORKLOAD_COMPLEXITY.md](WORKLOAD_COMPLEXITY.md).
