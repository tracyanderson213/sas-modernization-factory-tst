# Validation Engine v1

## Purpose

Validation Engine v1 establishes deterministic evidence between conversion and
promotion.

A generated artifact is not considered a successful migration merely because a
conversion provider produced code.

## v1 validation layers

### Static artifact checks

- generated artifact is non-empty
- generated PySpark/Python parses
- generated Spark SQL has recognizable SQL structure
- obvious SAS-only syntax does not remain

### Assessment risk gate

The validation engine consumes the Assessment Engine result.

Advanced procedures, unsupported constructs, and assessment risk factors
increase review requirements.

### Dependency traceability

Input and output datasets discovered during assessment are compared with the
generated target artifact.

This is a traceability heuristic, not semantic proof. Missing textual
traceability produces a warning rather than an automatic failure.

### Evidence-based confidence

Each deterministic check contributes weighted evidence.

- pass: full weight
- warning: half weight
- fail: zero weight

A blocking failure forces validation status `failed`.

Advanced or unsupported source behavior forces `human_review` even when the
generated artifact is syntactically valid.

## Output

Every validation run produces:

```text
out/<workload>/validation/validation.manifest.json
```

The manifest contains:

- source artifact
- generated artifact
- target
- validation status
- confidence
- human-review requirement
- individual checks
- evidence
- warnings
- source assessment

## What v1 does not claim

Validation Engine v1 does not prove data parity or business semantic parity.

Those become subsequent validation layers:

1. static validation
2. execution validation
3. structural/data parity
4. business/semantic parity
5. performance validation

For advanced Humana workloads, statistical or business equivalence must not be
inferred from syntax validation alone.
