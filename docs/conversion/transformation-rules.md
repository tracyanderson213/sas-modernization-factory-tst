# Transformation Rules

## Rule Requirements

Each deterministic transformation rule should define:

- rule ID
- version
- source pattern
- applicability conditions
- target pattern
- confidence contribution
- provenance metadata
- known limitations
- test fixtures

## Example Naming

```text
SAS.SQL.SELECT.001
SAS.SQL.JOIN.001
SAS.DATASTEP.FILTER.001
SAS.MACRO.PARAMETER.001
```

## Rule Behavior

Rules must fail closed when their applicability conditions are not met. A rule should not claim a construct it only partially understands.
