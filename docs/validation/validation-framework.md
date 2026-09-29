# Validation Framework

## Principle

Successful execution is necessary but not sufficient for migration acceptance.

## Validation Levels

### Level 1: Compilation
Does the generated artifact compile?

### Level 2: Execution
Does the converted workload execute successfully?

### Level 3: Structural Parity
Examples:
- schema
- column types
- row counts
- keys
- null behavior

### Level 4: Data Parity
Examples:
- aggregates
- distributions
- checksums
- sampled records
- calculated values

### Level 5: Semantic Parity
Examples:
- business measures
- population membership
- financial totals
- risk scores
- statistical results
- model outputs
- coefficients
- confidence intervals
- business KPIs

Validation policy should be selected from workload risk and behavior rather than applying the same level to every workload.
