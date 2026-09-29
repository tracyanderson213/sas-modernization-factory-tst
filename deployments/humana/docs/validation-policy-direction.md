# Humana Validation Policy Direction

## Principle

Automation percentage must be based on successful migration lifecycle completion,
not code-generation percentage.

A workload should count toward straight-through automation only when it has
completed the required validation policy without manual code rewrite.

## Initial policy direction

### Simple workloads

Expected minimum:

- static validation
- execution validation
- structural parity
- row/data parity

### Moderate workloads

Expected minimum:

- static validation
- execution validation
- enhanced data parity
- targeted semantic assertions

### Complex workloads

Expected minimum:

- enhanced validation
- explicit owner acceptance criteria
- human review where risk remains

### Highly complex workloads

Expected minimum:

- human-supervised conversion
- semantic validation
- advanced statistical/business equivalence where applicable
- explicit approval before promotion

The final policy must be aligned with Humana engineering, security, governance,
data ownership, and regulatory requirements before production use.
