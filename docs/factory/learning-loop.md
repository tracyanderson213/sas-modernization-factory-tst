# Factory Learning Loop

## Objective

Human remediation should create reusable factory capability whenever the resolved issue represents a recurring pattern.

## Flow

```text
Exception
   |
   v
Engineer Resolution
   |
   v
Pattern Analysis
   |
   +---- One-Off ----> Close
   |
 Reusable
   |
   v
Transformation Rule / Validation Pattern
   |
   v
Regression Test
   |
   v
Registry Update
   |
   v
Factory Release
```

## Rule Promotion Criteria

A human resolution should become a deterministic rule when:

- the source pattern can be recognized reliably
- the intended target behavior can be defined deterministically
- tests can establish correctness
- the pattern is likely to recur
- the rule does not depend on hidden workload-specific context
