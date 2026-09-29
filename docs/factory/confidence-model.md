# Confidence Model

## Principle

Confidence is derived from evidence. It is not an LLM opinion.

## Candidate Signals

- parser coverage
- recognized SAS constructs
- deterministic rule coverage
- unsupported constructs
- percentage of AI-assisted transformations
- compilation result
- execution result
- schema parity
- row-count parity
- data parity
- semantic validation
- prior success rate of applied rules
- remediation history

## Routing

Example initial routing:

- High confidence: deterministic conversion plus standard validation
- Medium confidence: AI-assisted conversion plus enhanced validation
- Low confidence: human-supervised conversion

Thresholds should be configuration, not hard-coded constants.
