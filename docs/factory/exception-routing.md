# Exception Routing

## Exception Categories

- parse failure
- unsupported SAS construct
- dependency resolution failure
- conversion failure
- compile failure
- runtime failure
- structural parity failure
- data parity failure
- semantic parity failure
- performance regression
- policy violation

## Routing Principle

Exceptions should include enough context that an engineer does not need to rediscover the workload.

An exception package should contain:

- workload identity
- source artifact references
- assessment
- IR
- generated target artifacts
- applied rules
- AI-assisted changes
- execution logs
- validation failures
- remediation attempts
- recommended next action
