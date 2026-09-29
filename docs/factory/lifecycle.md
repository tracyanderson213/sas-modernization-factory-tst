# Factory Lifecycle

## Target-state canonical states

This section describes the intended production lifecycle. It is not a claim that every transition
is currently implemented by an end-to-end orchestrator. See `../IMPLEMENTATION_STATUS.md` for the
current capability boundary.

A workload progresses through controlled states:

1. discovered
2. ingested
3. assessing
4. assessed
5. readiness qualification (`READY`, `BLOCKED`, `NEEDS_EVIDENCE`, `UNSUPPORTED`, or `HUMAN_REQUIRED`)
6. converting
7. converted
8. validating
9. validated or validation_failed
10. human_review when required
11. approved
12. deployed

A workload may also enter `failed` when processing cannot continue.

## Currently implemented local transitions

The current CLI exposes discovery, assessment, readiness qualification, readiness-gated conversion,
static validation, local validation execution, and supplied-snapshot structural parity. It does not
yet expose a single `smf run` command or durable production transitions through approval, deployment,
certification, and rollback.

## State Transition Rules

- State transitions must be durable and auditable.
- Failed tasks should be restartable without recreating the workload.
- Remediation attempts must not erase prior evidence.
- Human review can override routing but should capture the reason.
- Deployment is prohibited until required validation and approval policies are satisfied.
- Conversion always requires an authoritative deployment binding and a deterministically
  replay-validated `READY` manifest matching workload, run, attempt, policy, source artifact, and
  exact source bytes. Decision-bearing evidence is cryptographically verified against the binding's
  public keys before it can authorize `READY`.
