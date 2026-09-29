# AIREP-01 bounded AI repair controller acceptance

AIREP-01 composes the canonical deterministic conversion package with the offline AI Gateway
preflight contract. Deterministic conversion always runs first. A packaged deterministic result is
selected without evaluating the gateway boundary. Only an explicit deterministic non-success can
enter the bounded gateway branch.

## Contract boundaries

- The controller verifies the current immutable CV-04 package and binds its source, generated
  output, provider revision, provider license, runtime evidence and content digest.
- The fallback branch re-evaluates the current AIGW-01 configuration and deployment snapshot. It
  permits at most three synthetic contract attempts and links each attempt to the prior attempt
  digest. A non-retryable or uncertain outcome stops the chain.
- The shipped gateway transport is an in-process deterministic mock. It cannot contact a provider,
  return repair bytes, authorize a repair or satisfy external execution evidence. Consequently every
  fallback result remains blocked pending real gateway authority and later execution/revalidation.
- Publication replays both dependency contracts, rejects stale or mutated source/configuration,
  derives strict telemetry from the canonical result and publishes without overwrite under the
  run/workload/attempt evidence boundary.

## Acceptance evidence

| Criterion | Evidence |
| --- | --- |
| AIREP-01-AC01 | `test_deterministic_success_never_crosses_gateway_boundary` proves deterministic-first selection; bounded fallback and stop-policy tests prove the controller branch. |
| AIREP-01-AC02 / HC-01 | Result identity binds client, deployment, environment, workload, source artifact, run, attempt, controller policy, exact dependency result digests and implementation manifest. |
| AIREP-01-AC03 / HC-05 | Attempt-limit, identity, root, protected-value, mutation, current-input replay and two-workload isolation tests fail closed. |
| HC-02 | The verified CV-04 projection preserves the exact upstream revision and Apache-2.0 license digest. |
| HC-03 | No repair is generated, executed, reconciled or accepted by this offline increment. Deterministic generated output remains separately reviewable. |
| HC-04 | Dependency request admission rejects protected identities; the controller opens no network socket and persists no source or provider payload. |

## Prohibited claims

This increment does not implement live AI Gateway transport, contact Anthropic or another provider,
generate or accept repair code, execute a repair, perform reconciliation, prove SAS equivalence,
access Humana systems, or establish migration, production or readiness status. A synthetic
`success` proves only the deterministic mock-response contract; it is not provider evidence.
