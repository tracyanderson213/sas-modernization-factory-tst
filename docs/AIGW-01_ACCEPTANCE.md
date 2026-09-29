# AIGW-01 acceptance evidence

## Bounded disposition

AIGW-01 implements a provider-neutral, offline configuration and preflight evidence contract for
the Humana AI Gateway boundary. It ships no operational HTTP transport. The CLI validates exact
configuration and deployment bytes, binds the packaged implementation, publishes immutable result
and telemetry artifacts, returns exit `2`, and leaves every connectivity, provider invocation,
repair, readiness, and migration claim false.

The only executable transport is an in-process deterministic mock with an explicit
`synthetic_contract` evidence class. No mock outcome can authorize external execution or satisfy
connectivity, repair, reconciliation, parity, or readiness acceptance.

## Acceptance mapping

| Criterion | Implementation | Test evidence |
|---|---|---|
| AIGW-01-AC01 | `smf.ai_gateway` strict configuration loader, synthetic transport boundary, and `smf ai-gateway preflight`; direct Anthropic/OpenAI endpoints and arbitrary transports are rejected. | `tests/unit/test_ai_gateway.py`; `tests/integration/test_migration_cli.py` |
| AIGW-01-AC02 / HC-01 | Result identity binds client, deployment, environment, workload, run, attempt, exact configuration bytes, factory bundle, implementation manifest/upstream revision, source non-applicability, and canonical output reference. | offline-preflight, immutable-publication, retry/recovery, and mutation tests |
| AIGW-01-AC03 / HC-04 / HC-05 | Duplicate/unknown fields, credential material, unsafe files, direct providers, stale authority, incompatible TLS/auth/timeout/retry state, and modified evidence fail closed. Synthetic denial, throttling, content filtering, malformed response, missing correlation, disconnect, and uncertain timeout remain distinct. | negative/adversarial parameterization plus every `MockGatewayScenario` |
| HC-02 | Packaged implementation files and schemas are content-addressed in every result; public and packaged schemas are byte-identical. | schema parity checks and result replay verification |
| HC-03 / AC04 | No generated repair is accepted and all execution, validation, reconciliation, parity, and migration-readiness claims remain schema-fixed false. Source artifacts are explicitly not applicable to configuration preflight. | result/telemetry schemas and offline-preflight assertions |

## External evidence still required

Humana must provide and separately authorize the gateway origin, route, model alias/version, exact
headers, Entra or Vault authentication references, audience, CA/mTLS references, quotas,
correlation behavior, content-filter behavior, and a non-sensitive probe. A later authorized
operational preflight must prove DNS, TLS, authentication, protocol/schema, filters, quotas, and
correlation behavior. Until then `live_gateway_authority_missing` remains blocking.

## Prohibited claims

This increment does not establish live AI Gateway connectivity, direct Anthropic access, credential
resolution, provider invocation, repair correctness, SAS equivalence, Humana validation, migration
readiness, data reconciliation, semantic parity, certification, promotion, or production readiness.
