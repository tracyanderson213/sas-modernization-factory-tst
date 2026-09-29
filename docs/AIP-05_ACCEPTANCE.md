# AIP-05 prompt and model governance acceptance

This bounded increment implements offline, provider-neutral prompt/model governance mechanics. It
binds exact prompt-template bytes, an opaque AI Gateway route and model alias/version, context
budgets, evidence-selection rules, a synthetic evaluation receipt and workload/run/attempt identity.
It integrates with the existing AIP-01 request contract; it does not create another provider path.

## Acceptance evidence

| Criterion | Evidence | Result |
| --- | --- | --- |
| AIP-05-AC01 | `test_contract_binds_prompt_model_budget_evaluation_without_live_claims` | Versioned policy, template, gateway/model binding, budgets and evaluation bytes are exact and replayable. |
| AIP-05-AC02 | `test_existing_provider_request_requires_exact_governance_bindings` | AIP-01 must match the exact policy/template/model/endpoint and workload boundary; raw prompt bytes are absent from durable evidence. |
| AIP-05-AC03 | mutation, hostile-template, strict-schema and current-input replay tests | Changed inputs invalidate the result; source is untrusted data and cannot authorize tools, endpoint or model changes. |
| HC-01/HC-05 | immutable result/telemetry, collision, time-boundary and two-workload tests | Terminal state is reconstructable, idempotent and workload-isolated. |
| HC-02 | strict `approved_advisory` evidence kind plus request/source/policy binding | Advice remains selected evidence, never authority. No memory service is added. |
| HC-03 | deterministic-first/fallback-only constants | AI cannot replace the deterministic path or establish SAS equivalence. |
| HC-04 | protected identity/template, traversal, symlink and non-echo tests | Unsafe data and paths fail before publication. |

## Bounded disposition

Local policy and evaluation files are deliberately `pending` and `synthetic_contract`. Caller
content cannot promote them to operational authority. Every result is
`blocked_external_authority` until a separately authenticated composition boundary verifies the
Humana gateway route/model approval and real evaluation evidence. Direct provider access, tool
actions and prompt persistence are prohibited.

This work performs no network request and makes no live gateway/model invocation, generation,
execution, validation, parity, Humana-readiness, production-readiness or migration-completion
claim. Humana still owns route/model selection, security approval, evaluation acceptance and the
authorized operational test window.
