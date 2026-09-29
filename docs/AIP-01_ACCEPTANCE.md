# AIP-01 acceptance evidence

## Scope and claim boundary

This record covers the offline common AI-provider contract only. It does not attest an Anthropic or
OpenAI integration, network transport, generated conversion artifact, execution, validation, parity,
certification, human approval, Humana qualification, deployment, or production activation. The
deterministic mock is always `synthetic_contract` evidence.

The implementation worktree is based on repository revision `aebbc29`. The changes are intentionally
uncommitted because final commit and integration remain human-controlled. Consequently, local test
results are recorded below, but every acceptance row remains **unverified for closeout** until a
reviewed commit supplies the required immutable revision reference.

## Acceptance matrix

| Criterion | Source/configuration revision | Command or review procedure | Expected outcome | Actual outcome | Safe immutable evidence reference |
|---|---|---|---|---|---|
| AIP-01-AC01 | `aebbc29` + uncommitted AIP-01 worktree | Focused provider test command below; inspect `smf.ai` and deterministic mock | Strict versioned neutral contract; mock has no vendor/network dependency | Local pass; mock success remains synthetic | Pending reviewed commit; closeout unverified |
| AIP-01-AC02 | Same | Model/boundary/manifest tests | Exact request identities and authenticated prerequisites bind explicit success, blocked, unsupported, and failed states without parity | Local pass; public calls reject caller-selected trust roots, including a complete attacker-signed evidence chain and matching verifier configuration; missing, unsigned, forged, expired, digest-mismatched, cross-run, and cross-attempt prerequisites cannot invoke; lifecycle claims remain false | Pending reviewed commit; closeout unverified |
| AIP-01-AC03 | Same | Negative/adversarial and no-network tests | Malformed, missing, timeout, cancellation, hostile text, provider exceptions, mutation, and cross-request cases fail predictably | Local pass; ordinary provider exceptions become sanitized durable failures | Pending reviewed commit; closeout unverified |
| AIP-01-AC04 | Same | Manifest restart/isolation tests and scope review | Exact snapshots/policies are bound; restart, cancellation, and two-workload isolation are explicit; mocks do not prove real execution | Local pass for offline contract; real-workload competition evidence unavailable and unverified | Pending reviewed commit and authorized real-environment evidence |
| HC-01 | Same | Request/result binding and tamper tests | Results bind client/workload/source/run/attempt/artifact/policy/provider identities; downstream claims remain separate | Local pass | Pending reviewed commit; closeout unverified |
| HC-02 | Same | Advisory-evidence model tests | Advice records carry provenance/applicability/version/reason/conflict and cannot cross client/source/policy scope | Local pass; no recall store added | Pending reviewed commit; closeout unverified |
| HC-03 | Same | Source/subject and output-meaningfulness tests; architecture review | Empty or non-convertible subjects cannot succeed; no source bytes or target oracle are fabricated | Local pass for provider boundary; semantic fidelity remains downstream | Pending reviewed commit; closeout unverified |
| HC-04 | Same | Identity, protected-response, traversal, mutation, and no-network tests | Unsafe identities/references and protected or hostile output fail without durable leakage or authority escalation | Local pass | Pending reviewed commit; closeout unverified |
| HC-05 | Same | Signed manifest, mutation, retry, unknown-outcome, concurrency, telemetry tests | Failures stay visible; tampering fails; retry is idempotent; one atomic claimant invokes an attempt; mocks cannot masquerade as operational proof | Local pass; identical-call race invokes once without publication error | Pending reviewed commit; closeout unverified |

## Reproducible commands

Focused contract and adjacent security gate:

```bash
python -m pytest -q -p no:cacheprovider \
  tests/unit/test_ai_provider_models.py \
  tests/unit/test_ai_provider_boundary.py \
  tests/unit/test_ai_provider_manifest.py \
  tests/integration/test_ai_provider_guardrails.py \
  tests/unit/test_ai_context_admission.py \
  tests/unit/test_ai_context_manifest.py \
  tests/unit/test_ai_transport_boundary.py \
  tests/unit/test_ai_transport_manifest.py \
  tests/unit/test_sec01_threat_model.py \
  tests/integration/test_security_schema_packaging.py
```

Result on 2026-09-16 at base revision `aebbc299279b` plus the uncommitted AIP-01 worktree:
`182 passed in 6.29s` (exit status `0`). This is the exact result of the command above, including the
provider contract and adjacent SEC-01/SEC-02/SEC-04 suites. The result is local evidence only and is
not an immutable closeout reference until the reviewed changes are committed.

Additional 2026-09-16 results:

- targeted Ruff check and format check: pass;
- strict mypy for `smf.ai` and the compatibility module: pass;
- discovery confidence gates A, B, and C: pass (`1`, `15`, and `16` tests respectively);
- `make verify`: Ruff pass, repository mypy pass (`180` source files), and its pytest phase passed
  (`1302 passed in 146.55s`); the final
  `pip-audit` step was unavailable because the sandbox could not resolve
  `pypi.org`, so the aggregate command is not recorded as pass;
- public corpus worktree diff: clean;
- upstream public-portfolio byte verification: unavailable because the sandbox could not resolve
  the constrained GitHub URL, so it is not recorded as pass.

A failed, skipped, or unavailable command remains unverified. The final reviewer must rerun both
network-dependent gates in a network-enabled controlled environment and bind all results to the
reviewed commit.

## Pattern self-review

- Optional/caller-supplied authority cannot create success: direct and persisted invocation require
  the trusted SEC-02 result plus six authenticated, request-bound prerequisites. Evidence locations
  and records cannot carry verification keys. The public invocation functions do not accept
  per-attempt trust roots as authority: the regression constructs the entire evidence chain and
  verifier configuration with attacker keys and confirms a blocked result with zero provider
  invocations. The verified core is exercised only by the test harness pending a separately
  authenticated composition boundary. AIP-01 also blocks an `operational_verified` provider until a
  future attributable verifier exists.
- Exact request digests bind all durable evidence; strict enums reject unknown states and targets.
- Non-empty source identities, context, and meaningful output are required.
- Transient inputs copy admitted bytes and are rehashed immediately before invocation.
- Pending, missing, denied, unsupported, failed, timeout, cancellation, and unknown outcome remain
  separate states.
- Duplicate/case-colliding identities and boundary-escaping references are rejected.
- Every provider result fixes generated/executed/validated/parity/certification/approval to false.
- Atomic append-only evidence elects one invocation claimant, preserves canonical terminal state,
  and keeps telemetry derived and recoverable; an interrupted invocation is not reissued.
