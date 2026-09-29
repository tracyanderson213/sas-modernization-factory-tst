# SEC-04 Runtime AI Transport Evidence

## Scope and limitations

This record covers the provider-neutral offline implementation and synthetic deterministic tests for
SEC-04. It is not live Humana qualification, an endpoint approval, a provider integration, model
governance approval, or evidence of conversion, execution, validation, or parity. The checked-in
Humana endpoint, identity, credential, retention, access, classification, and submission-authority
bindings remain pending and therefore block client transport.

The source baseline is `bafe2d4f9a7dc097e1a73db56b0584c44d728328` plus the uncommitted SEC-04
worktree diff; configuration revision is the signed synthetic fixture plus the pending opaque Humana
policy in `deployments/humana/security-policy.yaml`.
Immutable evidence references below identify repository tests and signed per-attempt evidence paths;
local test output is offline evidence only.

## Acceptance matrix

| Criterion | Procedure and expected outcome | Actual offline result | Safe evidence reference |
|---|---|---|---|
| SEC-04-AC01 | Run the focused transport suite; only the internally resolved signed HTTPS binding reaches the guard-owned one-shot transport, while missing/unapproved inputs make zero calls. | Fourteen boundary checks passed. The public guard accepts no caller-supplied sender. | `tests/unit/test_ai_transport_boundary.py`; `evidence://security/sec-04/ac01` |
| SEC-04-AC02 | Run initial/retry binding, signed-attestation, exact-payload classification, payload digest, and configuration snapshot tests; each attempt must revalidate before dispatch. | Implemented offline; live provider retry remains unverified. | `tests/unit/test_ai_transport_attestation.py`; `evidence://security/sec-04/ac02` |
| SEC-04-AC03 | Exercise the concrete HTTPS transport with a hostile `Location`, canonical URL and poisoned-signature cases, phone/member canaries, arbitrary payload mutation, and changed binding cases; no second destination receives bytes. | Implemented with a deterministic fake HTTPS connection; live network is not claimed. | `tests/unit/test_ai_transport_boundary.py`; `evidence://security/sec-04/ac03` |
| SEC-04-AC04 | Verify isolated run/workload/attempt paths, atomic concurrent dispatch claiming, dispatch-without-result recovery, immutable results, and automatic telemetry-only repair on retry. | Implemented offline. | `tests/unit/test_ai_transport_boundary.py`; `evidence://security/sec-04/ac04` |
| HC-01 | Inspect request and signed evidence bindings for workload/source/run/workflow attempt/transport attempt/policy/provider/configuration identities. | Implemented. | `src/smf/security/ai_transport_models.py`; `evidence://security/sec-04/hc01` |
| HC-02 | Confirm the guard has no recall dependency and payload text cannot select a destination or alter policy. | Implemented; no memory subsystem added. | `src/smf/security/ai_transport.py`; `evidence://security/sec-04/hc02` |
| HC-03 | Rehash the immutable SEC-02 context and preserve downstream success flags as false. | Implemented; semantic parity is not claimed. | `tests/unit/test_ai_transport_boundary.py`; `evidence://security/sec-04/hc03` |
| HC-04 | Exercise identity, signed exact-payload classification, phone/member/secret payload, endpoint, and response safety boundaries; persist no prompt, response, credential, URL, or provider diagnostic. | Implemented for deterministic canaries. | `tests/unit/test_ai_transport_boundary.py`; `evidence://security/sec-04/hc04` |
| HC-05 | Run positive, negative, mutation, restart, telemetry-repair, and concurrent duplicate-attempt tests; blocked/failed/unknown states remain distinct and cannot assert downstream success. | Implemented offline; real-environment evidence remains blocked. | `tests/unit/test_ai_transport_manifest.py`; `evidence://security/sec-04/hc05` |

## Commands

Run the focused commands from `agent-artifacts/architect.md`, followed by `make verify`. Expected:
all tests, formatting, lint, typing, schema packaging, and repository verification pass. If required
dependencies or client approvals are unavailable, record that as blocked rather than substituting a
mock or generated-only success claim.

Current worktree execution results:

- The focused transport, policy, attestation, manifest, and schema-packaging command passed all 39
  tests, including positive dispatch, exact-payload classification, phone/member denial, terminal
  redirect handling, configuration TOCTOU rejection, atomic duplicate-attempt dispatch, automatic
  telemetry repair, cross-workload isolation, and interrupted-dispatch no-resend recovery.
- `make verify` passed Ruff, mypy over 152 source files, and all 1,159 unit/integration tests in the
  current worktree.
- The trusted repository-environment `pip-audit` run completed with no known vulnerabilities; the
  local `sas-modernization-factory` package was skipped because it is not published on PyPI. The
  disposable Reviewer snapshot could not resolve `pypi.org`, so its independent audit was recorded
  as environment-limited rather than substituted for the trusted result.
- `python -m compileall -q src tests` and `git diff --check` passed. Public corpus bytes were not
  modified.
