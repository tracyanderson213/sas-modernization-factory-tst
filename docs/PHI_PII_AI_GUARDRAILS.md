# PHI/PII AI Guardrails

## Implemented boundary

SEC-02 implements provider-neutral, offline qualification of task-specific AI context. It does not
send a request to a model provider. Qualification requires a replay-valid `READY` manifest, exact
client/deployment/environment/workload/boundary/subject/run/attempt bindings, a complete canonical
source closure, an active explicit policy, and signed per-artifact/per-field classification evidence
from a configured authority.

The implementation rehashes source bytes before assembly. It rejects incomplete or ambiguous
boundaries, unsafe paths, duplicate or case-ambiguous identities, unsupported kinds/encodings,
empty or non-meaningful SAS entry subjects, policy or evidence mismatches, and deterministic
secret/PHI/PII canaries including supported encoded forms. Sanitization is used to make diagnostics
safe; a detected transformation blocks admission and never turns protected source into allowed
source.

## States and claims

The canonical states are `qualified_offline`, `blocked_missing`, `blocked_pending`, `denied`,
`blocked_ambiguous`, and `invalid_binding`. Pending evidence is not denial, and neither is success.
Every result fixes these claims to false: transport attempted, submission authorized, generated,
executed, validated, parity passed, certified, human approved, and human assisted.

A qualified context is held in a deliberately non-serializable, non-copyable, zeroable transient
envelope. Durable evidence stores only the safe identity/provenance bindings, categorical checks,
safe evidence references, allowed artifact/field IDs, context digest and byte count. It never stores
raw context, source excerpts, canary values, provider error text, or credentials.

## Persistence and retry

Results are isolated below
`runs/<run>/workloads/<workload>/attempts/<attempt>/security/ai-context/<decision>/`. Publication is
atomic and append-only. An identical retry preserves the canonical decision and can recreate missing
telemetry; conflicting bytes under the same decision identity fail. Independent workload and attempt
paths do not share mutable decision state. Every persisted result requires an Ed25519 evidence proof;
reload requires the corresponding explicitly trusted public key. The public content digest detects
accidental change but is never treated as authority, so hand-authored JSON cannot manufacture a
durable qualification claim.

## Transport-time enforcement

SEC-04 adds a provider-neutral egress guard at the actual sender boundary. Every initial request
and retry requires fresh verification of the signed transport policy, protected endpoint binding,
SEC-02 result, immutable context and payload digests, identity and credential decisions, signed
classification evidence for the exact payload, and a separately signed `ai-prompt-submit` decision
bound to the exact transport attempt. The destination and one-shot HTTPS implementation are inside
the guard; callers cannot supply a URL or executable sender. Only canonical HTTPS endpoints are
accepted, every 3xx is terminal, and there is no redirect-following or provider-fallback path.

The complete JSON payload is bounded and scanned immediately before dispatch. Detection blocks;
the guard never sanitizes unsafe prompt content into allowed prompt content. Durable preparation,
dispatch, result, and telemetry evidence stores only safe identities, digests, categorical outcomes,
and governed references. Atomic marker publication gives an exact attempt one dispatch claimant.
A marker without a terminal result becomes `outcome_unknown` and is never resent automatically;
missing telemetry is recreated from the verified canonical result on ordinary retry. A received
response is transport evidence only: generated, executed,
validated, parity-passed, certified, and human-approved remain false.

## Humana blockers

`deployments/humana/security-policy.yaml` names Anthropic as an allowed provider, but it does not
supply an approved endpoint/model binding, field or artifact allowlist, classification authority,
retention/access policy, or signed submission authority. Its AI binding is pending and protected
data in prompts is false. These are explicit blockers, not defaults to be inferred.

## Downstream obligations and non-goals

AIP-01 now supplies the provider-neutral request/result contract and consumes immutable transient
bytes bound to the exact SEC-02 context digest and size. Its deterministic mock makes no outbound
call, records only `synthetic_contract` evidence, rejects protected/hostile or non-meaningful output,
and cannot assert a downstream lifecycle claim. The provider cannot be invoked from caller-supplied
references, digests, or a `verified` label: it authenticates the exact SEC-02 result and signed,
time-bounded prompt, transport, configuration, retention, and access prerequisites under configured
trusted keys and rechecks their immutable snapshots immediately before invocation. Evidence locations
remain untrusted and cannot supply those keys. The current public invocation functions reject or
ignore per-attempt verifier configuration and therefore block; the authenticated composition layer
that will own fixed SEC-02 and prerequisite trust roots is intentionally deferred. Signed append-only
preparation, invocation, result, and derived telemetry records preserve exact
workload/run/attempt/provider identities. An invocation marker without a terminal result becomes
`outcome_unknown` and is never automatically reissued.

Future real adapters must invoke the SEC-04 guard for every outbound call. Provider adapters may
serialize requests and parse responses, but must not select destinations, follow redirects, open a
parallel network path, or treat provider diagnostics as durable evidence.

This increment adds no OpenAI or Anthropic adapter, no CLI activation, no live Humana activation, no
durable recall or memory store, no transcript capture, no background service, and no conversion,
execution, validation, parity, certification, deployment, or promotion claim.
