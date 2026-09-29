# Factory Telemetry

## Primary Metrics

- parse success rate
- deterministic conversion rate
- AI-assisted conversion rate
- straight-through processing rate
- first-pass validation rate
- remediation success rate
- human intervention rate
- average remediation effort
- end-to-end conversion cycle time
- semantic validation pass rate
- reusable pattern discovery rate
- regression pass rate

## Operational Metrics

- queue depth
- worker latency
- Databricks execution latency
- model invocation count
- model token/cost metrics where available
- retry count
- failure category distribution

## Readiness outcomes

Readiness persists a distinct `readiness.telemetry.json` lifecycle event beside each immutable
attempt manifest with workload/run/attempt identity,
classification, policy version, elapsed time, and sanitized blocker category/owner pairs. Readiness
alone always reports generated, executed, validated, and parity-passed as false. `HUMAN_REQUIRED`
records a pending decision and reports `human_assisted` as false; a later READY attempt reports
`human_assisted` as true only when explicit approval evidence satisfied the required review. This
keeps blocked qualification separate from later conversion and parity outcomes.

Macro discovery contributes strategy/analysis identities and typed blocker reasons to canonical
discovery and readiness evidence. Macro-dependent conversion without an explicitly capable provider
is `review_required`; it remains generated=false, executed=false, validated=false, and
parity_passed=false. Static resolution is never counted as expansion, conversion, or parity.

## Corpus regression outcomes

Corpus regression telemetry is derived from immutable attempt evidence and carries exact scenario,
workload, subject, run, attempt, source-bundle, and policy bindings. `generated`, `executed`,
`validated`, `parity_passed`, `human_assisted`, and `blocked` remain independent. In particular,
submitted or skipped execution is not executed, static validation is not parity, and pending approval
is distinct from denial. Corpus events are explicitly scoped `shared-regression` or `test-only`; they
are not Humana workload evidence.

## Databricks authentication outcomes

DBX-02 telemetry is derived only from immutable terminal authentication evidence. Events bind the
client, workload, run, workflow attempt, authentication request/attempt, deterministic decision,
provider/configuration versions, categorical state/reason, retry ordinal, probe progress and elapsed
time. `generated`, `authenticated`, `submitted`, `executed`, `validated`, `parity_passed`,
`human_assisted`, `blocked`, `certified`, and `human_approved` remain independent. A verified
authentication result sets only `authenticated`; it cannot manufacture a submitted, executed,
validated, parity-passed, certified, or human-approved outcome. Missing/pending authority, denial,
expiry, wrong workspace, wrong identity, permission denial, provider failure and unknown interrupted
outcomes remain distinct. No credential, authorization header, provider exception text, or
credential-derived hash is retained.

## Databricks compute-policy outcomes

DBX-03 telemetry is derived from immutable compute-selection results and binds client, workload,
run, workflow/selection attempts, deterministic decision, policy, profile and availability
observation identities. `generated`, `allocated`, `submitted`, `executed`, `validated`,
`parity_passed`, `human_assisted`, `blocked`, `certified`, and `human_approved` are independent.
`selected_offline` sets none of the allocation or downstream-success claims. Missing or unsigned
availability, pending policy, denial, quota exhaustion, allocation/provider unavailability,
incompatible runtime, expiry and invalid binding remain categorically distinct.
The durable evidence path is keyed by run, workload, workflow attempt, and selection attempt rather
than decision time. If publication stops after preparation, recovery verifies the preparation
signature and replays the captured request and `evaluated_at`; it never creates a new identity for
that attempt. Duplicate or substituted attempt evidence is an integrity failure, not telemetry.

## Objective

Telemetry should turn factory automation and velocity into measured evidence rather than estimates.
