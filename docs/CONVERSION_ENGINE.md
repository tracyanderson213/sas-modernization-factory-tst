# Conversion Engine v1

## Purpose

The Conversion Engine turns an assessed SAS workload into Databricks-oriented code while keeping orchestration, policy, provenance, and review gates inside SMF.

The upstream `sas2databricks` project is treated as a conversion implementation, not as the factory architecture.

## Current Flow

1. Assess the SAS source.
2. Read the assessment route.
3. Stop automatic conversion for `human_supervised`.
4. Stop macro-dependent conversion when the provider does not explicitly consume the accepted
   macro strategy and immutable source bundle.
5. For governed identities, plan the package-owned deterministic registry before any compatibility
   provider; otherwise invoke the explicitly selected conversion provider for eligible workloads.
6. Write generated PySpark or Spark SQL.
7. Write `conversion.manifest.json`.
8. Pass the generated artifact into Validation Engine v1.
9. Preserve provider review/escalation metadata so uncertainty remains visible downstream.

## Provider Boundary

`ConversionProvider` is the stable SMF interface.

Current executable provider:

- package-owned deterministic PROC SQL registry
- `sas2databricks`

## Deterministic PROC SQL Registry

The closed registry records rule identity/version, construct family, supported semantics, explicit
unsupported cases, composition order, and descriptor/registry digests. Package-owned qualification
records bind exact descriptor digests to fixture byte hashes, expected outcomes, runner version,
and recorded result digests; caller-authored labels cannot qualify a changed rule. Only one active
revision of a rule may exist for a target. The current qualified slice is one complete PROC SQL
block containing one SELECT statement, with
projection/filter/group/order, explicit INNER or LEFT JOIN predicates, and COUNT/SUM/AVG/MIN/MAX.
PySpark output wraps the same qualified Spark SQL statement in `spark.sql`; Spark SQL output is the
statement itself.

The planner uses the exact readiness-admitted bytes. Empty/comment-only input, multiple or nested
SELECTs, set operators, HAVING, SELECT INTO macro assignment, CALCULATED, CASE, window/pagination
clauses, unknown functions, pass-through SQL, macro processing, PROC FORMAT, and target Jinja/dbt
never fall through to a broader rewrite. CTAS is registered but blocks until authoritative source/output
dataset mappings are supplied; the current conversion command does not invent those mappings.

Each deterministic attempt publishes `rule-plan.json`, `rule-applications.json` when generated,
the generated artifact, `conversion.manifest.json`, and `conversion.telemetry.json`. Evidence binds
client/deployment/environment when present, workload/source/run/attempt, readiness and macro-policy
identities, exact source span/hash, rule/version/descriptor, registry digest, and output hash.
Attempt-local locking prevents duplicate transformation of one attempt without serializing other
workloads. Identical retries replay the plan, repair missing generated/application/telemetry files,
and reject changed bytes or collisions.

Scaffolded, non-operational provider families:

- Anthropic
- OpenAI

The common invocation contract is implemented separately in `smf.ai`. It provides a strict,
versioned request/result boundary and a deterministic no-network mock. The mock can prove contract
behavior only: its evidence class is always `synthetic_contract`, and provider success does not set
generated, executed, validated, parity-passed, certified, or human-approved claims. The legacy
conversion-provider classes above remain disabled compatibility scaffolds; AIP-01 does not connect
them to the conversion CLI.

The common boundary does not trust request fields as prerequisite attestations. Invocation requires
the exact signed SEC-02 admission result plus independently trusted, time-bounded evidence for prompt
policy/template, transport policy, provider configuration, retention, and access. Each record binds
the full provider request digest and is reverified immediately before the atomic invocation claim.
Evidence paths and records are an untrusted bundle; their verification keys come from a separate
governed composition boundary and cannot be supplied by that bundle or by the per-attempt caller.
That authenticated composition is not implemented in AIP-01, so public attempts reject or ignore
caller-selected verifier configuration and block instead of invoking.
Missing, pending, denied, expired, forged, cross-run, cross-attempt, or changed evidence cannot invoke
the provider.

Enterprise deployments select approved model adapters without changing the conversion-engine contract.
Humana's confirmed binding is Anthropic; Azure OpenAI remains an optional adapter for other
deployments and is not part of Humana's competition-critical path.

The presence of an AI provider class does not mean AI execution is enabled. Every future AI adapter
must use `smf.security.guarded_ai_transport`; direct provider network transport, caller-selected URLs,
caller-supplied transport senders, redirect following, and automatic fallback are prohibited. The
guard implements endpoint, exact-payload classification, and protected-data enforcement, but live
identity/credential bindings and prompt/model governance must also be approved before a provider is
operational.

## sas2databricks Adapter

The adapter normalizes the upstream converter into the SMF provider contract.

In particular, the upstream CLI can append conversion metadata to generated output. SMF removes that non-code trailer from the generated artifact and preserves the parsed values in provider metadata. Converter review signals can cause the conversion result to become `review_required`.

See [`SAS2DATABRICKS_ADAPTER.md`](SAS2DATABRICKS_ADAPTER.md).

## Safety Principle

A conversion completing is not evidence of semantic equivalence.

The current provider has no contract-aware SAS macro capability. A readiness-admitted workload
with macro definitions, calls, variables, quoting, intrinsic operations, or includes therefore
terminates as `review_required` before provider invocation and publishes only its manifest. The
manifest binds the macro analysis ID and strategy digest; it does not report converted, executed,
validated, or parity-passed success.

Complex statistical, unsupported, low-confidence, or converter-flagged workloads must remain reviewable. Assessment and validation policy can prevent unsafe automatic progression.

## Current Limitations

Conversion Engine v1 does not yet provide:

- demonstrated coverage across the representative SAS estate
- authoritative CTAS dataset-mapping ingestion through the conversion CLI
- complete PROC SQL coverage or qualification for SAS-specific missing-value/collation semantics
- complete SAS macro or semantic compatibility
- executable AI-provider fallback
- automated remediation
- data or business-semantic equivalence proof

Those capabilities are tracked separately in the GitHub Project.
