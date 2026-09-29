# SMF Command Line Interface

The `smf` CLI is the local engineering entry point for the SAS Modernization Factory.

The product CLI below is separate from the repository engineering-agent CLI. For the governed
Humana competition backlog, `smf-agent drain` runs the local-only continuous engineering workflow
documented in [BACKLOG_ENGINEERING_WORKFLOW.md](BACKLOG_ENGINEERING_WORKFLOW.md); it is not an SMF
migration execution command and does not claim SAS/Databricks semantic validation.

## Verify an offline provenance chain

Replay a previously assembled PROV-01 chain from its original evidence, exact source snapshot, and
lineage-bound trust policy:

```bash
smf verify-provenance \
  --chain out/runs/RUN/workloads/WL/attempts/ATT/provenance/chain.json \
  --evidence-root /authorized/immutable/evidence \
  --source-root /authorized/source/snapshot \
  --policy /authorized/config/provenance-policy.json \
  --out out --json
```

The command rederives ORCH-04 identities, rehashes source closure bytes, original producer records
and stage artifacts, verifies configured Ed25519 producer signatures, walks graph and supersession
edges, and reconstructs terminal state and telemetry. The provenance policy digest must already be
bound into the canonical lineage, so a caller cannot substitute a new trust root for an existing
attempt. An accurately verified `validated` offline chain exits `0`; a verified blocked, pending,
denied, unsupported, cancelled, or failed chain exits `2`; malformed, ambiguous, substituted,
missing, unsigned, or tampered evidence exits `1`.

Verification does not run conversion, execution, validation or repair and cannot grant approval,
parity, certification, promotion, deployment, or final integration. `parity_passed` and `certified`
remain false in this bounded increment. Human approval is reported only from exact-attempt evidence
issued by a producer authority fixed by the lineage-bound policy. See
[PROV-01_ACCEPTANCE.md](PROV-01_ACCEPTANCE.md).

## Acquire a trusted SAS baseline

Import one approved, signed SAS export for an exact admitted workload attempt:

```bash
smf acquire-baseline \
  --acquisition-id ACQ-123 --mode approved_export \
  --policy deployments/client/baseline-policy.yaml \
  --intake-result out/runs/run-1/batch-intakes/BATCH/revisions/REV/attempts/1/intake.result.json \
  --intake-policy deployments/client/intake-policy.yaml \
  --package-root /approved/export/package --receipt /approved/export/package/receipt.json \
  --approval /approved/evidence/baseline-approval.json \
  --workload-id WL-123 --workload-revision-id WREV-123 --closure-digest SHA256 \
  --boundary-id BND-123 --run-id run-1 --attempt-id 1 --out out --json
```

The command verifies separate producer and approval signatures, exact admitted source bytes, input
snapshots, SAS runtime/configuration identity, selected boundary outputs, and output bytes before
publishing immutable evidence. `acquired` exits `0`; valid missing, pending, denied, or unavailable
provider states persist and exit `2`; malformed, untrusted, unsafe, or integrity-invalid input exits
`1`. The `sas_execution` mode is currently blocked because no direct SAS provider is installed.

The command does not generate target code, execute target code, validate results, establish parity,
certify a workload, or grant final human approval. Checked-in fixtures are synthetic contract tests,
not trusted SAS baselines. See [BASELINE_ACQUISITION.md](BASELINE_ACQUISITION.md).

## Architecture/security review packet

Assemble offline HENV-03 evidence for one exact workload subject:

```bash
smf architecture-review assemble examples/simple/example.sas \
  --discovery-manifest out/discovery.json --discovery-namespace default \
  --workload-id WL-123 --subject-id ART-123 --boundary-id BND-123 \
  --run-id run-1 --attempt-id 1 --assessed-revision REVISION --out out
```

The discovery manifest is replayed from its canonical source and the supplied workload, executable SAS
entry artifact, boundary, source checksum, full boundary closure, and dependency graph must match. Every
closure artifact is sensitive-scanned before qualification. The controlled packet records governed source
locators and `load_packet` re-hashes the complete closure before downstream use, so later entry/include
mutation fails closed. With pending Humana bindings the command returns exit code `2` and disposition
`blocked`. It never authenticates, contacts endpoints, executes workloads, validates parity, or grants
approval. Request strings cannot publish a shared projection. Shared publication also requires
`--security-policy`, `--security-bindings`, and `--disclosure-evidence` containing a valid, unexpired,
exact-scope signed decision. `--activation-evidence` additionally requires a replay-valid `READY`
HENV-01 manifest whose workload digest and exact source closure match canonical discovery. The review
packet remains non-authorizing; the existing Vault provider independently rejects it before Entra or
Vault transport. See
[HUMANA_SECURITY_ARCHITECTURE_REVIEW_PACKET.md](HUMANA_SECURITY_ARCHITECTURE_REVIEW_PACKET.md).

## Deployment configuration

Generate and offline-preflight the Humana deployment skeleton:

```bash
smf deployment-config init --template humana --out out/humana
smf deployment-config preflight --config out/humana/factory.yaml --json
```

Generation writes deterministic configuration bytes only and refuses conflicting existing files.
Preflight performs no provider, network, credential, or deployment action. The checked-in template
is intentionally unresolved until named Humana requirements are active and a matching,
replay-valid HENV-01 readiness manifest is supplied. See
[HUMANA_DEPLOYMENT_CONFIGURATION.md](HUMANA_DEPLOYMENT_CONFIGURATION.md).

Create an immutable, non-mutating environment plan from a strict configuration containing only
opaque references:

```bash
smf deployment-config plan \
  --config deployments/client/factory.yaml \
  --environment-config deployments/client/environment-plan.yaml \
  --out out \
  --run-id run-1 \
  --attempt-id attempt-1 \
  --json
```

`plan` supports `internal_provision` and `customer_validate` configuration modes but performs no
provisioning or validation probe. It imports no provider SDK, resolves no credential, and contacts no
Azure, Databricks, Vault, AI Gateway, source system, or model provider. The command publishes an
append-only result and derived telemetry under
`out/runs/<run-id>/environments/<environment-id>/plan-attempts/<attempt-id>/`. See
[DBENV-01_ACCEPTANCE.md](DBENV-01_ACCEPTANCE.md).

## Discover

Discover a SAS estate from the filesystem and persist the canonical workload graph:

```bash
smf discover tests/fixtures/e2e/sample-sas-estate --out out/discovery.json
```

Provider selection can be explicit:

```bash
smf discover /path/to/sas-estate --provider filesystem
smf discover /path/to/content-assessment --provider sas-content-assessment
```

Discovery is read-only. Current deterministic enrichment includes SAS references, data endpoint characterization, producer/consumer lineage, and shell/AutoSys/cron execution-context relationships. Unknowns remain unresolved rather than guessed.

## Intake a batch

Admit a signed, versioned source inventory into isolated canonical workload snapshots:

```bash
smf intake-batch batch-manifest.json --policy intake-policy.yaml \
  --source-root /authorized/source/root --run-id run-1 --attempt-id 1 \
  --out out --json
```

The command verifies the configured Ed25519 manifest authority, exact source sizes and SHA-256
digests, denominator reconciliation, safe paths and identities, distinct ownership, meaningful SAS
entry points, and discovered code closure. It publishes an immutable batch decision plus recoverable
per-workload readiness-input, run-lineage, and telemetry projections. The versioned lineage envelope
derives full-digest workload, source-revision, run, attempt, and envelope identities from the signed
client/workload key, complete canonical source closure, policy/strategy/configuration digests, and
safe idempotency/attempt keys. Source acquisition locators remain provenance and do not replace
canonical source identity. A wholly admitted batch exits `0`; a valid
partial or blocked decision exits `2`; malformed, untrusted, unsafe, or integrity-invalid input exits
`1`.

Intake admission means only that source bytes were admitted and snapshotted. Generated, executed,
validated, parity-passed, certified, and human-assisted remain separate false claims. The readiness
projection records configured missing prerequisites but cannot issue a `READY` decision. The command
does not contact Humana, acquire SAS baselines, select a competition cohort, convert or execute code,
validate parity, or grant approval. See [BATCH_INTAKE.md](BATCH_INTAKE.md).

## Qualify pinned upstreams offline

```bash
smf upstream qualify \
  --policy upstream-policy.json \
  --inventory competition/upstream/approved-inventory.json \
  --evidence-root /approved/upstream-evidence \
  --scope-id humana-recovery --run-id upq-2026-09-18 --attempt-id attempt-1 \
  --evaluation-time 2026-09-18T12:00:00Z \
  --signing-key /protected/qualification-key.pem \
  --signing-key-id qualification-key-2026 \
  --signing-authority qualification-service --out out --json
```

This command performs no network access, download, installation, code execution, legal approval, or
promotion. Exit `0` means only that every expected entry has reconstructable signed evidence for its
governed disposition. See [`UPSTREAM_QUALIFICATION.md`](UPSTREAM_QUALIFICATION.md).

## Assess

```bash
smf assess examples/simple/example.sas
```

Explain the routing decision:

```bash
smf assess examples/simple/example.sas --explain
```

Structured output:

```bash
smf assess examples/simple/example.sas --json
```

## Ready

Qualify supplied discovery and evidence before expensive conversion:

```bash
smf ready discovery.json readiness-evidence.json \
  --policy deployments/humana/readiness-policy.yaml \
  --run-id run-1 --attempt-id 1 --workload-id WL-123 --boundary-id WB-123 \
  --out out --json
```

The result and bounded readiness telemetry event are persisted under the run/workload/attempt
hierarchy. `READY` exits `0`; a valid
blocked, unsupported, unresolved, or human-required result exits `2` after persistence. The command
qualifies supplied evidence only; it does not acquire SAS baselines, dataset mappings, or environment
connectivity.

For the Humana policy, each environment/runtime prerequisite record must carry the exact
`prerequisite_id`, client/deployment/environment and configuration bindings, evidence run and
attempt IDs, owner-assignment reference, validity interval, governed check execution or decision
ID, and immutable `result_uri`/`result_digest`. `pending` requires `approval_pending`; `fail`
requires `access_denied`. Missing or mismatched fields remain non-ready even when the record is
signed or says `pass`. `result_uri` is resolved only as a canonical `results/*.json` path beneath
the evidence JSON directory; remote URLs, traversal, missing files, digest mismatch, noncanonical
JSON, and artifact identity mismatch fail closed. The verified result is retained in the readiness
manifest so restart/replay does not depend on a mutable locator.

The CLI qualifies supplied governed evidence; it does not currently acquire or attest the complete
evidence bundle. Evidence acquisition remains an external control-plane responsibility.

## Select a pilot cohort

Evaluate a versioned inventory against an explicit, owner-supplied selection policy:

```bash
smf select-pilot inventory.json --policy pilot-policy.yaml \
  --run-id run-1 --attempt-id 1 --out out --json
```

The command verifies the signed inventory, discovery and source snapshots, assessments, prerequisite
manifests, full-inventory denominator, configured representativeness criteria, and exact run/attempt
binding before publishing append-only selection evidence. A qualified offline selection exits `0`;
a structurally valid `blocked` or `human_required` result is persisted and exits `2`; malformed,
unsafe, ambiguous, or integrity-invalid input exits `1`.

Selection performs no conversion, execution, validation, deployment, network access, or owner
approval. Public, synthetic, workshop, mock, and generated fixtures test the mechanism only and are
not Humana competition evidence. See [PILOT_SELECTION.md](PILOT_SELECTION.md).

Each candidate assessment must reference a packaged-schema-valid workload-complexity result and its
exact policy. Selection verifies the result digest and Ed25519 proof, the allowlisted policy digest,
and the client/discovery/workload/boundary/source/run/attempt bindings. Candidate complexity, score,
construct, macro, dependency, data-access, and validation-difficulty projections must exactly match
the governed result. An unsigned, unknown, blocked, stale, conflicting, or mismatched assessment is
ineligible. Workload assessment is currently a Python contract; no new product CLI command is claimed.

## Convert

Convert a workload only after it has received a replay-valid `READY` decision:

```bash
smf convert source.sas --target pyspark --out out \
  --provider deterministic --conversion-attempt-id convert-1 \
  --temporal-policy examples/policies/sas-temporal-utc.json \
  --value-compatibility-policy examples/policies/sas-value-compatibility-v1.json \
  --deployment-config deployments/humana/factory.yaml \
  --workload-id WL-123 --source-artifact-id ART-123 --run-id run-1 \
  --readiness-attempt-id 1 \
  --readiness-manifest out/runs/run-1/workloads/WL-123/attempts/1/readiness.manifest.json
```

Add `--json` for structured output. Use `--target sparksql` for Spark SQL. `auto` selects the
package-owned deterministic registry first when the deployment binding supplies a governed
client/deployment/environment identity. `--provider deterministic` selects that same offline path
explicitly; `--provider sas2databricks` selects the compatibility adapter. Unknown provider and
target values fail closed.

The conversion command always performs assessment after admission. Workloads routed as
`human_supervised` produce a `review_required` result and are not automatically converted.
The deterministic provider supports one complete, comment-free PROC SQL statement in the qualified
SELECT/INNER-or-LEFT-JOIN/aggregate subset. Macro processing, PROC FORMAT, target Jinja/dbt,
pass-through SQL, unqualified CTAS mappings, unsupported functions, multiple/nested SELECTs, set
operators, HAVING, macro INTO, CALCULATED, CASE, window/pagination clauses, and empty or comment-only
sources become explicit `unsupported` or `blocked` results without generated code.

`--temporal-policy` explicitly enables the bounded SAS date/datetime literal subset. The checked-in
example policy is UTC-only and supports `DDMONYYYY` date literals plus
`DDMONYYYY:HH:MM:SS[.ffffff]` datetime literals in either SAS quote form. A temporal literal without
a policy blocks; invalid
calendar/clock values, unsupported suffixes, time-only values, non-UTC policy, and excess fractional
precision do not generate output. Successful temporal attempts add immutable
`temporal-mappings.json` evidence. Supplying the example policy is configuration, not Humana owner
approval or parity evidence.

`--value-compatibility-policy` enables only exact, bounded character-to-numeric coercion when both
operand types are self-evident literals in a supported binary comparison. The canonical value must
also be exactly representable as a SAS IEEE-754 numeric; decimal digit limits alone do not qualify
it. ASCII-padded and leading-zero values that satisfy those constraints normalize to a canonical
number and publish immutable `value-mappings.json` evidence. Implicit arithmetic, `BETWEEN`/`NOT
BETWEEN`, and numeric/character concatenation remain attributable but unsupported pending
operation-specific SAS/target equivalence evidence. Detected ordinary (`.`), special (`._`,
`.A`-`.Z`), or character missing values also remain unresolved and generate no target artifact.
Missing policy, malformed or out-of-bound numeric text, exponent/locale/date/NaN/infinity forms,
numeric-to-character behavior, and schema-dependent column coercion do not generate output. The
checked-in policy is technical package configuration, not Humana approval, SAS execution,
validation, or parity evidence.

Every conversion requires `--deployment-config` and a replay-valid `READY` manifest. The binding
must mandate readiness and supply the authoritative policy digest. The workload, run, attempt, and
source-artifact identities must match the manifest, and the recorded source SHA-256 must match the
exact input bytes. `--readiness-policy-digest`, when supplied, is an additional equality constraint.
A missing, non-`READY`, expired, tampered, identity-mismatched, policy-mismatched,
replay-inconsistent, or source-mismatched manifest is rejected before the provider runs.

The parser presents these admission arguments as optional, but the conversion guard requires them
for every successful conversion.

Outputs are isolated under
`out/runs/<run-id>/workloads/<workload-id>/attempts/<conversion-attempt-id>/conversion/<source-artifact-id>/`.
When `--conversion-attempt-id` is omitted, it defaults to the readiness attempt ID. Deterministic
attempts publish an immutable rule plan, generated artifact, per-rule application evidence,
temporal and value mapping evidence when applicable, canonical result, and derived telemetry. An
identical retry returns the canonical result and repairs
missing derived artifacts; a content or identity collision fails closed. The telemetry keeps
generated, executed, validated, parity-passed, certified, human-assisted, blocked, unsupported, and
failed claims distinct.

## Validate

Validate a generated artifact:

```bash
smf validate \
  examples/simple/example.sas \
  out/example/example.py \
  --target pyspark \
  --out out
```

Explain individual checks:

```bash
smf validate \
  examples/simple/example.sas \
  out/example/example.py \
  --target pyspark \
  --out out \
  --explain
```

Structured output:

```bash
smf validate \
  examples/simple/example.sas \
  out/example/example.py \
  --target pyspark \
  --out out \
  --json
```

## Execute

Execute an eligible generated artifact with the local engineering provider:

```bash
smf execute examples/simple/example.sas out/example/example.py \
  --target pyspark --provider local --out out \
  --run-id run-1 --workload-id WL-123 --attempt-id execute-1
```

Local execution captures runtime evidence but does not prove Databricks compatibility. Set stable
run, workload, and attempt identities for attributable evidence. Results are append-only under
`out/runs/<run-id>/workloads/<workload-id>/attempts/<attempt-id>/execution/`. The compatibility
defaults are `run-id=standalone`, `workload-id=<source stem>`, and `attempt-id=1`; repeating those
defaults after any result is intentionally blocked. Never rerun a failed or timed-out attempt.
Reconcile possible side effects first, then use a distinct attempt ID for an authorized retry. A
claim without a terminal manifest is an unknown outcome and cannot be retried automatically.
These compatibility identifiers are not the ORCH-04 canonical derivations unless the caller obtained
and verified them through the governed lineage contract. Standalone execution does not consume an
intake lineage envelope and must not be represented as governed end-to-end lineage, Humana execution,
parity, certification, or approval.

## Validate schema

Compare two authoritative, pre-acquired schema snapshots with the strict default policy:

```bash
smf validate-schema source-schema.json target-schema.json --out out --json
```

Apply explicit compatibility mappings or tolerances from a versioned JSON or YAML policy:

```bash
smf validate-schema source-schema.json target-schema.json \
  --policy structural-policy.yaml --out out
```

A pass exits `0`. A mismatch, blocked evidence, malformed snapshot, or invalid policy exits nonzero.
The manifest is written to
`out/<logical-dataset-id>/validation/structural-parity.manifest.json`. JSON mode writes only the
schema-valid result to stdout. This command compares supplied evidence; it does not connect to SAS or
Databricks, acquire runtime schemas, or establish data or semantic parity.

## Current local flows

### Competition availability matrix

| Surface | Current status | What is actually executable |
| --- | --- | --- |
| Real SAS binary-data acceptance | **Executable local acceptance harness** | `make vs01-confidence` runs the licensed `.sas7bdat -> pyreadstat -> Spark -> Delta -> DataComPy -> immutable evidence` path. `make scale01-confidence` runs the partitioned `spark-sas7bdat`/Parso proof. |
| Deterministic SAS code package | **Executable focused gate/API foundation** | `make cv04-confidence` exercises pinned `sas2databricks 0.4.0`; top-level `smf convert` remains the older assessment-first stage command. |
| Static/schema validation | **Executable stage commands** | `smf validate` and `smf validate-schema` operate only on supplied local artifacts/snapshots. |
| Local generated-code execution | **Executable local provider** | `smf execute --provider local`; it is not Databricks proof. The Databricks provider boundary remains disabled/default-deny. |
| AI repair | **Offline-only contract** | `smf ai-gateway preflight` and AIREP-01 focused tests; no socket, provider invocation, or repair bytes. |
| Unified conversion-only workflow | **Scaffold** | `smf migrate convert` validates/binds inputs, writes blocked contract evidence, and exits `2`; MIGCLI-01 owns the future backend. |
| Full modernization workflow | **Scaffold/later phase** | `smf migrate modernize` exits `2`; MODAP-01/MODCLI-01 remain later competition/January 2027 work. |
| Live Humana/Databricks/Unity Catalog | **Unavailable without separate authority and executed evidence** | No current command may claim live connectivity, execution, parity, readiness, or promotion. |

The exact currently demonstrated conversion-and-validation sequence is therefore:

```bash
# Real local binary-data slice; requires the approved existing conversion runtime.
make vs01-confidence

# Partitioned reader/reconciliation proof; its script performs only its documented, hash-bound
# build-time upstream acquisition and never performs a runtime public dependency download.
make scale01-confidence

# Deterministic SAS-code package qualification.
make cv04-confidence
```

These are acceptance gates, not a single operator workflow. Their artifacts cannot be combined into
a migration-complete claim until the DP/VAL, PROV-02, READY-02, PKG-QUAL-01, MIGCLI-01 and MIGOPS-01
gates pass in dependency order.

## Migration contract scaffold

The migration namespace is an offline contract scaffold. Valid invocations publish an immutable
blocked result and derived telemetry, return exit `2`, and keep `generated`, `executed`, `validated`,
`parity_passed`, `certified`, `human_approved`, `promoted`, and `provider_invoked` false. It does not
alias the existing top-level `smf convert` command.

Input-qualified conversion contract example:

```bash
smf migrate convert \
  --source authorized/source \
  --workload-config workload.yaml \
  --factory-config deployments/humana/factory.yaml \
  --gateway-config deployments/humana/ai-gateway.yaml \
  --asset-policy migration/asset-policy.yaml \
  --type-policy migration/type-mapping.yaml \
  --validation-policy migration/validation-policy.yaml \
  --workload-id claims --run-id run-1 --attempt-id attempt-1 --out out --json
```

`modernize` takes the same arguments plus `--modernization-policy`. Run-ledger surfaces are
`status`, `resume`, `exceptions list|submit|decide`, `approve`, and `promote`. They publish contract
evidence only because CLICON-01 has no authoritative run ledger. Consequently their `attempt_id` is
explicitly null and `run_manifest_unavailable` remains visible.

Exact scaffold invocations are:

```bash
smf migrate status --run-id run-1 --workload-id claims --out out --json
smf migrate resume --run-id run-1 --workload-id claims \
  --from-checkpoint latest-safe --factory-config deployments/humana/factory.yaml --out out --json
smf migrate exceptions list --run-id run-1 --workload-id claims --out out --json
smf migrate exceptions submit --run-id run-1 --workload-id claims \
  --exception-file exception.json --out out --json
smf migrate exceptions decide --run-id run-1 --workload-id claims \
  --decision-file decision.json --out out --json
smf migrate approve --run-id run-1 --workload-id claims --stage migration-completion \
  --approval-file approval.json --out out --json
smf migrate promote --run-id run-1 --workload-id claims --target development \
  --promotion-approval approvals/run-1-development-promotion.json --out out --json
```

Every valid invocation above exits `2` today. `approve` does not authorize `promote`; promotion
requires its separate target-specific, unexpired, run/evidence/source/target/identity/environment-
bound approval. None of these scaffold commands mutates an external system.

Gateway preflight validates the provider-neutral AIGW-01 configuration contract, binds the exact
configuration, factory snapshot, implementation files, workload, run, and attempt, and publishes an
immutable result plus derived telemetry. It never resolves a secret, opens a socket, invokes a
provider, or falls back to a public endpoint. Use the complete template in
`examples/ai-gateway-preflight.yaml`; it includes endpoint/route/model alias, authentication and
header references, CA/mTLS references, timeouts, bounded retry, quotas, retention, and authority.
References identify externally governed values and never contain credential bytes.

The committed example is intentionally pending and non-routable:

```yaml
gateway:
  state: pending
  endpoint: https://gateway.example.invalid
authentication:
  mode: pending
  credential_reference: null
```

Unknown versions or fields, duplicate keys or headers, direct Anthropic/OpenAI endpoints, plaintext
credential fields, unsafe paths, mutable inputs, and policy-incompatible values fail before
publication. The shipped transport is an in-process synthetic mock only. Its success, denial,
throttle, content-filter, malformed-response, missing-correlation, disconnect, and uncertain-timeout
outcomes cannot satisfy real connectivity, execution, repair, readiness, or parity claims.

```bash
smf ai-gateway preflight \
  --config examples/ai-gateway-preflight.yaml \
  --evaluation-time 2026-09-20T12:00:00Z \
  --workload-id claims --out out/preflight --json
```

Canonical evidence is under
`out/runs/<run-id>[/workloads/<workload-id>]/contract-attempts/<attempt-or-invocation-id>/`.
Unknown commands, enum values, and fields are errors. Missing upstream qualification remains a
blocker; caller-authored approval, success, signature, or mock fields are not accepted as evidence.

Discovery flow:

```bash
smf discover tests/fixtures/e2e/sample-sas-estate --out out/discovery.json
```

Readiness-gated conversion/validation flow:

```bash
smf assess examples/simple/example.sas --explain
smf ready discovery.json readiness-evidence.json --policy deployments/humana/readiness-policy.yaml --run-id run-1 --attempt-id 1 --workload-id WL-123 --out out
smf convert examples/simple/example.sas --target pyspark --out out --deployment-config deployments/humana/factory.yaml --workload-id WL-123 --source-artifact-id ART-123 --run-id run-1 --readiness-attempt-id 1 --readiness-manifest out/runs/run-1/workloads/WL-123/attempts/1/readiness.manifest.json
smf validate examples/simple/example.sas out/runs/run-1/workloads/WL-123/attempts/1/conversion/ART-123/example.py --target pyspark --out out --explain
```

The placeholders above must match the canonical IDs and paths in the supplied discovery and
readiness evidence. There is no end-to-end `smf run` command in the current implementation.

## Exit status

| Command | Exit status |
|---|---|
| `migrate ...` | `2` for a valid blocked/not-implemented contract result; `1` for malformed input or integrity/publication failure; never `0` |
| `ai-gateway preflight` | `2` for a valid offline configuration result blocked at live authority/connectivity; `1` for malformed, unsafe, mutated, direct-provider, or integrity/publication failure; never `0` in AIGW-01 |
| `deployment-config init` | `0` for template publication; `1` on error/collision |
| `deployment-config preflight` | `0` for qualification; `2` for blocked/unresolved; `1` for malformed input |
| `deployment-config plan` | `0` for a complete offline plan; `2` for a valid blocked plan; `1` for malformed, unsafe, mutated, or conflicting input/evidence |
| `discover`, `assess` | `0` on success; `1` on error |
| `ready` | `0` for `READY`; `2` for a valid non-ready decision; `1` on error |
| `convert` | `0` for `converted` or `review_required`; `2` for a valid blocked/unsupported/human-pending/denied result; `1` on failure or error |
| `validate` | Text mode returns `1` for `failed`; JSON mode currently emits the result and returns `0` |
| `execute` | Text and JSON modes return `0` for `succeeded` or an attributable future `submitted` result and `1` for `blocked` or `failed` |
| `validate-schema` | `0` for `passed`; `1` for mismatch or error |

Automation using `validate --json` must inspect the emitted `status` until its JSON-mode exit
behavior is made consistent. `execute --json` now uses the same status-sensitive exit behavior as
text mode.

Conversion is not migration acceptance. Validation Engine v1 supplies static and traceability
evidence only. The separate structural comparator proves only schema comparison for supplied trusted
snapshots. Databricks execution and broader data and semantic parity are subsequent validation layers.
