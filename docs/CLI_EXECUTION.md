# SMF Execute Command

Execution Validation is invoked with:

```bash
smf execute <source.sas> <generated.py> --provider local \
  --run-id <run-id> --workload-id <workload-id> --attempt-id <attempt-id>
```

Options:

- `--target pyspark|sparksql`
- `--provider local|databricks`
- `--out <directory>`
- `--run-id <identity>` (default: `standalone`)
- `--workload-id <identity>` (default: source stem)
- `--attempt-id <identity>` (default: `1`)
- `--timeout <seconds>`
- `--allow-writes`
- `--json`

`--allow-writes` is intentionally blocked by the Databricks provider. It exists as an explicit
future policy signal rather than an implicit permission.

The engine reserves an append-only attempt claim before provider execution and writes the terminal
manifest without replacement under
`<out>/runs/<run-id>/workloads/<workload-id>/attempts/<attempt-id>/execution/`. Reusing an attempt
with a terminal manifest is blocked. A claim without a manifest means the outcome is unknown and
also blocks retry. After a failed or timed-out execution, reconcile possible side effects before an
authorized retry with a distinct attempt ID; the original claim and manifest remain unchanged.

The current Databricks execution provider does not submit a remote job. It does not read
`DATABRICKS_HOST`, `DATABRICKS_TOKEN`, Databricks CLI profiles, or SDK default credentials. It
always returns `status: blocked`, `reason_code: remote_submission_disabled`, and
`remote_submission_enabled: false`. A separate DBX-02 boundary can qualify approved enterprise
authentication from exact HENV readiness/deployment evidence, signed activation-backed Vault
resolution evidence, immutable source/generated digests, and injected workspace/identity/permission
probes. Authentication qualification remains distinct from submission, execution, validation, and
parity.

JSON and text modes return nonzero for blocked or failed execution results. `submitted` remains a
schema value reserved for a future attributable remote submission receipt; DBX-02 never emits it.
