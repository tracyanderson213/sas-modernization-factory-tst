# SAS Modernization Factory

The SAS Modernization Factory (SMF) is an engineering platform for analyzing, modernizing, converting, executing, validating, and governing SAS-to-Databricks workload migration.

SMF is intentionally evidence-driven. It separates deterministic discovery and transformation from AI-assisted reasoning, preserves unresolved state rather than guessing, and treats execution and parity evidence as distinct from code generation.

## Current state

At `origin/main` `0690b29a24380a09188f44e0f6b0b258b8d8f128`, the repository contains
reviewed, locally executable foundations for:

- SAS estate discovery and canonical workload modeling;
- governed static LIBNAME/path resolution and explicit unresolved runtime dependencies;
- real `.sas7bdat` reads through pinned `pyreadstat`/ReadStat and partitioned
  `spark-sas7bdat`/Parso qualification;
- canonical descriptors plus governed, underlying-value-first SAS-to-Spark type mapping;
- deterministic SAS-code packaging through pinned `sas2databricks` 0.4.0;
- a real local `.sas7bdat -> Spark DataFrame -> Delta v0 -> DataComPy reconciliation`
  acceptance path with immutable replay and mutation evidence;
- restartable local Spark-to-Delta ingestion, offline Unity Catalog planning, execution-plan and
  runtime-receipt contracts;
- provider-neutral AI Gateway preflight and bounded deterministic-first repair control, with no
  operational gateway transport;
- structural schema, row-count-policy and aggregate-policy foundations;
- supervised Architect / Developer / Reviewer engineering-agent workflows;
- layered corpus, adversarial, integration, security, provenance, and repository quality gates.

The real binary-data path is an acceptance harness (`make vs01-confidence`), not yet one unified
operator command. `smf migrate convert` and the adjacent migration commands remain fail-closed
contract scaffolds that return blocked exit `2`. Live Humana SAS baselines, AI Gateway transport,
Databricks/Unity Catalog execution, distributed cell-level parity, end-to-end certification,
offline-bundle qualification, production orchestration, and a representative Humana rehearsal are
not proven. Canonical backlog completion is not customer-environment proof.

Code conversion, data conversion, validation, AI-assisted repair, and modernization are separate:

| Capability | Current boundary |
| --- | --- |
| SAS code conversion | Deterministic local package mechanics are implemented; unsupported/review-required constructs fail into evidence. |
| SAS data conversion | Real local and partitioned reader paths are proven on licensed public fixtures; customer assets and arbitrary SAS variants are not qualified. |
| Validation | Schema and local fixture reconciliation exist; the `DP-02` through `VAL-01` distributed validation path remains active. |
| AI-assisted repair | Deterministic-first routing and offline gateway contracts exist; no live provider call or repair generation is implemented. |
| Modernization | Inventory and recommendation foundations exist, but full modernization is later competition/January 2027 scope and does not block Day 1 lift-and-shift. |

See [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) for the precise capability boundary.

## Architecture at a glance

The current, status-labeled left-to-right architecture is maintained in
[`docs/architecture/overview.md`](docs/architecture/overview.md). In short:

```text
discover -> LIBNAME/path -> SAS readers -> descriptor/type mapping -> deterministic code conversion
    -> bounded gateway repair -> Spark/Delta -> distributed validation -> evidence/exceptions
    -> later feedback and estate modernization
```

Individual agents receive bounded task context. Estate-wide knowledge belongs in durable, retrievable models and evidence, not in an ever-growing LLM prompt.

The intended enterprise deployment separates an Azure-hosted factory control plane from Databricks execution and target workload hosting. Deployment-specific policy and configuration remain outside the reusable core.

## Quick start

Supported local environment: macOS or Linux with Python 3.12.

```bash
./scripts/bootstrap.sh
source .venv/bin/activate
make verify
```

The package installs two command-line entry points:

```bash
smf --help
smf-agent --help
```

If an editable install has not exposed the entry point in the current shell, the engineering agent can also be invoked directly:

```bash
python -m smf.engineering_agent --help
```

## Primary CLI

```bash
smf discover <source> --out out/discovery.json
smf assess examples/simple/example.sas --explain
smf ready <discovery.json> <evidence.json> --policy <policy.yaml> --run-id <run-id> --attempt-id <attempt-id> --out out
smf convert <source.sas> --deployment-config <factory.yaml> --workload-id <workload-id> --source-artifact-id <artifact-id> --run-id <run-id> --readiness-attempt-id <attempt-id> --readiness-manifest <readiness.manifest.json> --out out
smf validate <source.sas> <generated.py> --target pyspark --out out
smf execute <source.sas> <generated.py> --target pyspark --provider local --out out
smf validate-schema <source-schema.json> <target-schema.json> --out out
```

Those are executable stage commands, but they are not a single end-to-end competition command.
The currently proven binary-data workflow is:

```bash
make vs01-confidence
make scale01-confidence
```

The first runs the exact real local SAS7BDAT-to-Delta acceptance slice; the second runs the
partitioned reader/reconciliation qualification and may use approved build-time upstream access.
Neither contacts Humana, Databricks, Unity Catalog, AI Gateway, or a model provider. See
[`docs/CLI.md`](docs/CLI.md) for the executable/scaffold/offline/live-unavailable matrix.

See [`docs/CLI.md`](docs/CLI.md) for command behavior and evidence boundaries.

## Supervised engineering agent

Backlog execution uses isolated `agent/<backlog-key>` worktrees with bounded Architect, Developer, deterministic-gate, and Reviewer stages.

```bash
python -m smf.engineering_agent next
python -m smf.engineering_agent plan <BACKLOG-KEY>
python -m smf.engineering_agent work <BACKLOG-KEY>
python -m smf.engineering_agent continue <BACKLOG-KEY>
```

The orchestrator does not commit, push, close issues, or mark Project items complete. Final integration remains human-controlled.

See [`scripts/engineering-agent/README.md`](scripts/engineering-agent/README.md).
For the complete start-through-closeout procedure, see
[`docs/BACKLOG_ENGINEERING_WORKFLOW.md`](docs/BACKLOG_ENGINEERING_WORKFLOW.md).

## Repository map

| Path | Purpose |
|---|---|
| `src/smf/` | Reusable factory implementation |
| `tests/` | Unit, integration, corpus, adversarial, and regression evidence |
| `schemas/` | Public machine-readable contracts |
| `rules/` | Deterministic transformation-rule registry |
| `docs/` | Product, architecture, engineering, validation, and operations documentation |
| `deployments/` | Deployment-specific configuration and documentation |
| `scripts/project-tools/` | GitHub Project lifecycle tooling |
| `scripts/engineering-agent/` | Supervised engineering-agent policy and prompts |

Temporary repair bundles, generated audits, one-time reconciliation files, and local run artifacts do not belong in the permanent collaborator-facing repository.

## Documentation

Start with [`docs/README.md`](docs/README.md).

Key references:

- [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md): what is actually implemented now
- [`docs/architecture/overview.md`](docs/architecture/overview.md): target architecture
- [`docs/architecture/principles.md`](docs/architecture/principles.md): architectural principles
- [`docs/factory/discovery-overview.md`](docs/factory/discovery-overview.md): discovery model
- [`docs/TESTING.md`](docs/TESTING.md): evidence and test confidence ladder
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md): developer setup
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution rules
- [`SECURITY.md`](SECURITY.md): security expectations

## Deployment-specific work

Reusable product behavior belongs in `src/smf`. Client-specific configuration, policy, and operational guidance belongs under `deployments/<deployment>/`.

The Humana deployment surface is under [`deployments/humana/`](deployments/humana/). Its competition sequencing is a deployment execution concern, not the identity of the repository.

## Quality gate

Before human integration:

```bash
make verify
./scripts/test-discovery-confidence.sh
```

A green repository test suite is engineering evidence. It is not proof that a SAS workload has executed successfully on SAS and Databricks or achieved business parity.
