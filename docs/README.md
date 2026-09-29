# Documentation Map

This directory is the collaborator-facing documentation surface for the SAS Modernization Factory.

Client- or environment-specific material belongs under `deployments/<deployment>/`. Detailed backlog state belongs in the GitHub Project. One-time implementation history, repair instructions, generated audits, and reconciliation payloads belong in Git/GitHub history rather than permanent product documentation.

## Start here

```text
README.md
   |
   +--> docs/TEAM_ONBOARDING.md        Clean setup, ownership, integration trains
   +--> docs/REPOSITORY_STABILIZATION.md  Preservation and bounded cleanup record
   +--> docs/IMPLEMENTATION_STATUS.md   Current implementation truth
   +--> docs/architecture/overview.md   Target architecture and direction
   +--> docs/factory/discovery-overview.md
   +--> docs/TESTING.md                 Evidence and confidence ladder
   +--> docs/CLI.md                     Product CLI
   +--> docs/operations/runbook.md      Operator and incident procedures
   +--> docs/OPS-03_ACCEPTANCE.md       Runbook acceptance evidence
   +--> docs/BACKLOG_ENGINEERING_WORKFLOW.md
   +--> scripts/engineering-agent/README.md
   +--> GitHub Project                  Detailed backlog/execution state
```

## Documentation by concern

| Area | Primary documents |
|---|---|
| Current truth | `IMPLEMENTATION_STATUS.md`, `CLI.md`, `TESTING.md` |
| Developer workflow | `TEAM_ONBOARDING.md`, `DEVELOPMENT.md`, `GIT_WORKFLOW.md`, `../CONTRIBUTING.md`, `../competition/ACTIVE-OWNERSHIP.yaml` |
| Backlog lifecycle | `BACKLOG_ENGINEERING_WORKFLOW.md`, `../scripts/project-tools/README.md` |
| Engineering agent | `../scripts/engineering-agent/README.md` |
| Architecture | `architecture/overview.md`, `architecture/principles.md`, `architecture/decisions/` |
| Discovery | `factory/discovery-overview.md`, `factory/discovery-acquisition.md`, `factory/canonical-workload-model.md` |
| SAS analysis | `factory/sas-static-reference-discovery.md`, `factory/data-source-output-discovery.md`, `factory/data-lineage-graph.md`, `factory/cross-program-dependency-graph.md`, `factory/external-dependency-connection-inventory.md`, `factory/downstream-consumer-output-discovery.md` |
| Scheduler/runtime | `factory/scheduler-runtime-dependency-discovery.md` |
| Workload understanding | `factory/workload-grouping-boundary-detection.md`, `factory/current-state-workload-topology.md` |
| Modernization planning | `factory/modernization-disposition-input-model.md`, `factory/target-state-pattern-recommendation-inputs.md`, `factory/migration-wave-grouping.md`, `factory/delivery-path-decision-model.md`, `factory/retire-candidate-detection.md`, `factory/consolidation-candidate-detection.md`, `factory/duplicate-redundant-logic-identification.md`, `factory/target-databricks-pattern-mapping.md`, `factory/batch-to-incremental-opportunity-analysis.md`, `factory/intermediate-artifact-elimination-analysis.md`, `factory/target-state-workload-manifest.md`, `factory/modernization-rationale-evidence.md` |
| Assessment | `assessment-engine-v1.md`, `factory/complexity-model.md`, `factory/confidence-model.md` |
| Conversion | `CONVERSION_ENGINE.md`, `conversion/` |
| Execution | `EXECUTION_VALIDATION_V2.md`, `CLI_EXECUTION.md` |
| Validation | `VALIDATION_ENGINE.md`, `validation/`, `VALIDATION_ROADMAP.md` |
| Test corpus | `factory/modernization-test-corpus.md`, `factory/multi-artifact-corpus-fixtures.md`, `factory/synthetic-data-corpus-fixtures.md`, `../tests/corpus/README.md` |
| Operations | `operations/runbook.md`, `operations/`, `OPS-03_ACCEPTANCE.md` |
| Security | `../SECURITY.md`, `architecture/security-model.md` |
| Project tooling | `../scripts/project-tools/README.md` |
| Deployment-specific material | `../deployments/<deployment>/` |

## Reading status correctly

```text
IMPLEMENTED FOUNDATION
Working code + tests for the stated boundary
            |
            v
PARTIAL / FEATURE-GATED
Useful implementation exists; broader capability remains incomplete
            |
            v
NOT IMPLEMENTED
Architecture/backlog only; do not represent as operational
```

Architecture documents describe intended production direction unless they explicitly identify a component as implemented. `IMPLEMENTATION_STATUS.md` is the capability-level truth statement. The GitHub Project is the source of truth for individual work-item state.
