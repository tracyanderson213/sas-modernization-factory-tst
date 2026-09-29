# September 27 SAS migration demonstration dashboard

<!-- smf-doc-status: {"source_revision":"70963c8b604b277196313a71405c009bc761ee9d","source_tree":"9f818cb7a690f18f8ba69e6d27214010dd2860a1","refreshed_at":"2026-09-22T14:00:28-04:00","plan_sha256":"e5aee87d80a4e6610c374058b3e0b1f98175a6bc5f24d3939a330dc6dea15bfc","active_records":["AIP-02","BASE-01","VAL-01"],"completed_records":["AIGW-01","AIP-05","AIREP-01","BASE-02","BASE-04","BASE-06","BASE-08","CV-04","DBPKG-01","DBPKG-04","DBX-01","DBX-03","DBX-04","DP-02","DP-03","DP-04","DP-05","HMET-01","OPS-01","ORCH-01","ORCH-03","SCALE-01","SCHEMA-INT-01","SPIKE-02","TASK-11","TASK-12","TASK-24","TASK-25","VS-01"]} -->

## Snapshot authority

- Deadline: **September 27, 2026**.
- Refreshed: **2026-09-22T14:00:28-04:00**.
- Repository source: `origin/main` `70963c8b604b277196313a71405c009bc761ee9d`, tree
  `9f818cb7a690f18f8ba69e6d27214010dd2860a1`.
- State sources: live GitHub Project read-back, actual CLI parsers/help, merged acceptance evidence,
  and the validated 208-record graph in `competition/generated/replan.yaml` plus
  `scripts/engineering-agent/config.yaml`.

The recovery report is historical. This dashboard does not infer current state from its old queue or
dates. A dependency is consumable only after the live Issue is closed and the Project record is
exactly `Done / Foundation Complete`.

## Day 1 exit predicate

The competition Day 1 target is lift-and-shift conversion and validation, not estate redesign:

```text
representative SAS program + real .sas7bdat
  -> discovery and governed LIBNAME/path resolution
  -> qualified SAS reader, metadata and rows
  -> canonical descriptor and governed Spark mapping
  -> deterministic sas2databricks conversion
  -> bounded Humana AI Gateway repair only on deterministic non-success
  -> restartable Spark/Delta execution (Unity Catalog only with separate authority)
  -> distributed schema/row/cell/aggregate/null/sample reconciliation
  -> immutable evidence, exceptions, readiness decision and throughput report
  -> repeatable conversion CLI/runbook from an offline/source-only package
```

Success requires actual executed inputs and outputs, reconciliation, sealed evidence, repeatability,
and measured throughput. Generated code alone is not success. Unsupported or ambiguous assets must
produce actionable exceptions; they may not silently degrade output.

Full modernization, table rationalization, architecture redesign, persistent-versus-reproducible
classification and estate-wide business disposition remain later competition/January 2027 work.

## Proven now

| Capability | Merged evidence | Bounded claim |
| --- | --- | --- |
| Real local binary-data slice | `VS-01`: licensed 5-row/7-column SAS7BDAT through `pyreadstat 1.3.6`, Spark 3.5.8, Arrow 25.0.1, delta-rs 1.6.4, and DataComPy 1.0.4 | Real local mechanism with immutable replay; not Humana or live Databricks proof |
| Partitioned reader | `SCALE-01`: source-built `spark-sas7bdat`/Parso, Spark 3.5.8/Scala 2.12.18, three partitions, 18,638 rows, no whole-table collection | Bounded public-fixture compatibility; final offline JAR intake remains pending |
| Descriptor and mapping | `BASE-04`, `BASE-02`, `SCHEMA-INT-01` | Governed offline descriptors/mapping and target-plan schema integration; not observed UC or SAS parity |
| SAS code conversion | `CV-04`, `SPIKE-02`: pinned `sas2databricks 0.4.0` package and measured construct outcomes | Deterministic package mechanics and explicit unsupported/review outcomes; not broad behavioral coverage |
| AI fallback boundary | `AIGW-01`, `AIREP-01`, `AIP-05` | Provider-neutral offline preflight, deterministic-first control, and governance; no live transport or generated repair |
| Delta/Databricks contracts | `DBPKG-04`, `DBPKG-01`, `DBX-01`, `DBX-04` | Restartable local Delta plus offline UC/execution/runtime-receipt contracts; no live remote execution |
| Lifecycle/evidence foundations | `ORCH-01`, `ORCH-03`, `TASK-24`, `TASK-25` | Attempt/restart, exception, and certification-bundle mechanics; no approval, promotion, or migration completion |
| Executed validation foundations | `DP-02`, `HMET-01`, `OPS-01` | Distributed row-count composition, throughput/outcome accounting, and lifecycle telemetry are canonically complete; none establishes cell parity or customer execution |

The real data slice is invoked by `make vs01-confidence`; the partitioned reader proof is invoked by
`make scale01-confidence`. There is not yet a unified executable `smf migrate convert` backend.

## Active Day 1 records

<!-- active-day1:begin -->
| Record | Live state at refresh | Purpose | Current boundary |
| --- | --- | --- | --- |
| `VAL-01` | `In Progress / Partial` | distributed full-row/cell reconciliation | built-in Spark/DataComPy adapter and contract mechanics active; qualified runtime and authoritative Humana snapshots remain unavailable |
| `BASE-01` | `In Progress / Partial` | trusted SAS baseline acquisition | implementation is merged but real Humana baseline authority remains external; needs bounded closeout review |
| `AIP-02` | `In Progress / Partial` | provider-specific adapter boundary | direct-provider work must not bypass the provider-neutral Humana gateway or introduce provider credentials |
<!-- active-day1:end -->

The active train is `competition/integration-day1-val01`. Canonically completed DP-03/04/05
foundations are inputs to the isolated VAL-01 implementation; no local VAL-01 candidate is
consumable as a completed dependency.

## Exact remaining Day 1 critical path

```text
VAL-01
  -> PROV-02
       +-> READY-02 -----+
       +-> PKG-QUAL-01 --+-> MIGCLI-01
  -> MIGOPS-01
  -> ORCH-02
  -> clean-room conversion/validation rehearsals and competition evidence
```

`PROV-02` also consumes already-complete `DBX-04`, `TASK-24`, and `TASK-25` foundations.
`PKG-QUAL-01` consumes the completed reader, conversion, execution and gateway foundations plus
`VAL-01`/`PROV-02`. No downstream record may consume a local-only predecessor as complete.

## Newly eligible records

| Record | State/relevance |
| --- | --- |
| `VAL-01` | dependency-safe and active; shortest path to end-to-end provenance and readiness evidence |
| `BASE-01` | dependency-safe but externally unqualified against Humana; review the already-merged bounded implementation instead of duplicating it |
| `AIP-02` | dependency-safe but materially different provider/security risk; keep isolated unless it is proven compatible with the gateway-only contract |
| `BASE-11` | eligible but later modernization/edge-case work; not a Day 1 blocker |
| `DBENV-02` | eligible contract work, but customer-owned environment validation needs external details and is not required for the local slice |
| `REM-03` | eligible exception-queue contract; schedule when required by the operator path without displacing reconciliation |

## External blockers

| Required input | Owner | Blocks only |
| --- | --- | --- |
| governed Humana SAS programs/data, legal use, source digests, SAS runtime/version/options/locale/timezone/`YEARCUTOFF`, baseline exports and runtime LIBNAME traces | Humana SAS/source owners | customer-representative validation, authoritative SAS baseline and runtime-generated dependencies |
| keys/alignment, raw-versus-formatted authority, special-missing/deleted-row policy, tolerances and business aggregates | Humana validation/business owners | customer parity and certification; local strict fixtures continue |
| AI Gateway endpoint, route/model alias, auth references, headers, CA/mTLS, timeouts, retry/quota/content policy and test window | Humana AI governance/identity/network/security owners | live preflight and repair only; offline fail-closed contracts continue |
| workspace/runtime/compute policy, UC catalog/schema/volume, storage/grants/network and isolated write authority | Humana platform owner | live Databricks/UC execution and readiness; local Delta continues |
| approved offline wheel/JAR/native closure | Humana software intake/security | final `PKG-QUAL-01`; no runtime public download is allowed |

## Unsupported and fail-closed assets

Until specifically qualified, views with unresolved lineage, semantic indexes, missing/incompatible
catalogs, unqualified formats/informats or FCMP, encrypted/corrupt/truncated datasets, lossy or
unsupported encodings, distinct special-missing values without policy, unresolved deleted-row
semantics, runtime-generated paths/dependencies, and unsupported compression/host/version
combinations remain blocked. An exception must identify the source location/identity, stage, reason,
owner/evidence needed, retryability, permitted next action, and prohibited claim.

## Next 24 hours

1. Complete VAL-01's independent review of the built-in distributed comparison and evidence
   boundary without weakening its fail-closed runtime gate.
2. Qualify the pinned Spark/DataComPy runtime closure and execute the runtime-required lane against
   the licensed SAS7BDAT-to-local-Delta vertical fixture; unavailable dependencies remain blocked.
3. Integrate and canonically close VAL-01 only after that proof, complete gates, remote CI and the
   separately authorized lifecycle workflow pass.
4. Continue through `PROV-02`, readiness/package qualification, `MIGCLI-01`, `MIGOPS-01`, and
   `ORCH-02` without allowing local-only predecessors to satisfy dependencies.
5. Preserve external blockers without converting them into false local success.

## Remaining deadline risks

- The validation, end-to-end evidence/readiness, offline package, unified CLI and rehearsal path is
  still incomplete; the date does not authorize dependency bypass.
- The proven binary slice is public-fixture scale. Distributed cell-level reconciliation and actual
  Humana baseline authority remain absent.
- Live AI Gateway and Databricks/Unity Catalog proof requires external values and authority.
- `smf migrate convert` remains a scaffold until `MIGCLI-01`; operators must not mistake exit `2`
  contract evidence for an executed migration.
- The GitHub API exposed no formal review events for several externally merged PRs even though local
  independent review and CI evidence existed; audit reports must preserve that discrepancy.

## Refresh discipline

Run `python scripts/check-documentation-consistency.py` and this read-only inventory command with
every stabilization/integration boundary:

```bash
python scripts/project-tools/repository-hygiene.py \
  --repo . \
  --ownership competition/ACTIVE-OWNERSHIP.yaml \
  --output .project-audit/repository-stabilization/current.json
```

Refresh this dashboard from `origin/main`, the live Project and the validated graph after canonical
closeouts. Never leave a completed record in the active table, invent a CLI option, or treat local,
synthetic, generated-only or externally blocked evidence as customer proof.
