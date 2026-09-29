# Humana: ten-week delivery plan

Local planning baseline, not client acceptance approval or a claim of implemented capabilities.
The user confirmed **10 weeks, 1,000 mixed-complexity SAS scripts, and proof of velocity and
validation**. Calendar dates, pass quota, complexity distribution, data access, tolerances and
resource budgets remain open in [requirements.yaml](requirements.yaml). This plan refines the
[documented objective](../deployments/humana/docs/competition-execution-plan.md); no official
scoring rubric was supplied.

The user also confirmed Humana uses HashiCorp Vault for secrets, Microsoft Entra ID / Active
Directory for identity, and Anthropic as the LLM provider allowed inside its ecosystem. The factory
remains provider-neutral: those are Humana deployment bindings, not portable core dependencies.
Exact authentication flow, scopes, endpoints, models and owner approvals remain open requirements.

## What counts

Track the immutable 1,000-script inventory separately from executable workloads and dependency
groups: multiple scripts may form one workload, and one script may yield multiple outputs.
Only count a distinct script as validated when its required outputs and dependency context meet
the approved policy on attributable source/target evidence. Preserve the script-to-workload mapping.
Do not inflate velocity with retries, duplicate scripts, generated artifacts, skipped checks or
success on easy cohorts alone. Report all excluded/blocked scripts and the unchanged original
denominator alongside any approved eligible-cohort denominator.

Full coverage implies 100 validated scripts/week over ten weeks, 125/week after two setup weeks,
or about 143/week if two setup weeks and one final evidence week leave seven processing weeks.
These are arithmetic scenarios, **not measured capacity or an agreed contractual pass quota**.
Each week forecast `(remaining agreed target - already validated) / remaining processing weeks`;
show complexity, dependency groups, available people/compute, confidence range and blockers.

Report distinct validated scripts and workloads/hour/day/week, first-pass and eventual parity,
straight-through versus human-assisted success, repair attempts, human minutes, p50/p95 elapsed
time, queue age, model/compute cost per validated workload, and counts by complexity and disposition.
Measure cold/no-recall and governed-recall paths separately before claiming a learning benefit.

## Delivery milestones (proposed, relative weeks)

| Window | Exit evidence | Principal work packets |
| --- | --- | --- |
| Week 1 | Versioned inventory and dependency/complexity map; owners and approvals; representative cohorts; baseline and target bindings; measured starting point | HENV, SEC, AD/WLD reuse, BASE-01..04, HPILOT-01 |
| Weeks 1–2 | Thin source → conversion → real Databricks execution → independently validated parity slice, including a deliberately failing case | CV, DBX/DBPKG-01, VAL/DP, ORCH identity/state, PROV |
| Weeks 3–4 | Representative simple, moderate and complex paths; bounded repair, resume and human exception handling; weekly capacity forecast | AIP-01/02/05, REM, LOOP, HR, relevant SASSEM/BASE conditional slices |
| Weeks 5–7 | Dependency-aware controlled batches; measured bottleneck reduction and reproducible scorecards; stable validation | ORCH-05, BENCH, SCORE, HMET, OPS; conditional learning only if measured benefit |
| Weeks 8–9 | Close highest-impact remaining coverage gaps; rerun affected regressions; reconcile blocked cases and independent evidence | Cohort-driven fixes, validation owners, HPILOT-03/04 |
| Week 10 | Reproducible final inventory/status, validation bundles, exceptions, velocity/cost evidence and signed handoff | COMP-01, PROM-01 competition evidence slice, HPILOT-04 |

This is a proposed delivery cadence, not an effort estimate for 186 separate implementations.
Work proceeds in parallel **where dependencies and shared contracts allow**. Instrument the first
slice from day one; do not wait until the benchmarking wave to measure it. AI integration must not
hold up deterministic-path proof. A missed week-two real-data parity gate triggers an explicit
reforecast and escalation, not weaker checks or fabricated evidence. Client access delays remain
visible even when offline engineering can continue.

## Competition versus Phase 2+

The [replan](generated/replan.yaml) assigns every record a phase, priority, sequencing wave,
explicit dependencies, competition slice, later boundary and evidence-review disposition.
[Coverage](generated/issue-specs/_ACCEPTANCE-COVERAGE.md) lists every record. Waves are dependency
and integration groupings, not week numbers or a requirement to finish every earlier-wave item.

- **Competition-critical / P0:** minimum governed source/baseline acquisition, qualified reuse of
  discovery and readiness, conversion, actual remote execution, independent parity, failure/state
  evidence, bounded repair and exceptions, controlled batches and proof of throughput.
- **Competition-conditional / P1:** enable a bounded slice when inventory evidence shows it blocks
  required coverage or an experiment shows it materially improves validated throughput. Examples:
  deeper SAS semantics, additional baseline adapters, profiling/performance validation and governed
  workload recall. Record the affected scripts, owner, expected benefit and dependency/priority update
  before activation. A discovered required construct becomes critical; it cannot remain optional
  merely to improve the score. Evaluate these triggers in week one and weekly, not only at wave 5.
- **Phase 2 / P2:** broad connectors, generalized API/control-plane/platform work, enterprise
  operationalization and expansion beyond the selected target/cohort. Existing completed foundations
  remain reusable; this classification does not undo completed work.
- **Later / P3:** alternate provider/platform and longer-term capabilities with no demonstrated
  competition dependency. The Project's P0–P2 field maps P3 to P2; the spec preserves the later label.

BASE-01..04 move into the critical path: source-of-truth acquisition and mapping cannot wait until
after claims of parity. Approved, reproducible SAS exports can satisfy the bounded acquisition
slice; an enterprise unattended connector suite is not a prerequisite. Thin checkpoint/evidence
storage and competition proof bundles are required now; enterprise services and production promotion
remain separate. General-purpose estate memory is not required in every component.

## What the code actually establishes

These are scoped code/test inspections, not 186 independent implementation certifications.

| Area | Existing evidence and boundary | Consequence |
| --- | --- | --- |
| AD-03/04, discovery/corpus | Static macro evidence and synthetic oracle/regression foundations; see `src/smf/discovery/macro_strategy.py`, `src/smf/corpus/oracle.py` | Reuse, but do not call this executable macro expansion or real Humana SAS baselines |
| READY-01 | `src/smf/readiness/engine.py` verifies supplied byte-bound baseline/mapping/environment evidence | Qualification is not acquisition, live connectivity or parity |
| Conversion / AI | Deterministic provider exists; `src/smf/conversion/providers/ai.py` raises `NotImplementedError` | AIP contracts and an authorized adapter still need implementation/integration |
| Databricks | `src/smf/execution/providers/databricks.py` returns a submitted boundary with remote submission disabled | Local request artifacts are not proof that a remote job ran |
| Validation | `src/smf/validation/structural.py` and corpus oracle compare supplied/synthetic evidence | Acquire trusted source/target data and prove required parity on actual cohorts |
| Orchestration / learning | Supervised engineering orchestration and `review_learning.py` exist | Neither establishes the migration runtime loop nor an estate-wide recall system |

The live-state inspection found TASK-03/04/05/06 Partial under completed AD-02/03/04 parents.
Reconcile their existing implementation and acceptance evidence; do not launch duplicate work or
silently close them. Completed records remain historical foundations, not automatically reapproved
against new cohort requirements. Epics summarize children; Phase 2 children remain visible and
prevent an unqualified claim that the entire epic is complete.

The queue and runner share the canonical completion predicate: both `Done` and `Foundation Complete`
are required. Closed-but-incomplete issues and inconsistent status/implementation fields are
reported as lifecycle blockers, never silently treated as satisfied dependencies.

### Task/parent reconciliation before publication

The following are evidence pointers for review, not new completion attestations:

| Task / completed parent | Existing evidence to inspect | Required disposition |
| --- | --- | --- |
| TASK-03 / AD-02 | `tests/unit/test_include_reconciliation.py`, `tests/unit/test_code_dependencies.py` | Map AC01–03 and applicable shared/integration gates to include-resolution tests, including ambiguity/cycles; approve closure only for proved scope |
| TASK-04 / AD-02 | `tests/unit/test_data_lineage.py`, `tests/unit/test_ad02_reviewer_convergence.py` | Verify qualified identities, producer conflicts and overwrite/source-revision cases individually; retain any gap as approved follow-up |
| TASK-05 / AD-03 | `tests/unit/test_macro_strategy.py`, `tests/unit/test_macro_call_projection.py` | Map the strategy-only fixtures and negative cases; do not infer executable macro expansion |
| TASK-06 / AD-04 | `tests/corpus/README.md`, `tests/unit/test_synthetic_data_corpus.py` | Separately prove the new generator-seed/tier/dimension criteria; existing corpus admission does not establish a complexity-tier generator |

These tasks are blocked from body publication and `work`/`continue` while their
`reconcile-task-with-completed-parent` marker remains. An authorized human must choose evidenced
closure or a bounded follow-up and reconcile the local marker/live lifecycle accordingly. This
update does not close tasks, reopen parents or declare their newer acceptance criteria satisfied.

## Carrying forward both reference repositories

Use the recorded AD-03 decisions and [shared acceptance policy](generated/issue-specs/_ACCEPTANCE-POLICY.md):
source-faithful conversion, construct-specific routing, isolated target scope and independent
reconciliation from the workshop; provenance, applicability, conflict/invalidation, bounded recall
and outcome evidence from Hippo. Recall is advisory, never source truth or a parity/approval override.
The workshop remains patterns-only under the recorded reuse restriction; no source/docs copying.
This plan neither installs Hippo nor adds background capture, embeddings, client data ingestion or
new model permissions. Future actual reuse requires the recorded licensing/security checks.

## Materialized OSS-first recovery backlog

The accepted recovery package is materialized locally from
[`SAS_MIGRATION_RECOVERY_REPORT.md`](SAS_MIGRATION_RECOVERY_REPORT.md). It adds 19 unpublished
records, updates the accepted dependency sets, leaves DP-01 unchanged, defers TASK-06 without
touching its dirty implementation worktree, and does not authorize implementation or live mutation.

The initially runnable roots are: `UPQ-01`, `CLICON-01`, `WLD-03`, `DBX-03`, `SASSEM-01`, `SASSEM-02`, `SASSEM-04`. All other recovery records remain blocked until their
declared prerequisites are canonically complete.

| Record | Priority | Phase | Wave | Dependencies | Recovery scope |
| --- | --- | --- | ---: | --- | --- |
| `TASK-06` | P2 | phase2 | 6 | unchanged/none | set deferred/Todo lifecycle and P2 while preserving Implementation State Partial, all historical evidence, and the dirty worktree pending separately approved disposition |
| `UPQ-01` | P0 | competition-critical | 0 | SEC-03 | upstream revision/artifact/license/capability/disposition gate |
| `LIC-01` | P0 | competition-critical | 1 | UPQ-01, SEC-03 | license, NOTICE, SBOM, provenance and vulnerability acceptance |
| `PKG-DES-01` | P0 | competition-critical | 1 | UPQ-01, LIC-01, HENV-02 | early portability design: runtime matrix, source-only eligibility, offline artifact plan, lock format and intake contract; no final bundle claim |
| `CLICON-01` | P0 | competition-critical | 0 | HENV-02, SEC-01, SEC-02 | early parser/config/schema/result scaffold for smf migrate convert/modernize/status/resume/exceptions/approve/promote and smf ai-gateway preflight; backend operations may return explicit not_implemented/blocked |
| `AIGW-01` | P0 | competition-critical | 1 | PKG-DES-01, CLICON-01, HENV-02, SEC-01, SEC-02, SEC-03 | Humana AI Gateway-only client, mock, configuration schema and preflight; prohibit direct provider access/fallback |
| `CORPUS-11` | P0 | competition-critical | 1 | UPQ-01, LIC-01 | distinguish licensed, evaluation-only, customer-controlled and prohibited binary assets |
| `WLD-03` | P0 | competition-critical | 1 | WLD-01, TASK-03, SEC-05 | complete code/include/call closure with unresolved runtime edges |
| `BASE-07` | P0 | competition-critical | 1 | WLD-03, WLD-04, WLD-05, TASK-04, SEC-05 | physical SAS-native asset inventory |
| `BASE-06` | P0 | competition-critical | 1 | WLD-03, BASE-07, TASK-04, SEC-05 | fail-closed LIBNAME/runtime path binding |
| `BASE-08` | P0 | competition-critical | 1 | UPQ-01, LIC-01, PKG-DES-01, CORPUS-11, BASE-06, BASE-07 | rename “Qualified local SAS binary reader provider”; remove parser construction |
| `VS-01` | P0 | competition-critical | 1 | BASE-08, PROV-01 | first technical gate: real SAS7BDAT → bounded local-reader descriptor/rows → fixture-specific provisional Spark mapping → local Delta → reconciliation → evidence; does not satisfy BASE-04 or BASE-02 |
| `DBX-03` | P0 | competition-critical | 2 | HENV-01, HENV-02, SEC-01, SEC-02 | governed DBR/Spark/Scala/JVM/compute/network/runtime policy |
| `SCALE-01` | P0 | competition-critical | 2 | VS-01, DBX-03, PKG-DES-01 | distributed spark-sas7bdat/Parso qualification; no local-collection acceptance |
| `BASE-04` | P0 | competition-critical | 1 | BASE-08, SCALE-01 | canonical descriptor shared across reader providers |
| `SASSEM-01` | P0 | competition-critical | 1 | CORPUS-02 | promote the three unfinished prerequisites to P0; preserve their existing evidence and acceptance scope |
| `SASSEM-02` | P0 | competition-critical | 1 | CORPUS-02 | promote the three unfinished prerequisites to P0; preserve their existing evidence and acceptance scope |
| `SASSEM-04` | P0 | competition-critical | 1 | CORPUS-02, AD-03 | promote the three unfinished prerequisites to P0; preserve their existing evidence and acceptance scope |
| `BASE-02` | P0 | competition-critical | 1 | BASE-04, SASSEM-01, SASSEM-02, SASSEM-04 | governed type/mapping/semantic policy |
| `BASE-11` | P0 | competition-critical | 2 | BASE-02, BASE-04, BASE-06, BASE-08, SCALE-01 | catalogs, formats/informats, views, indexes, encryption, corruption and unsupported-asset dispositions; no new parser |
| `BASE-09` | P0 | competition-critical | 2 | BASE-07, BASE-11, WLD-05, TASK-04 | six-way asset disposition and persistent-versus-reproducible proof |
| `MODAP-01` | P0 | competition-critical | 2 | BASE-09, WLD-11, WLD-12, MOD-02, MOD-08 | named, attributable target-architecture and business-disposition approval record; binds six-way dispositions, workload boundaries, consolidation/retirement, incremental candidates and target orchestration |
| `CV-04` | P0 | competition-critical | 2 | UPQ-01, LIC-01, PKG-DES-01, BASE-02, CV-02 | harden sas2databricks; deterministic first; gateway-only optional repair |
| `AIREP-01` | P0 | competition-critical | 2 | AIGW-01, CV-04, BASE-02 | bounded deterministic-plus-gateway repair controller |
| `DBPKG-04` | P0 | competition-critical | 2 | BASE-02, BASE-08, SCALE-01, ORCH-04 | restartable reader/Spark-to-Delta orchestration; remove reader/writer engine scope |
| `BASE-10` | P0 | competition-critical | 2 | BASE-02, BASE-03, HENV-02 | governed target mapping |
| `DBPKG-01` | P0 | competition-critical | 2 | DBPKG-04, BASE-10, DBX-02, DBX-03 | upstream Delta + UC provider integration; remove Delta-engine construction |
| `DBX-01` | P0 | competition-critical | 2 | DBX-02, DBX-03, DBPKG-01, CV-04 | retain In Progress / Partial; complete governed remote execution |
| `DBX-04` | P0 | competition-critical | 2 | DBX-01, ORCH-04, PROV-01 | retain In Progress / Partial; immutable runtime receipts |
| `DP-01` | P0 | competition-critical | 3 | unchanged/none | preserve the completed record exactly as Done / Foundation Complete; add no dependency or new acceptance obligation |
| `SCHEMA-INT-01` | P0 | competition-critical | 3 | DP-01, BASE-04, DBPKG-01 | prove the completed DP-01 comparator consumes authoritative cross-provider source and published target descriptors; this is new acceptance, not retroactive DP-01 scope |
| `DP-02` | P0 | competition-critical | 3 | DBPKG-01, DBX-04, BASE-02 | row-count receipt through shared distributed-capable adapter |
| `DP-03` | P0 | competition-critical | 3 | DP-02, DBPKG-01, DBX-04 | keyed/grouped aggregate receipt |
| `DP-04` | P0 | competition-critical | 3 | DP-02, BASE-02, SASSEM-01, SASSEM-02, SASSEM-04 | null/special-missing/distribution receipt |
| `DP-05` | P0 | competition-critical | 3 | DP-02, DBX-04 | deterministic sample receipt, explicitly non-authoritative for full parity |
| `VAL-01` | P0 | competition-critical | 3 | SCHEMA-INT-01, DP-02, DP-03, DP-04, DP-05, DBX-04 | DataComPy/Spark-backed full-row certification; require partitioned/distributed execution for large tables; prohibit whole-table pandas collection |
| `PROV-02` | P0 | competition-critical | 3 | PROV-01, DBPKG-04, DBPKG-01, DBX-04, VAL-01, TASK-24, TASK-25 | end-to-end immutable migration evidence |
| `READY-02` | P0 | competition-critical | 3 | DBX-04, VAL-01, PROV-02 | mandatory migration completion predicate |
| `PKG-QUAL-01` | P0 | competition-critical | 3 | AIGW-01, BASE-08, SCALE-01, CV-04, DBPKG-01, DBX-04, VAL-01, PROV-02 | final source-only/offline bundle qualification using actual provider/transitive artifacts; prove zero runtime public downloads |
| `MIGCLI-01` | P0 | competition-critical | 4 | CLICON-01, PROV-02, READY-02, PKG-QUAL-01, ORCH-01, ORCH-03, ORCH-04 | end-to-end acceptance of smf migrate convert |
| `MODCLI-01` | P0 | competition-critical | 4 | CLICON-01, MIGCLI-01, MODAP-01, PKG-QUAL-01 | end-to-end acceptance of smf migrate modernize; must consume named approval record |
| `MIGOPS-01` | P0 | competition-critical | 4 | CLICON-01, MIGCLI-01, PROV-02 | status/resume/exceptions/approve/promote acceptance |
| `ORCH-02` | P0 | competition-critical | 3 | MIGCLI-01, MIGOPS-01, READY-02, AIREP-01 | complete fail-closed orchestration |
| `HPILOT-04` | P0 | competition-critical | 4 | ORCH-02, MIGOPS-01, PKG-QUAL-01 | authorized Humana pilot gate |
| `COMP-01` | P0 | competition-critical | 4 | HPILOT-04, READY-02, PROV-02 | terminal competition count uses mandatory predicate only |

## Databricks environment bootstrap and readiness

The approved environment capability adds three child records under `EPIC-HENV` without changing
completed-record acceptance or dependencies:

| Record | Priority | Phase | Wave | Dependencies | Bounded scope |
| --- | --- | --- | ---: | --- | --- |
| `DBENV-01` | P0 | competition-critical | 0 | HENV-01, HENV-02, SEC-01, SEC-02, CLICON-01 | strict two-mode environment configuration, non-mutating plan, stable CLI, immutable evidence and fail-closed security mechanics; no provider contact |
| `DBENV-02` | P0 | competition-critical | 2 | DBENV-01, DBX-02, DBX-03, AIGW-01 | least-privilege customer-owned Databricks capability validation; live contact and write probes require separate environment authority |
| `DBENV-03` | P1 | competition-conditional | 5 | DBENV-01, DBX-03, LIC-01, PKG-DES-01 | internal-only Terraform provisioning with destructive-plan guards and separately approved apply |

`DBENV-01` is the only initially runnable DBENV root. `DBENV-02` and `DBENV-03` remain
dependency-blocked. See [the architecture and ownership plan](../.azure/deployment-plan.md).

Implementation must reuse `smf deployment-config`, readiness, Databricks authentication,
HashiCorp Vault, AI Gateway, provenance, protected-path, and independent-review controls. Customer
mode never requires Azure subscription access, Contributor, metastore-admin, broad Unity Catalog, or
infrastructure-creation authority. Environment readiness is separate from SAS conversion failure and
never implies parsing, parity, promotion, migration completion, or customer approval.

## Operational and publication gates

1. Validate the local plan and use its read-only competition queue; ordinary `next` still uses live
   Project priorities and is not a phase-filtered competition queue.
2. Review the changed specs, dependencies and per-item proof. Each spec includes concrete AC01–03,
   a cohort/integration AC04, applicable additional criteria and HC-01..05. Missing evidence is not done.
3. Generate a **fresh** acceptance dry-run. Prior reports are stale after these plan/spec changes.
   Review body changes AND reported live-to-planned priority differences. Body synchronization does
   **not** apply Project priority fields; those require a separately approved field-update operation
   with fresh metadata checks and read-back. Do not run a broad legacy replan apply as a shortcut.
4. Publish only reviewed records, preserving issue identity, parents, status and historical completed
   approvals. The dry-run now proposes exact corrections for the nine identified legacy priority
   lines and records each old/new line, without changing Project fields or other unmanaged prose.
   Review those complete body changes; duplicate legacy labels block publication. Other scope
   contradictions still need explicit decisions. Draft promotion is a separate lifecycle action.
5. Verify exact live managed acceptance and intended priority/parent/status. Only then authorize an
   agent run for one bounded eligible packet. Do not autoapprove, merge, reopen or close items.

```bash
python -m smf.engineering_agent.competition_plan --validate-only
python -m smf.engineering_agent.competition_plan
bash scripts/project-tools/sync-acceptance-specs.sh dry-run
```

The queue reads live state without changing it; eligibility means implementation dependencies are
complete, not that client access, baseline approval, publication or human launch approval exists.
Finalize HC-REQ inputs with named owners before making applicable client acceptance claims.
