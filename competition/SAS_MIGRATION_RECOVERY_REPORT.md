# SAS Modernization Factory Competition Recovery Report

> **Historical recovery and authorization record — not current capability status.** This document
> preserves the decisions, proposed mutations, sequencing, and approval basis used during recovery.
> Do not infer present implementation, lifecycle, dependency eligibility, or customer-environment
> proof from it. Use the current
> [`September 27 dashboard`](SEPTEMBER-27-DEADLINE-DASHBOARD.md) and
> [`implementation status`](../docs/IMPLEMENTATION_STATUS.md), backed by the live GitHub Project and
> validated generated plan, for current state.

Date: 2026-09-18
SMF repository inspected: `tbarry3c/sas-modernization-factory`
SMF audited revision: `299c977e5ef145649ecf83400761c52c4d1faffd` (`main == origin/main`)
Package version: **third and final approval package**
Decision status: **proposal only; do not publish, mutate Project state, alter lifecycle fields, launch agents, or implement until the single approval in Section 19 is given**

## 1. Revised recovery decision

The end-to-end migration completion predicate from the original recovery report remains correct. The implementation strategy did not: it treated several mature or promising upstream capabilities as net-new SMF engines.

The corrected strategy is **qualify, adopt, wrap, and harden upstreams first**:

- `sas2databricks` remains the primary `.sas` conversion engine behind the existing SMF adapter.
- `pyreadstat`/ReadStat is the preferred local and moderate-volume SAS binary reader provider.
- `spark-sas7bdat`/Parso is the preferred distributed large-file reader candidate, contingent on Databricks Runtime compatibility and security qualification.
- Delta Lake/delta-rs supplies Delta write/read mechanics; the Databricks SDK supplies workspace and Unity Catalog control-plane integration.
- DataComPy supplies the comparison kernel. SMF owns SAS-aware policy, evidence binding, approval, and completion semantics, not a replacement reconciliation engine.
- The Cognition workshop repositories supply scenario, orchestration, mapping, corpus, and reconciliation patterns. Repositories without an explicit license are evidence only and must not be copied or redistributed.

No new SAS binary parser, reader, conversion engine, Delta writer, or generic dataframe comparison engine is justified by the recovered evidence.

The governing completion claim remains:

> A workload is migrated only when its complete required SAS code/data/metadata/dependency closure is inventoried; every required asset has an approved disposition; required persistent assets are migrated or explicitly replaced/retained; reproducible intermediates are proven reproducible; unsupported assets are resolved or approved as exceptions; converted code executes against governed Delta/Unity Catalog targets; schema, data, and semantic reconciliation pass under approved policies; immutable evidence is independently reviewed; and a human approves completion.

Open-source adoption changes implementation effort, not this predicate or its evidence standard.

### 1.1 Corrected Humana architecture

Humana already owns and operates the AI gateway. SMF does not create, deploy, configure infrastructure for, or operate an AI gateway. The only permitted inference route is:

```text
SMF deterministic/upstream pipeline
  -> SMF-owned Humana gateway client
  -> Humana AI Gateway
  -> Humana-controlled Anthropic passthrough
```

Direct Anthropic, OpenAI, Azure OpenAI, public-provider, or automatic public fallback access is prohibited. At runtime SMF must also require no access to GitHub, PyPI, Maven Central, or any other public service.

AI is a bounded repair service, never an authority or primary implementation:

```text
qualified deterministic/upstream implementation
  -> deterministic validation
  -> Humana AI Gateway diagnosis/repair only when necessary
  -> deterministic revalidation
  -> governed Databricks execution
  -> independent schema/data/semantic reconciliation
  -> bounded retry or human exception
  -> human approval
```

This loop applies to source conversion, schema/type mapping, formats/informats, and repairable execution or reconciliation defects. AI may not parse SAS binaries, reconstruct corrupt data, invent source rows, baselines, metadata, business meaning, target policy, approval, or exception authority. Every AI-produced change is untrusted until deterministic validation, execution, reconciliation, immutable evidence, independent review, and human approval all pass.

## 2. Recovery scope and unresolved history

The following evidence was exhausted before preparing this revision:

- current SMF code, history, documentation, dependency declarations, adapters, tests, generated issue specifications, engineering-agent run evidence, and local session history;
- the existing `sas2databricks` adapter and installed package metadata;
- the Cognition SAS-to-Databricks workshop and the upstream repositories it names;
- recorded public SAS corpus sources and the Hippo memory experiment;
- upstream source, license, tests, fixtures, and current GitHub metadata for candidate readers, Spark connectors, Delta writers, Databricks integration, and comparison frameworks;
- cached referenced-conversation previews available to this project.

The environment does not expose the `read_thread` capability, the local ChatGPT browser surface was unavailable, and the cached conversation previews do not contain the user’s original link list. Therefore, **additional user-supplied projects may still be unrecovered**. The list below is complete for the evidence currently accessible, but it is not represented as proof that no other prior links existed. No user action is required before reviewing this report; any later recovered link must enter the same qualification gate before it changes a disposition.

## 3. Recovered upstream inventory and license assessment

Activity is assessed as of 2026-09-18 from the pinned revision and repository state. “Active” means recent repository work, not enterprise support or fitness for Humana.

### 3.1 Core implementation candidates

| Upstream and exact evaluated revision | License and redistribution obligations | Activity | Disposition |
|---|---|---|---|
| `navintkr/sas2databricks@392d3a34c1390f6335fb47e165a4f4f3ac03111c` (0.4.0) | MIT; retain copyright and license | Active/beta; pushed 2026-06-23 | **Wrap behind existing SMF conversion provider; harden** |
| `Roche/pyreadstat@12cc1495d468ae8a170c57cce7557c147b972eac` (1.3.6 plus two commits) | Apache-2.0 package plus embedded ReadStat MIT; carry both notices, Apache license/NOTICE duties, mark modifications | Active; pushed 2026-08-12 | **Adopt through an SMF reader provider** |
| `WizardMac/ReadStat@5850fb57dfc0301f62c745c547763610e5a6c347` | MIT; retain notice | Active; pushed 2026-09-17 | **Reuse through pyreadstat; direct C only if profiling proves necessary** |
| `saurfang/spark-sas7bdat@dad0840bd89b7581c35a41ce372c61dc42d15eab` (3.0.0 plus 13 commits) | Apache-2.0; carry license/NOTICE, mark modifications | Active; pushed 2026-01-22; docs cover Spark 2.4/3.0/3.5 | **Wrap as distributed reader after DBR qualification** |
| `epam/parso@3c514e66264f5f3d5b2970bc2509d749065630c0` (2.0.14 plus one commit) | Apache-2.0 | Maintained slowly; pushed 2026-01-26 | **Reuse transitively through spark-sas7bdat; fork only for proven defect** |
| `delta-io/delta-rs@6a954aff7503103f9cc7a9c7878fe330ec57e080` (Python 1.6.4) | Apache-2.0 | Very active | **Adopt for local staging behind Delta provider** |
| `delta-io/delta@3b1b99cd077ec9c84c8a94c250dea3730cc33392` | Apache-2.0 | Very active | **Adopt native Delta/Spark runtime; never reimplement** |
| `apache/spark@6aa2688a21e3fbc9db9abc2a66e47a951fa94702` | Apache-2.0 | Very active | **Adopt as approved platform runtime** |
| `databricks/databricks-sdk-py@d56f2da7c0b64b907937b05c6f7f4278668ec965` | Apache-2.0 | Very active | **Adopt behind existing Databricks provider boundary** |
| `capitalone/datacompy@16c4a3b07abf8271f65fc0456c3e354dcc70bb48` (1.0.4 plus eight commits) | Apache-2.0 | Very active | **Wrap as comparison kernel; add SAS policy/evidence in SMF** |
| `pandas-dev/pandas@cf85d5d203826cab8e164e3ccbe755e49f328d99` | BSD-3-Clause; retain notice/disclaimer; no endorsement | Very active | **Reject as primary SAS reader; retain as dataframe layer/fallback** |
| `great-expectations/great_expectations@8bfb2b2989dc2707a859a997c422e87590a6c3fb` | Apache-2.0 | Very active | **Reject for core reconciliation; optional data-quality policy only** |
| `databrickslabs/remorph@fec265c8cca1d1aa63645820bd2de0cfa7b022a9` | Databricks License, not OSI open source; use/redistribution restricted to Databricks Services and subject to termination | Active | **Patterns only unless Legal/platform owners separately approve** |
| `FredHutch/sas7bdat@7b28fd3b3da8c161f3c6f8d110f33933aa76a7d0` | MIT | Active | **Reject for ingestion; writer-only fixture research** |

For Apache-2.0 components, SMF must retain the license, preserve NOTICE content when present, mark modified files, and retain patent/attribution terms. MIT/BSD components require their notices and disclaimers in redistribution. This report is an engineering assessment, not a substitute for formal Legal approval.

### 3.2 Workshop, scenario, and corpus sources

| Upstream and exact evaluated revision | License | Contribution and disposition |
|---|---|---|
| `Cognition-Partner-Workshops/uc-data-migration-sas-to-databricks@4db2b770f8be05e48e90aea1e809b87137829aba` | **No license found** | dbt/UC/workflow/reconciliation architecture; **patterns only, no copying** |
| `Cognition-Partner-Workshops/ts-sas-legacy-analytics@ef511409f2bd93ff6304084edef8cc064ad7dad5` | Unlicense | runnable SAS scenario, macros, formats, golden-output concept; **reuse selected licensed components/patterns** |
| `Cognition-Partner-Workshops/uc-data-migration-sas-to-snowflake@6519f37fab7875804219b4bd29a9bf2ae15f2246` | **No license found** | seven `.sas7bdat` samples and validation patterns; **evaluate in place only, do not redistribute** |
| `lexjansen/cdisc-core-sas@c9928c6819e0064e41c4af6606dc2839ddf750ef` | MIT | public SAS corpus; not an engine |
| `sascommunities/fundamentals-programming-sas@75276cae15a57cb904e37087237b8dc792eaa0de` | Apache-2.0 | public SAS code/data corpus |
| `sascommunities/learning-sas-by-example-2nd@c38a76c55309a7824d9190cb21b967703999c228` | Apache-2.0 | public SAS code corpus |
| `sascommunities/sas-access-samples@6e2fb148ee64aeda1e8e0a5d49689a0145afee13` | Apache-2.0 | connection-discovery corpus |
| `sasjs/core@5776bd3806d8fc64523c5dd3db8ec783ed0364ed` | MIT | production-style macro corpus |
| `sassoftware/sas-code-examples@579e057f90cd699f744fd6a1c8acaf9243f7ff67` | Apache-2.0 | vendor-authored SAS corpus |
| `kitfunso/hippo-memory@f774b2db885d7f7c87dccb38b7f0ae919b14dc36` | MIT | recall/provenance patterns only; outside minimum data path |

### 3.3 Functional qualification detail

| Upstream | SAS/artifact capability | Scale/target/validation capability | Security, dependencies, and known limitations |
|---|---|---|---|
| sas2databricks | Converts PROC SQL, DATA step, macros, multiple PROCs and FORMAT/INFORMAT to PySpark/SQL/DLT/workflows; no binary reader | project conversion, bundles, generated validation notebooks | install without its direct-provider extra; all model work must use the SMF-owned client through the Humana AI Gateway’s Anthropic-compatible protocol; sanitize context, preserve provenance, and block review-required/unfulfilled nodes |
| pyreadstat/ReadStat | SAS7BDAT/XPORT rows; metadata-only; names, labels, types, widths, row counts, timestamps, encoding; SAS7BCAT/value labels; format/informat strings; CHAR/BINARY compression fixtures; no proven SAS view/index semantics | selected columns, offset/limit, chunks and multiprocessing; pandas/polars output; no native Spark/Delta/UC or reconciliation | native C/Cython, zlib/iconv, NumPy/dataframes; upstream says it is not validated; host/version, encrypted/corrupt/deleted-row/special-missing/large-file matrices remain; observed chunk dtype drift requires SMF schema stabilization |
| spark-sas7bdat/Parso | SAS7BDAT rows/metadata; CHAR and BINARY compression, encoding, formats/labels; no catalog/view/index proof | Spark DataFrames, distributed filesystems, splittable uncompressed input, CSV/Parquet; README reports 200 GB but SMF has not reproduced; Delta via Spark | JVM/Scala/Spark/Parso supply chain and DBR compatibility; local suite not executed because Maven/SBT unavailable |
| pandas `read_sas` | SAS7BDAT/XPORT, but less catalog/value-label metadata and often caller-supplied encoding | iterator/chunksize; local DataFrame only | insufficient metadata surface for primary selection |
| Delta Lake/delta-rs/Spark/Databricks SDK | no SAS parsing | authoritative Delta mechanics; local/cloud writes; Spark runtime; SDK UC control plane | native/JVM/cloud dependencies; protocol, credentials, concurrency, retention/vacuum, collision and unknown-write policy required |
| DataComPy | no SAS parsing | pandas/Polars/Spark comparisons; row/column overlap, exact/tolerant comparison and reports | join keys, duplicates, null/special missing, tolerance, ordering and canonicalization remain SMF policy |
| Great Expectations | no SAS parsing | data-quality expectations, not complete source-target equivalence | avoid a second validation framework absent a demonstrated need |
| Cognition repos | scenario conversions, mappings, dbt/workflows, seven binaries in Snowflake repo | count/aggregate/sample reconciliation patterns | two migration repos have no license; demonstrations are not independent qualification |
| Remorph/Lakebridge | workload migration/reconciliation patterns, not a SAS binary reader | Databricks-oriented | restrictive Databricks License; not selected dependency |
| FredHutch writer | writes 64-bit UNIX little-endian SAS7BDAT; no reading | no ingestion/reconciliation | synthetic writer output cannot prove customer SAS compatibility |

## 4. Executed qualification evidence

Qualification ran in an isolated Python 3.12.13 environment. Nothing was added to the SMF dependency graph.

### 4.1 Conversion

- `sas2databricks@392d3a3`: upstream suite **44 passed**.
- The SMF adapter already pins `sas2databricks>=0.4,<0.5`, strips CLI trailer noise, and retains review/provenance metadata.
- Binary fixture result: not applicable; it converts source code and does not read SAS datasets.

### 4.2 Binary, catalog, corruption, and scale-smoke tests

Versions: `pyreadstat 1.3.6`, `pyarrow 25.0.1`, `deltalake 1.6.4`, `datacompy 1.0.4`.

| Test | Result |
|---|---|
| Binary-compressed `sample_bincompressed.sas7bdat`, SHA-256 `641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c` | **Pass**: 5 rows, 7 columns, UTF-8; formats/informats, widths, table name and timestamps extracted |
| Metadata-only read | **Pass**: zero materialized rows; 5-row/7-column descriptor |
| Chunks 2/2/1 | **Values pass; hardening required**: `dtime` was `datetime64[us]` for full read and `object` after chunk concatenation |
| SAS7BCAT `test_formats_linux.sas7bcat`, SHA-256 `dc93b77d27a2fc0de92c53b3f9135b63a897d3ddb1aac7ced8259cadbb0eeb66` | **Pass**: two value-label sets applied to three rows |
| Non-ASCII path | **Pass**: 5 rows, UTF-8 |
| Truncated binary | **Pass negative**: `ReadstatError: Unable to read from file` |
| Cognition Snowflake samples | **7/7 pass**: 141,740 rows total; largest 122,760 rows / 5,111,808 bytes |
| Parso corpus | 134 SAS7BDAT fixtures found; not executed because Maven/SBT unavailable |
| spark-sas7bdat corpus | 4 SAS7BDAT fixtures found; not executed because SBT and approved DBR unavailable |

The Cognition fixtures were evaluated in place only. Their unlicensed repository prevents check-in or redistribution without permission.

### 4.3 Proven local vertical smoke

The compressed SAS binary was read by pyreadstat, normalized into an explicit Arrow/Spark-compatible staging schema, written as Delta version 0 by delta-rs, read back, and compared by DataComPy on `mychar` with zero tolerance.

- Delta rows: **5/5**; all rows overlap and intersecting rows match.
- Delta log SHA-256: `72bbdce86f29983c200901d11745c065503d38b4a085878f72557332c449dc53`.
- Parquet SHA-256: `c394a9160957e01f02b1aa089d646118e34861243b7025c463b4a156647821eb`.
- Qualification JSON SHA-256: `445b0c9dc2ab332723d10301301c64d3ae9bc0cc2e87b617b8f2fead42bf7081`.

This is qualification evidence, not an SMF implementation or migration claim. The time column required an explicit normalization decision, no Spark runtime was invoked, and evidence is not yet emitted through `PROV-01`.

## 5. Capability-to-upstream matrix, requirements A through M

| Requirement | Selected upstream | Integration and hardening | Genuine net-new gap | Tests/evidence |
|---|---|---|---|---|
| A. Physical discovery | current SMF discovery; OS paths; Cognition patterns | extend inventory with roots, symlinks, digest, accessibility and missing-reference binding | physical closure and approved-root policy | mixed asset tree; missing/inaccessible/duplicate/mutated files |
| B. Library/path resolution | current parser plus public/Cognition SAS corpus | resolver consumes config/autoexec/env; handle reassignment, concatenation, engine, scope and macro ambiguity | runtime-only binding disposition | positive/negative config matrix; no arbitrary SAS execution |
| C. Binary reader | pyreadstat local; spark-sas7bdat distributed | two providers under typed contract; qualify host/version/compression/encoding/corrupt/encrypted/schema consistency | provider selection/support matrix only | pinned fixtures, DBR matrix, large-file/resume, SBOM/CVE |
| D. Schema/metadata | pyreadstat and Spark metadata | canonical descriptor; declared-vs-observed; stable temporal/missing types | canonical SMF descriptor/evidence schema | metadata/full/chunk agreement; mutation |
| E. Lifecycle classification | Cognition patterns plus SMF dependency graph | ledger linked to physical/code closure; hidden-consumer/restart controls | owner-approved classification logic | two workloads, hidden consumer, restart, mutation |
| F. Type/target policy | Spark types, sas2databricks, Cognition mappings | governed mapping for length/precision/encoding/missing/temporal/formats | customer-approved mappings/tolerances | boundary-value matrix and approvals |
| G. Restartable ingestion | pyreadstat chunks or Spark DataFrame into Delta | checkpoint wrapper; stable schema, idempotency, quarantine, unknown outcome | SMF run/attempt ledger | interruption/resume, changed source, duplicate attempt, isolation |
| H. Delta/UC | Delta Lake/delta-rs/Spark and Databricks SDK | provider integration; protocol, collision, grants, drift and rollback | approved target mapping/evidence binding | local Delta then authorized UC create/register/read-back/deny |
| I. Catalog/view/index | pyreadstat SAS7BCAT; conversion/workshop format patterns | catalog provider; explicit view/index/unsupported dispositions | view/index policy and exception workflow | catalog/missing catalog; authorized SAS view/index baseline |
| J. Databricks execution | sas2databricks bundles, Spark, Databricks SDK | existing providers; Entra/Vault refs, compute, timeout/cancel/unknown result | authorized live configuration | auth/deny/timeout/cancel/stale-ID receipts |
| K. Reconciliation | DataComPy plus Cognition controls | SAS canonicalization and evidence adapters; duplicates, special missing, formatted/raw, keyless, tolerances | policy/certification aggregation, not compare engine | exact/mutated/tolerance/empty/duplicate/unordered actual snapshots |
| L. Evidence/certification | `PROV-01` and upstream provenance | bind versions/config/digests; tamper/staleness/reviewer/human approval | end-to-end evidence graph/completion policy | omit/substitute/mutate each node; signed immutable record |
| M. Corpus | licensed public corpora, reader fixtures, Cognition evidence, approved SAS/customer assets | license-separated manifest; producer/version/host coverage and PHI isolation | authorized Humana/SAS baseline and special assets | local slice, DBR slice, approved SAS-produced workload |

## 6. Explicit dispositions

1. **Adopt directly:** Spark, Delta Lake, delta-rs for local qualification, Databricks SDK.
2. **Wrap:** pyreadstat/ReadStat, spark-sas7bdat/Parso, sas2databricks, DataComPy.
3. **Fork and harden:** none now. Consider only after reproducible defect, upstream issue/patch assessment, license review, and proof an adapter cannot contain it.
4. **Reuse selected licensed components:** the Unlicensed Cognition legacy scenario and MIT/Apache public corpora with notices/attribution.
5. **Patterns only:** unlicensed Cognition migration repositories, Remorph absent separate approval, Hippo memory.
6. **Reject:** pandas as primary reader, Great Expectations as core reconciliation, FredHutch writer as ingestion, and any invented parser/writer/comparator while selected upstreams meet the mechanics.

## 7. Complete next P0 recovery program

This dependency-complete program is the proposed next workstream. Every record is P0, `Todo`, and `Not Started` unless an existing foundation state is explicitly preserved. It is **not published**. “Stop” always includes protected-path, security/data-boundary, destructive/external-action, contractual ambiguity, contradictory requirement, systemic architecture conflict, or unresolved independent-review rejection.

| # | Record and category | Owner | Dependencies | Acceptance and evidence | Additional stop rule | Estimate |
|---:|---|---|---|---|---|---:|
| 1 | `UPQ-01` upstream qualification | Dependency architect | SEC-03 | exact revision, artifact, license, activity, capability, limitation and disposition for every recovered upstream; signed inventory | unlicensed copying or unpinned input | 3–5 d |
| 2 | `LIC-01` license/SBOM gate | Security + Legal liaison | UPQ-01, SEC-03 | licenses/NOTICE, transitive SBOM, hashes, provenance and vulnerability results accepted | license ambiguity or risk exception | 3–5 d |
| 3 | `PKG-01` Humana-portable packaging | Release engineer | UPQ-01, LIC-01, HENV-02 | source-only and offline bundles reproduce without public network; manifest names every file/hash/bootstrap step | missing platform wheel/JAR, compiler, or intake approval | 5–8 d |
| 4 | `AIGW-01` Humana AI Gateway client | Integration engineer + Humana AI owner | HENV-02, SEC-01/02/03, PKG-01 | mock contract, sanitized receipts, preflight, Entra/approved auth, TLS, throttling, bounded retry and fail-closed tests | direct provider route, uncertain timeout, malformed/content-filtered result | 6–10 d |
| 5 | `CORPUS-11` governed binary corpus | Test/data engineer + SAS SME | UPQ-01, LIC-01 | licensed/evaluation-only/customer-controlled partitions; producer/version/hash manifest; real binary positive/negative fixtures | unknown redistribution or fixture provenance | 4–6 d |
| 6 | `WLD-03` complete code closure | Discovery architect | WLD-01, TASK-03, SEC-05 | source/include/call closure with spans, digests and unresolved dynamic edges | runtime-only or contradictory entry point | 3–5 d |
| 7 | `BASE-07` physical SAS asset inventory | Data migration engineer | WLD-03/04/05, TASK-04, SEC-05 | observed and referenced-missing SAS datasets/catalogs/views/indexes/transports/configs with physical identity and SHA-256 | unauthorized root, path escape, inaccessible evidence | 5–8 d |
| 8 | `BASE-06` LIBNAME/runtime path binding | SAS architect | BASE-07, WLD-03, TASK-04 | config/autoexec/env/bounded-macro resolution with scope, reassignment and concatenation history | unresolved macro/runtime binding without authorized trace | 5–8 d |
| 9 | `BASE-08` local reader provider | Data platform engineer | UPQ-01, LIC-01, PKG-01, CORPUS-11, BASE-06/07 | pinned pyreadstat adapter; stable descriptor/chunk contract; corrupt/encrypted/encoding/compression matrix | schema drift, lossy decode or unsupported host variant | 6–10 d |
| 10 | `VS-01` vertical technical gate | Data platform + validation engineers | BASE-08, PROV-01 | actual SAS7BDAT → descriptor/rows → Spark schema → local Delta → exact reconciliation → immutable evidence | any mock/name-only evidence or unexplained mismatch | 6–10 d |
| 11 | `SCALE-01` distributed reader qualification | Databricks data engineer | VS-01, PKG-01, DBX-03 | approved spark-sas7bdat/Parso artifacts pass DBR/Spark/Scala/JVM, compressed and large-file tests | runtime binary incompatibility or unbounded memory | 6–10 d |
| 12 | `BASE-04` canonical SAS descriptor | Data architect | BASE-08, SCALE-01 | one versioned metadata/schema contract across local/distributed providers; replay proves equivalence | provider observations cannot be reconciled | 5–8 d |
| 13 | `BASE-02` type/mapping policy | SAS + Databricks architects | BASE-04, SASSEM-01/02/04 | approved temporal, precision, length, encoding, missing, format/informat and key policy | lossy mapping without owner approval | 5–8 d |
| 14 | `BASE-11` catalogs/special assets | SAS SME + data architect | BASE-02/04/06/08, SCALE-01 | every catalog/view/index/encrypted/corrupt/unsupported asset has a disposition from Section 15 | discovery without executable disposition | 6–10 d |
| 15 | `BASE-09` persistent/intermediate disposition | Modernization architect + business data owner | BASE-07/11, WLD-05 | every asset is migrate/reproduce/consolidate/replace/retain/retire; reproducible intermediates have complete producer/consumer/restart proof | hidden consumer, incomplete history or missing owner | 6–10 d |
| 16 | `CV-04` sas2databricks hardening | Conversion engineer | UPQ-01, LIC-01, PKG-DES-01, BASE-02, CV-02 | deterministic conversion first; gateway-only repair handoff; provenance/review flags and unsupported constructs preserved | direct model access or AI-only success | 6–10 d |
| 17 | `AIREP-01` deterministic-plus-AI repair controller | Orchestration + validation engineers | AIGW-01, CV-04, BASE-02 | bounded diagnose/repair/revalidate loop for code/mapping/formats/execution/reconciliation; immutable attempt chain | invented semantics/data, exhausted repair, uncertain external outcome | 5–8 d |
| 18 | `DBPKG-04` restartable ingestion | Data platform engineer | BASE-02/08, SCALE-01, ORCH-04 | idempotent chunks/partitions, checkpoints, quarantine, two-workload isolation and changed-source invalidation | unknown write outcome or partial success | 8–12 d |
| 19 | `BASE-10` target mapping | Databricks architect | BASE-02/03, HENV-02 | approved catalog/schema/table/storage/partition/owner mapping with collision prevention | default or unauthorized namespace | 4–6 d |
| 20 | `DBPKG-01` Delta/Unity Catalog integration | Databricks data engineer | DBPKG-04, BASE-10, DBX-02/03 | upstream Delta write, UC register/grant/read-back, drift/collision/rollback evidence | unauthorized live write, stale target or ambiguous rollback | 8–12 d |
| 21 | `DBX-03` governed compute policy | Databricks platform + security | HENV-01/02, SEC-01/02 | approved DBR/runtime/network/identity/quota/timeout/cancel policy and negative tests | missing owner policy or data-boundary change | 4–6 d |
| 22 | `DBX-01` + `DBX-04` execution and receipts | Databricks integration engineer | CV-04, DBPKG-01, DBX-02/03 | governed submit/status/cancel plus immutable job/task/package/target/log receipts; unknown outcomes block retry | uncertain side effects or stale/forged receipt | 10–15 d |
| 23 | `DP-01..05` + `VAL-01` reconciliation | Validation architect + SAS SME | BASE-02/04, DBPKG-01, DBX-04 | one DataComPy-backed adapter emits schema, counts, full rows/cells, aggregates, missing/distribution and sample receipts; mutations fail | missing source/target snapshot, unresolved duplicates/tolerance | 10–16 d |
| 24 | `PROV-02` + `READY-02` audit/completion | Governance engineer + independent Reviewer | DBX-04, VAL-01, TASK-24/25 | tamper-evident end-to-end graph and exact mandatory completion predicate; omitted-node matrix blocks | self-authored approval, stale evidence or missing Reviewer | 8–12 d |
| 25 | `MIGCLI-01` fast conversion CLI | CLI/platform engineer | PROV-02, READY-02, ORCH-01/03/04 | `smf migrate convert` contract in Section 12 passes E2E, resume and blocked-state tests | stage bypass or premature success | 8–12 d |
| 26 | `MODCLI-01` modernization CLI | Modernization + CLI engineers | BASE-09, architecture approval, MIGCLI-01 | `smf migrate modernize` performs six-way disposition, redundancy/boundary/incremental/target design, approval, then full migration | unapproved architecture/business disposition | 10–15 d |
| 27 | `MIGOPS-01` lifecycle controls | CLI + governance engineers | MIGCLI-01, PROV-02 | status/resume/exceptions/approve/promote are identity-bound, append-only and fail closed | overwritten attempt, caller-authored authority or cross-run replay | 8–12 d |
| 28 | `ORCH-02` complete orchestration | Platform architect | all provider/reconciliation/CLI records | deterministic stage graph, bounded recovery, two-workload isolation and failure-at-every-stage suite | systemic conflict or unsafe retry | 8–12 d |
| 29 | `HPILOT-04` authorized Humana pilot | Program lead + Humana/SAS/Databricks approvers | ORCH-02, MIGOPS-01 | approved real cohort completes both evidence and human gates under quotas/retention | missing access/baseline/tolerance/approver | 5–8 d + external lead |
| 30 | `COMP-01` competition completion gate | Program lead + independent Reviewer | HPILOT-04, READY-02 | only mandatory-predicate-complete workloads count; Project closure separately approved and read back | aggregate/code-only/synthetic claim | 3–5 d |

Estimated total effort: **179–282 engineer-days**, plus Humana software-intake, gateway, Databricks, SAS-baseline, security, Legal and business-approval lead time. Parallel waves reduce elapsed time; they do not remove any acceptance gate.

### Genuine net-new gaps

- complete physical-to-logical SAS asset closure and runtime ambiguity handling;
- stable cross-provider SAS descriptor and chunk/checkpoint contracts;
- SAS temporal, missing, format/catalog, view/index, keyless and mapping policy;
- Entra/Vault-bound provider configuration and Databricks execution controls;
- immutable binding of source, upstream revisions, conversion, Delta version, runtime receipt, comparison policy/result, review, exceptions, and human approval;
- end-to-end completion semantics and prohibited premature states.

These are integration/governance responsibilities, not reasons to rebuild parsers, writers, or comparison kernels.

## 8. Required reassessment of named items

- **BASE-08:** no parser implementation; qualify/wrap pyreadstat and later spark-sas7bdat.
- **BASE-11:** no catalog/view/index parser; use catalog support and record unsupported dispositions.
- **DBPKG-04:** no ingestion engine; add restart/checkpoint/evidence around readers and Delta.
- **DBPKG-01:** no Delta writer; use Delta/Spark/SDK and own authorization/collision/drift/evidence.
- **CV-04:** no new converter; harden the existing sas2databricks provider and route optional repair only through the SMF-owned Humana AI Gateway client using the gateway’s Anthropic-compatible protocol.
- **DP-02 through DP-05:** one DataComPy adapter, four distinct policy/evidence receipts.
- **VAL-01:** certification/policy aggregator only; no comparison engine.
- **CORPUS-11:** qualify licensed upstream fixtures and acquire only genuine gaps/customer baselines.

## 9. Revised sequence

```text
UPQ-01 -> LIC-01 -> PKG-01 -------------------------------> AIGW-01
    |          |                                               |
    |          +-> CORPUS-11                                   v
    |                    |                                  AIREP-01
    v                    v                                      |
WLD-03 -> BASE-07 -> BASE-06 -> BASE-08 -> VS-01 -> SCALE-01   |
                                      |              |          |
                                      v              v          |
                                  BASE-04 -> BASE-02 -> BASE-11 |
                                                   |       |    |
                                                   v       v    v
                                                BASE-09   CV-04
                                                   |       |
                                                   v       v
                                             DBPKG-04 -> DBPKG-01
                                                          |
                                         DBX-03 -> DBX-01/04
                                                          |
                                                DP-01..05 / VAL-01
                                                          |
                                                PROV-02 / READY-02
                                                          |
                     MIGCLI-01 -> MODCLI-01 -> MIGOPS-01 -> ORCH-02
                                                          |
                                                   HPILOT-04 -> COMP-01
```

The critical path is qualification/license/packaging → inventory/binding/local reader → `VS-01` → distributed reader/canonical policy → ingestion/publication/execution → reconciliation/evidence → CLI/orchestration → pilot → completion.

The proposed **first execution wave** is `UPQ-01`, `LIC-01`, `PKG-01`, `AIGW-01` through mock/config/preflight qualification only, `CORPUS-11`, `WLD-03`, `BASE-07`, `BASE-06`, `BASE-08`, and `VS-01`. Work may run in dependency-safe parallel. `VS-01` remains the first technical gate; downstream records are published and prioritized but remain dependency-blocked until it passes.

## 10. Exact proposed Project mutations

No mutation has been applied. This Section 10 table is the authoritative correction to the earlier P0 summary. New or incomplete records are proposed as Priority `P0`, Status `Todo`, Implementation State `Not Started` unless a row explicitly preserves an existing foundation/partial state.

| Record | Parent/owner | Exact proposed dependency set | Exact mutation |
|---|---|---|---|
| `TASK-06` | existing owner | unchanged | set deferred/Todo lifecycle and `P2` while preserving Implementation State `Partial`, all historical evidence, and the dirty worktree pending separately approved disposition |
| `UPQ-01` new | `EPIC-BASE` / dependency architect | `SEC-03` | upstream revision/artifact/license/capability/disposition gate |
| `LIC-01` new | security/dependency owner | `UPQ-01,SEC-03` | license, NOTICE, SBOM, provenance and vulnerability acceptance |
| `PKG-DES-01` new | release/deployment owner | `UPQ-01,LIC-01,HENV-02` | **early** portability design: runtime matrix, source-only eligibility, offline artifact plan, lock format and intake contract; no final bundle claim |
| `CLICON-01` new | CLI/platform owner | `HENV-02,SEC-01,SEC-02` | early parser/config/schema/result scaffold for `smf migrate convert/modernize/status/resume/exceptions/approve/promote` and `smf ai-gateway preflight`; backend operations may return explicit `not_implemented`/blocked |
| `AIGW-01` new | integration/security owner | `PKG-DES-01,CLICON-01,HENV-02,SEC-01,SEC-02,SEC-03` | Humana AI Gateway-only client, mock, configuration schema and preflight; prohibit direct provider access/fallback |
| `CORPUS-11` new | corpus owner | `UPQ-01,LIC-01` | distinguish licensed, evaluation-only, customer-controlled and prohibited binary assets |
| `WLD-03` | discovery owner | `WLD-01,TASK-03,SEC-05` | complete code/include/call closure with unresolved runtime edges |
| `BASE-07` | `EPIC-BASE` / data migration owner | `WLD-03,WLD-04,WLD-05,TASK-04,SEC-05` | physical SAS-native asset inventory |
| `BASE-06` | `EPIC-BASE` / SAS architect | `WLD-03,BASE-07,TASK-04,SEC-05` | fail-closed LIBNAME/runtime path binding |
| `BASE-08` | `EPIC-BASE` / data platform owner | `UPQ-01,LIC-01,PKG-DES-01,CORPUS-11,BASE-06,BASE-07` | rename “Qualified local SAS binary reader provider”; remove parser construction |
| `VS-01` new | `EPIC-BASE` / data + validation owners | `BASE-08,PROV-01` | first technical gate: real SAS7BDAT → bounded local-reader descriptor/rows → fixture-specific provisional Spark mapping → local Delta → reconciliation → evidence; does not satisfy `BASE-04` or `BASE-02` |
| `DBX-03` | `EPIC-DBX` / platform security | `HENV-01,HENV-02,SEC-01,SEC-02` | governed DBR/Spark/Scala/JVM/compute/network/runtime policy |
| `SCALE-01` new | `EPIC-BASE` / Databricks data owner | `VS-01,DBX-03,PKG-DES-01` | distributed spark-sas7bdat/Parso qualification; no local-collection acceptance |
| `BASE-04` | `EPIC-BASE` / data architect | `BASE-08,SCALE-01` | canonical descriptor shared across reader providers |
| `SASSEM-01,SASSEM-02,SASSEM-04` | existing SAS semantics owners | unchanged | promote the three unfinished prerequisites to `P0`; preserve their existing evidence and acceptance scope |
| `BASE-02` | `EPIC-BASE` / SAS + Databricks architects | `BASE-04,SASSEM-01,SASSEM-02,SASSEM-04` | governed type/mapping/semantic policy |
| `BASE-11` new | `EPIC-BASE` / SAS SME | `BASE-02,BASE-04,BASE-06,BASE-08,SCALE-01` | catalogs, formats/informats, views, indexes, encryption, corruption and unsupported-asset dispositions; no new parser |
| `BASE-09` | `EPIC-BASE` / modernization architect | `BASE-07,BASE-11,WLD-05,TASK-04` | six-way asset disposition and persistent-versus-reproducible proof |
| `MODAP-01` new | modernization governance owner | `BASE-09,WLD-11,WLD-12,MOD-02,MOD-08` | named, attributable target-architecture and business-disposition approval record; binds six-way dispositions, workload boundaries, consolidation/retirement, incremental candidates and target orchestration |
| `CV-04` | conversion owner | `UPQ-01,LIC-01,PKG-DES-01,BASE-02,CV-02` | harden sas2databricks; deterministic first; gateway-only optional repair |
| `AIREP-01` new | orchestration/validation owner | `AIGW-01,CV-04,BASE-02` | bounded deterministic-plus-gateway repair controller |
| `DBPKG-04` new | `EPIC-DBPKG` / data platform owner | `BASE-02,BASE-08,SCALE-01,ORCH-04` | restartable reader/Spark-to-Delta orchestration; remove reader/writer engine scope |
| `BASE-10` | `EPIC-BASE` / Databricks architect | `BASE-02,BASE-03,HENV-02` | governed target mapping |
| `DBPKG-01` | `EPIC-DBPKG` / Databricks data owner | `DBPKG-04,BASE-10,DBX-02,DBX-03` | upstream Delta + UC provider integration; remove Delta-engine construction |
| `DBX-01` | `EPIC-DBX` / integration owner | `DBX-02,DBX-03,DBPKG-01,CV-04` | retain `In Progress / Partial`; complete governed remote execution |
| `DBX-04` | `EPIC-DBX` / observability owner | `DBX-01,ORCH-04,PROV-01` | retain `In Progress / Partial`; immutable runtime receipts |
| `DP-01` | existing validation owner | **unchanged** | preserve the completed record exactly as `Done / Foundation Complete`; add no dependency or new acceptance obligation |
| `SCHEMA-INT-01` new | `EPIC-DP` / validation owner | `DP-01,BASE-04,DBPKG-01` | prove the completed DP-01 comparator consumes authoritative cross-provider source and published target descriptors; this is new acceptance, not retroactive DP-01 scope |
| `DP-02` | `EPIC-DP` / validation owner | `DBPKG-01,DBX-04,BASE-02` | row-count receipt through shared distributed-capable adapter |
| `DP-03` | `EPIC-DP` / validation owner | `DP-02,DBPKG-01,DBX-04` | keyed/grouped aggregate receipt |
| `DP-04` | `EPIC-DP` / validation owner | `DP-02,BASE-02,SASSEM-01,SASSEM-02,SASSEM-04` | null/special-missing/distribution receipt |
| `DP-05` | `EPIC-DP` / validation owner | `DP-02,DBX-04` | deterministic sample receipt, explicitly non-authoritative for full parity |
| `VAL-01` | validation architect | `SCHEMA-INT-01,DP-02,DP-03,DP-04,DP-05,DBX-04` | DataComPy/Spark-backed full-row certification; require partitioned/distributed execution for large tables; prohibit whole-table pandas collection |
| `PROV-02` new | `EPIC-PROV` / governance owner | `PROV-01,DBPKG-04,DBPKG-01,DBX-04,VAL-01,TASK-24,TASK-25` | end-to-end immutable migration evidence |
| `READY-02` new | readiness governance owner | `DBX-04,VAL-01,PROV-02` | mandatory migration completion predicate |
| `PKG-QUAL-01` new | release/deployment owner | `AIGW-01,BASE-08,SCALE-01,CV-04,DBPKG-01,DBX-04,VAL-01,PROV-02` | **final** source-only/offline bundle qualification using actual provider/transitive artifacts; prove zero runtime public downloads |
| `MIGCLI-01` new | CLI/platform owner | `CLICON-01,PROV-02,READY-02,PKG-QUAL-01,ORCH-01,ORCH-03,ORCH-04` | end-to-end acceptance of `smf migrate convert` |
| `MODCLI-01` new | modernization/CLI owners | `CLICON-01,MIGCLI-01,MODAP-01,PKG-QUAL-01` | end-to-end acceptance of `smf migrate modernize`; must consume named approval record |
| `MIGOPS-01` new | CLI/governance owners | `CLICON-01,MIGCLI-01,PROV-02` | status/resume/exceptions/approve/promote acceptance |
| `ORCH-02` | platform architect | `MIGCLI-01,MIGOPS-01,READY-02,AIREP-01` | complete fail-closed orchestration |
| `HPILOT-04` | program + Humana approvers | `ORCH-02,MIGOPS-01,PKG-QUAL-01` | authorized Humana pilot gate |
| `COMP-01` | program + independent Reviewer | `HPILOT-04,READY-02,PROV-02` | terminal competition count uses mandatory predicate only |

### 10.1 Corrected sequence and first execution wave

```text
UPQ-01 -> LIC-01 -> PKG-DES-01 ---------------------> AIGW-01
    |             |                                      |
    |             +-> CORPUS-11                          v
    |                                                 AIREP-01
    +-> WLD-03 -> BASE-07 -> BASE-06 -> BASE-08 -> VS-01
                                                       |
                                      DBX-03 ----------+-> SCALE-01
                                                            |
                                  BASE-04 -> BASE-02 -> BASE-11 -> BASE-09
                                               |                         |
                                               |                      MODAP-01
                                               v                         |
                         CV-04 -> DBPKG-04 -> BASE-10 -> DBPKG-01        |
                           |                              |               |
                           +-> AIREP-01 -> DBX-01 -> DBX-04              |
                                                   |                     |
                 DP-01 -> SCHEMA-INT-01; DP-02..05 -> VAL-01           |
                              (partitioned/distributed at scale)        |
                                                   |                     |
                                         PROV-02 -> READY-02             |
                                                   |                     |
             actual providers/dependencies ------> PKG-QUAL-01          |
                                                   |                     |
CLICON-01 -------------------------------------> MIGCLI-01 -> MODCLI-01 <-+
                                                               |
                                                           MIGOPS-01
                                                               |
                                                           ORCH-02
                                                               |
                                                    HPILOT-04 -> COMP-01
```

The dependency-safe **first execution wave** is: `UPQ-01`, `LIC-01`, `PKG-DES-01`, `CLICON-01`, `CORPUS-11`, `WLD-03`, `BASE-07`, `BASE-06`, `BASE-08`, `AIGW-01` limited to schema/mock/preflight, `DBX-03` limited to offline/runtime-policy qualification, `SASSEM-01`, `SASSEM-02`, `SASSEM-04`, and `VS-01` when its prerequisites pass. Its initially runnable roots are `UPQ-01`, `CLICON-01`, `WLD-03`, `DBX-03`, `SASSEM-01`, `SASSEM-02`, and `SASSEM-04`; every other first-wave record remains blocked until its declared prerequisites pass. `PKG-QUAL-01` is deliberately late. Publishing downstream P0 records does not authorize their execution before dependencies pass.

Only after later publication approval would these files change: `competition/generated/replan.yaml`, affected issue specs, `scripts/engineering-agent/config.yaml`, and `competition/COMPETITION-PLAN.md`, followed by live Project/issue sync with dry-run/read-back evidence.

## 11. Smallest first implementation increment

The smallest defensible increment is `VS-01`:

```text
actual licensed .sas7bdat bytes
  -> pyreadstat provider at approved pin
  -> bounded local-reader descriptor + bounded row chunks
  -> fixture-specific provisional Spark StructType mapping
  -> local Delta table through delta-rs (or approved local Spark Delta)
  -> schema + full-row reconciliation through DataComPy
  -> immutable PROV-01 evidence binding input, version, policy and output digests
```

Acceptance:

- Use a binary-compressed and a catalog-linked redistributable fixture. Cognition binaries may support local evaluation but cannot be checked in.
- Pin packages/hashes; produce SBOM, notices, vulnerability scan and native-platform evidence.
- Define a bounded local-reader descriptor before chunking; every chunk conforms. The observed timestamp dtype drift must fail until normalized by an explicit fixture policy.
- Construct actual provisional Spark `StructType` objects in tests, even if Delta is local. This proves only the selected fixtures/provider. `BASE-04` later establishes the canonical cross-provider descriptor, and `BASE-02` later establishes the governed production type/semantic mapping.
- Write isolated Delta, read it back, and reconcile count, schema, keyed full rows, nulls, temporal values and zero-tolerance numerics.
- Evidence binds source SHA-256, provenance/license, upstream revisions/package hashes, reader options, mapping digest, chunk receipts, Delta version/files, DataComPy policy/result, commands, environment and tests.
- Negative tests: truncated/unsupported/encrypted input, missing/mismatched catalog, source mutation, chunk schema drift, duplicate key, changed cell, stale evidence, interrupted/retried write.
- Exclude UC, live Databricks, Humana data and migration claims.

Estimate: **6–10 engineer-days** after `UPQ-01`, `LIC-01`, `PKG-DES-01`, `CLICON-01`, and the minimal licensed portion of `CORPUS-11` are accepted.

## 12. Proposed CLI contract and engineer runbooks

These commands are the required P0 contract; they are **not present in the current CLI**. `CLICON-01` establishes the parsers, schemas, configuration bindings, result envelopes, help text and exit codes early. Until a backend record is implemented, the scaffold must return a machine-readable blocked `not_implemented` result rather than simulate success. Current commands such as `smf discover`, `convert`, `execute`, and `validate-schema` remain bounded foundations until `MIGCLI-01`, `MODCLI-01`, and `MIGOPS-01` pass end-to-end acceptance.

### 12.1 Common configuration

```text
deployments/humana/factory.yaml              existing deployment binding root
deployments/humana/ai-gateway.yaml           AIGW-01 contract; references only, no secrets
migration/workload.yaml                      source roots, entry points, workload identity
migration/asset-policy.yaml                  asset dispositions and unsupported behavior
migration/type-mapping.yaml                  SAS-to-Spark/Delta type and semantic policy
migration/validation-policy.yaml             keys, tolerances, aggregates, missing/order policy
migration/modernization-policy.yaml          redundancy, boundary, incremental and target rules
migration/approvers.yaml                     approver role/identity requirements, never approvals
```

Configuration is schema-validated, unknown-field rejecting, digest-bound, environment-specific, and contains Vault/Entra references rather than credentials. A changed file creates a new attempt and invalidates stale approvals.

### 12.2 Fast faithful conversion: `smf migrate convert`

The command performs closure acquisition, discovery, path binding, native metadata extraction, required asset disposition, SAS conversion, dataset ingestion, Delta/UC publication, Databricks execution, independent reconciliation, evidence generation, bounded exception/repair handling, resumability, and final human approval. “Fast” removes modernization redesign, not migration evidence.

```bash
smf deployment-config preflight \
  --config deployments/humana/factory.yaml --json

smf ai-gateway preflight \
  --config deployments/humana/ai-gateway.yaml \
  --workload-id HUM-WL-001 --out out/preflight --json

smf migrate convert \
  --source /approved/sas-estate \
  --factory-config deployments/humana/factory.yaml \
  --gateway-config deployments/humana/ai-gateway.yaml \
  --workload-config migration/workload.yaml \
  --asset-policy migration/asset-policy.yaml \
  --type-policy migration/type-mapping.yaml \
  --validation-policy migration/validation-policy.yaml \
  --workload-id HUM-WL-001 --run-id HUM-CONV-20260918-001 \
  --attempt-id 1 --out out

smf migrate status --run-id HUM-CONV-20260918-001 --out out --json
smf migrate approve --run-id HUM-CONV-20260918-001 \
  --stage migration-completion --approval-file approvals/HUM-CONV-20260918-001.json \
  --out out
smf migrate promote --run-id HUM-CONV-20260918-001 \
  --target humana-pilot \
  --promotion-approval approvals/HUM-CONV-20260918-001-humana-pilot-promotion.json \
  --out out
```

Normal `convert` completion before approval is `awaiting_human_approval`, exit `2`. It must never return migration success merely because conversion, execution, or reconciliation passed.

The exact stage order is: `configuration_preflight` → `closure_acquisition` → `physical_discovery` → `libname_binding` → `native_descriptor` → `asset_disposition` → `deterministic_conversion` → optional `gateway_repair` → `deterministic_revalidation` → `restartable_ingestion` → `delta_uc_publication` → `databricks_execution` → `schema_reconciliation` → `distributed_row_reconciliation` → `semantic_reconciliation` → `evidence_seal` → `independent_review` → `awaiting_human_approval`. Large tables are reconciled by Spark/partitioned comparison with deterministic partition digests, key-range coverage and aggregate controls; the command must not collect complete Humana tables into local pandas memory.

### 12.3 Full modernization: `smf migrate modernize`

Modernization first classifies every asset as `migrate`, `reproduce`, `consolidate`, `replace`, `retain`, or `retire`; identifies redundant datasets/jobs; proves persistent versus reproducible-intermediate status; redesigns workload boundaries; identifies batch-to-incremental candidates; and defines target architecture/orchestration. It then stops for architecture/business approval before performing the same complete migration path as `convert`.

```bash
smf migrate modernize \
  --source /approved/sas-estate \
  --factory-config deployments/humana/factory.yaml \
  --gateway-config deployments/humana/ai-gateway.yaml \
  --workload-config migration/workload.yaml \
  --asset-policy migration/asset-policy.yaml \
  --modernization-policy migration/modernization-policy.yaml \
  --type-policy migration/type-mapping.yaml \
  --validation-policy migration/validation-policy.yaml \
  --workload-id HUM-WL-001 --run-id HUM-MOD-20260918-001 \
  --attempt-id 1 --out out

smf migrate status --run-id HUM-MOD-20260918-001 --out out --json
smf migrate approve --run-id HUM-MOD-20260918-001 \
  --stage modernization-architecture-business-disposition \
  --approval-record MODAP-01 \
  --approval-file approvals/HUM-MOD-20260918-001-architecture-business.json --out out
smf migrate resume --run-id HUM-MOD-20260918-001 \
  --from-checkpoint approved-modernization-architecture-business-disposition \
  --factory-config deployments/humana/factory.yaml --out out
smf migrate approve --run-id HUM-MOD-20260918-001 \
  --stage migration-completion \
  --approval-file approvals/HUM-MOD-20260918-001-completion.json --out out
smf migrate promote --run-id HUM-MOD-20260918-001 \
  --target humana-pilot \
  --promotion-approval approvals/HUM-MOD-20260918-001-humana-pilot-promotion.json \
  --out out
```

The exact modernization-only stages before the shared migration path are: `estate_closure` → `six_way_asset_classification` → `redundant_dataset_job_analysis` → `persistent_intermediate_proof` → `workload_boundary_redesign` → `batch_incremental_analysis` → `target_architecture` → `target_orchestration` → `modernization_plan_seal` → `awaiting_architecture_business_approval`. The first `modernize` phase normally exits `2` with `awaiting_architecture_business_approval`. It writes the candidate plan and a `MODAP-01` approval request. Only an attributable `MODAP-01` decision may unlock the shared conversion/ingestion/execution/reconciliation stages. The CLI verifies that decision but cannot manufacture it.

### 12.4 Status, resume, exceptions, approval, and promotion

```bash
smf migrate status --run-id <RUN> --out out --json
smf migrate resume --run-id <RUN> --from-checkpoint latest-safe \
  --factory-config deployments/humana/factory.yaml --out out
smf migrate exceptions list --run-id <RUN> --out out --json
smf migrate exceptions submit --run-id <RUN> \
  --exception-file exceptions/<ID>-request.json --out out
smf migrate exceptions decide --run-id <RUN> \
  --decision-file exceptions/<ID>-decision.json --out out
smf migrate approve --run-id <RUN> --stage <STAGE> \
  --approval-file approvals/<FILE>.json --out out
smf migrate promote --run-id <RUN> --target <APPROVED-TARGET> \
  --promotion-approval approvals/<RUN>-<APPROVED-TARGET>-promotion.json --out out
```

- `status` is read-only and reports stage, attempt, blockers, exceptions, upstream/config digests, external outcomes and next permitted action.
- `resume` verifies all prior manifests and current configuration/upstream digests, then starts a new append-only attempt at the requested safe checkpoint. It never skips an incomplete prerequisite, reuses stale approval, overwrites an attempt, or retries an uncertain Delta/Databricks/gateway outcome. An uncertain outcome exits `3` until reconciled by an authorized operator.
- `exceptions submit` records a request only. `decide` requires an authorized signed decision and cannot waive protected/security boundaries outside policy.
- `approve` validates human evidence and appends an approval node. It does not infer approval from identity, signature, status, or prior stage success.
- `promote` is externally mutating. Migration-completion approval never authorizes it. The command requires a separate target-specific promotion decision bound to the run ID, sealed evidence-manifest digest, source identity, target identity, approving identity/role, environment and expiration; it refuses missing, expired, stale, cross-run, cross-source, cross-target or cross-environment evidence.

Exit contract for the new namespace: `0` requested action completed in its authorized scope; `2` valid blocked/pending/review/exception/approval-required result; `1` malformed input or local operational failure; `3` external outcome uncertain and automatic retry prohibited. Automation must inspect the result status as well as the exit code.

### 12.5 Run outputs and evidence

```text
out/runs/<run-id>/run.json
out/runs/<run-id>/configuration.manifest.json
out/runs/<run-id>/workloads/<workload-id>/attempts/<n>/
  closure/ discovery/ bindings/ descriptors/ dispositions/
  modernization/ architecture-business-approval/
  conversion/ ai-repairs/ ingestion/ delta/ execution/
  reconciliation/schema/ reconciliation/partitions/ reconciliation/semantic/
  exceptions/ approvals/ promotion/
  evidence.manifest.json
```

Every stage is append-only and binds input bytes, configuration/policy revisions, upstream artifacts, commands, environment, identities, timestamps, outputs, dispositions and reviewer/human decisions. Reconciliation evidence records the complete partition/key-range coverage map, per-partition counts/digests/differences, aggregate controls and the proof that no full Humana table was collected into local process memory. Protected prompt/response content is excluded unless Humana explicitly authorizes its retention.

## 13. Humana delivery and dependency matrix

Humana selects one of two profiles per environment:

- **Source-only:** transfer SMF source/config/notebooks only; every dependency below must already exist in the approved Humana/Databricks runtime at the qualified version.
- **Offline packaged:** transfer SMF plus approved wheels/JARs/native components through Humana software intake with licenses, NOTICE, SBOM, vulnerability results, SHA-256, provenance, lockfiles and offline bootstrap instructions.

`PKG-DES-01` designs both profiles before provider implementation. `PKG-QUAL-01` later qualifies the final bundles using the actual provider and transitive dependency set.

The source-only profile is valid **only** when preflight proves that every required Python wheel/native library, JAR, JVM/Scala/Spark/DBR component and version is already approved and present in the Humana runtime. Missing, incompatible or unapproved dependencies block execution. The preflight result must name the exact required offline wheel/JAR/native artifact, version, platform and expected SHA-256 so the environment can move to the offline-packaged profile. It may not install, compile, download or silently substitute anything.

Neither profile contacts an upstream repository or package registry at runtime. Runtime access to GitHub, PyPI, Maven Central, Anthropic, OpenAI or any other public service is prohibited. No third-party project source is pasted into SMF to substitute for a compiled wheel/JAR.

| Component / selected revision | Vendored into SMF? | Delivery/runtime role | Qualified platforms | Exact Humana intake artifact |
|---|---|---|---|---|
| SMF `299c977...` plus approved P0 revisions | SMF source itself | source-only or signed offline source bundle; runtime | Linux x86_64 primary; Python 3.11/3.12 | signed SMF source archive, config schemas, notebooks, lock/manifest and SHA-256 generated from approved commit |
| sas2databricks `0.4.0` / `392d3a3...` | No | offline wheel or preinstalled; runtime; install without `[llm]` direct-provider extra | OS-independent Python 3.10+; SMF qualifies 3.11/3.12 | `sas2databricks-0.4.0-py3-none-any.whl`, SHA-256 `472f367872367633d452faad4c11cf3f1d2d9f7bc28c27eb5d75abee4c2ee8c0` |
| pyreadstat `1.3.6` / ReadStat `5850fb5...` | No; ReadStat is compiled into wheel | offline native wheel; local-reader runtime | Linux manylinux x86_64/aarch64; CPython-specific 3.11/3.12 | x86_64 CPython 3.11 wheel SHA `db275cc6a96b259a6369cd8b2d8ad159cf6c81b296c1a8205bb23e51686b0f24`, or CPython 3.12 wheel SHA `93182fc101e2adf27c36fb935e8144e5bc92a3da8d7577a1dabfcacf29b672e8`; architecture must match |
| spark-sas7bdat `3.0.0` / `dad0840...` | No | offline JAR or cluster library; distributed-reader runtime | exact DBR Spark/Scala/JVM combination pending Humana inventory; `_2.12` and `_2.13` must not be interchanged | `_2.12` JAR SHA `a4240d930e37d0bd2b8223e2b0186d26ecaa6dbf65226865227d3a2f71802d0e` or `_2.13` JAR SHA `d0e7e26be026072f6a968ccf94c71403bd8ea45b33d82e1f639ac39771d47e77`; approve only the DBR-qualified one |
| Parso `2.0.14` / `3c514e6...` | No | offline transitive JAR; distributed-reader runtime | JVM compatibility and DBR classpath pending `SCALE-01` | `parso-2.0.14.jar`, SHA-256 `3b7e7a32915e04caed5dba31be1430aa57b4f9fa2b3d0ab0ed29067510d16575` |
| Delta Lake / Spark | No | supplied by Databricks Runtime in Humana | Humana-approved DBR/Spark/Scala/JVM only | exact DBR identifier and installed Delta/Spark inventory, supplied and attested by Humana |
| delta-rs/deltalake `1.6.4` / `6a954af...` | No | offline wheel for local `VS-01`; runtime only where approved | CPython 3.10+ ABI3; Linux x86_64/aarch64 | x86_64 wheel `deltalake-1.6.4-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`, SHA `f26513d4ca8d95e1f7298197c7d870fdd18d600689f30859e7678f2632102194` |
| DataComPy `1.0.4` / `16c4a3b...` | No | offline wheel; reconciliation runtime | Python 3.10+; pandas/Polars or qualified Spark backend | `datacompy-1.0.4-py3-none-any.whl`, SHA-256 `56e28bb0e5e3f88e82b1f3e4ba6b6e729aa0f851320b78a06bf2020e41e0e60f` |
| Databricks SDK `0.133.0` / `d56f2da...` | No | offline wheel unless supplied; UC/jobs runtime | Python 3.10+; OS-independent | `databricks_sdk-0.133.0-py3-none-any.whl`, SHA-256 `3733a0f2b45c6da5c628755df0d0d10a438cc7e1465546f641690561fd97bc9e` |
| Azure Identity `1.25.1` | No | offline wheel unless Humana supplies; gateway/Databricks Entra auth runtime | Python 3.9+; OS-independent with locked transitives | `azure_identity-1.25.1-py3-none-any.whl`, SHA-256 `e9edd720af03dff020223cd269fa3a61e8f345ea75443858273bcb44844ab651` |
| Humana gateway client | Yes, SMF-owned source | runtime; speaks only to Humana endpoint | Python 3.11/3.12 on approved Humana host | included in signed SMF bundle; no Anthropic/OpenAI SDK required |
| PyArrow/pandas/NumPy/narwhals/crypto/HTTP and other transitives | No | offline wheels or Humana-supplied; runtime where selected provider needs them | exact Python/OS/CPU matrix and lock requirements designed by `PKG-DES-01` | complete hash-locked wheelhouse; every filename/hash/SBOM component requires intake approval and final verification by `PKG-QUAL-01` |
| build/test tools and public source clones | No runtime delivery | build-time/qualification only | controlled build environment | excluded from runtime bundle; build provenance retained |

Great Expectations, Remorph, the pandas SAS reader, FredHutch writer, direct Anthropic/OpenAI SDKs, and original upstream repositories are not runtime requirements. `PKG-DES-01` defines the dependency/platform design and locks. `PKG-QUAL-01` must prove the final source-only/offline runtime manifest excludes the broad SMF `[ai]` extra and contains no direct-provider SDK.

## 14. Humana AI Gateway configuration contract

`deployments/humana/ai-gateway.yaml` is proposed as a strict, secret-free contract:

```yaml
schema_version: "1.0"
gateway_id: humana-ai-gateway
state: pending
endpoint: "https://<humana-host>"
route: "/<approved-anthropic-route>"
protocol: anthropic-messages-compatible
model_alias: "<humana-controlled-alias>"
api_version: "<humana-required-version>"
required_headers:
  - name: "<approved-header-name>"
    value_reference: "vault://<reference>"
authentication:
  mode: entra-workload-identity
  audience: "<humana-provided-audience>"
  tenant_reference: "<approved-reference>"
tls:
  minimum_version: TLS1.2
  trust_bundle_reference: "<humana-ca-reference>"
  client_certificate_reference: null
limits:
  connect_timeout_seconds: 10
  request_timeout_seconds: 120
  max_attempts: 3
  retryable_statuses: [429, 502, 503, 504]
  max_concurrency: 2
  requests_per_minute: "<humana-limit>"
  input_tokens_per_request: "<humana-limit>"
  output_tokens_per_request: "<humana-limit>"
retention:
  persist_prompt: false
  persist_response: false
  sanitized_receipt_only: true
```

Humana must provide the endpoint, route, model alias, version, exact headers, authentication mode/audience, CA/mTLS requirements, content-filter semantics, quotas and correlation-header names. Values are configuration, not hard-coded assumptions.

The client serializes Anthropic Messages-compatible requests behind the Humana endpoint and accepts only the configured response schema. Receipts include run/attempt/workload, route/model alias/config digest, timestamps, sanitized outcome, token counts, latency, retry count, Humana correlation identifiers and validation disposition. They contain no protected prompt/response content; even content digests require Humana approval.

`smf ai-gateway preflight` uses a non-sensitive approved probe and verifies DNS/TLS/auth/protocol/schema/content-filter/correlation behavior without recording payload content. Authentication failure, certificate failure, rejection, malformed response, uncertain timeout or exhausted retry returns non-success and never triggers direct fallback.

The `AIGW-01` automated suite uses an in-process mock implementing success, authentication denial, throttling with bounded `Retry-After`, content-filter rejection, malformed body, correlation-ID omission, disconnect and uncertain-timeout cases. The mock is forbidden in non-test deployment configuration.

| Gateway outcome | Required client behavior |
|---|---|
| DNS/TLS/certificate/authentication failure | exit `2` blocked; sanitized reason; zero model fallback |
| HTTP 429 or configured transient 5xx | bounded retry within attempt/token/concurrency limits; exit `2` when exhausted |
| content-filter/policy rejection | exit `2` with distinct non-retryable disposition; preserve no protected content |
| malformed/incompatible response | exit `1` contract failure; quarantine response in memory only, sanitized receipt |
| timeout before authoritative response status is known | exit `3` outcome uncertain; no automatic retry or alternate provider |
| valid response | treat returned repair as untrusted; deterministic revalidation and the complete execution/reconciliation path remain mandatory |

## 15. Unsupported and special-asset behavior

Discovery is not support. Every required asset must receive and execute one of these dispositions:

| Asset/condition | Permitted behavior | Completion rule |
|---|---|---|
| SAS view | recreate from proven lineage in Databricks, or materialize through an authorized SAS baseline/export; temporarily retain only with owner plan | block until lineage/materialization and reconciliation pass or exception approved |
| SAS index | ingest base rows; recreate only required uniqueness/access behavior as Delta constraints/layout/optimization under target design | source index is not copied as data; block if semantics such as uniqueness/order are unresolved |
| SAS catalog | read with qualified SAS7BCAT support when possible; otherwise obtain authorized catalog export or SAS-materialized formatted baseline | block any workload whose labels/formats affect logic or acceptance until catalog authority is resolved |
| Formats/informats | convert supported definitions through sas2databricks plus governed mapping tables/UDFs; validate raw and rendered values against SAS baseline | unsupported or context-dependent definition blocks affected semantics pending recreation, retention or approved exception |
| Encrypted dataset | require customer-provided key through approved Vault reference or authorized SAS-side decrypted export; never persist key | quarantine and block until authorized access succeeds or exception approved |
| Corrupt/truncated dataset | quarantine immutable bytes; use authorized SAS recovery/export if available | no AI reconstruction; block required workload pending recovered authoritative source or exception |
| Missing/mismatched catalog | raw values may be staged, but formatted semantics remain unresolved; acquire catalog, materialize formatted baseline, or approve explicit replacement | block semantic completion until resolved/excepted |
| Unsupported encoding | apply only approved lossless transcoding with byte/value evidence; otherwise authorized SAS export | quarantine/block on decode loss or ambiguity |
| Unresolved macro-generated path | acquire config/autoexec/runtime trace from authorized SAS execution or customer mapping | block; never guess path or probe unapproved system |
| Special missing values | preserve distinct SAS missing semantics through qualified provider/policy, or materialize authoritative comparison columns through SAS baseline | block if collapsed values can affect logic/reconciliation unless owner-approved exception |
| Deleted-row semantics | qualify reader behavior against SAS baseline and policy for visible/deleted rows | block on disagreement or unknown row-count semantics |
| Runtime-only LIBNAME | require authorized runtime binding trace/config and appropriate source provider | block physical closure; no inferred connection or credential |
| Runtime-generated dependency | acquire authorized execution trace/scheduler evidence and bind the generated artifact or prove reproducibility from complete producers/inputs | block closure and modernization disposition while generation conditions or consumers remain unknown |
| Unsupported compression/host/version | use distributed/local alternate only if qualified; otherwise authorized SAS export | block until supported path or approved exception |

## 16. External inputs required from Humana

- approved runtime inventory: OS, CPU architecture, Python, JVM, Scala, Spark, DBR, installed libraries and cluster-library policy;
- source-only versus offline-packaged choice per environment; software-intake repository, malware/signing/SBOM/vulnerability thresholds and redistribution requirements;
- AI Gateway contract from Section 14, Entra workload identity or other approved auth, Vault references, CA/mTLS, network route, content-filter behavior, quotas and test window;
- approved SAS roots/exports, SAS releases/hosts, encodings, compression/encryption use, keys by reference, catalogs, views, indexes, generation groups, config/autoexec and runtime LIBNAME traces;
- Databricks workspace identity, compute/network policy, UC catalog/schema/storage/grants, scratch/output scopes, quotas, retention, audit and cleanup rules;
- source-target mappings, keys, tolerances, formatted/raw-value authority, special-missing/deleted-row policy, required business aggregates and exception owners;
- modernization priorities, target architecture constraints, consolidation/retirement authority, SLA/batch-to-incremental criteria and named architecture/business approvers;
- pilot cohort, authorized SAS-produced baselines, PHI/PII handling and final migration/promotion approvers.

## 17. Capability status at this decision point

| Status | Capabilities |
|---|---|
| **Proven now, bounded** | exact recovered OSS revisions/licenses; sas2databricks 44-test suite; pyreadstat compressed/catalog/metadata/non-ASCII/corruption smoke; seven evaluation-only Cognition binaries read; local pyreadstat → Delta-rs → DataComPy smoke |
| **Partial foundations** | SMF static discovery/code-reference models, limited literal LIBNAME parsing, supplied-snapshot schema comparison, offline deployment/readiness/security/provenance controls, conversion adapter, Databricks provider/auth boundaries; none proves native data closure, live execution, parity or migration completion |
| **Planned/P0 backlog** | early/final portability gates, CLI scaffold, complete inventory/binding, local/distributed readers, canonical descriptor/type policy, special assets, persistent/intermediate classification, gateway integration, deterministic-plus-AI repair, restartable ingestion, Delta/UC, execution, distributed reconciliation, immutable evidence, complete CLI/orchestration and pilot |
| **Blocked externally** | exact Humana runtime and intake approval; AI Gateway endpoint/auth/TLS/quota/protocol; authorized SAS data/baselines/keys/runtime traces; Databricks workspace/UC/compute/network; business mappings/tolerances/architecture decisions/pilot approvals |
| **Explicitly unsupported/prohibited** | direct Anthropic/OpenAI/public-provider access or fallback; runtime GitHub/PyPI/Maven access; AI binary parsing/data reconstruction/business invention; unlicensed Cognition redistribution; automatic retry of uncertain side effects; new parser/converter/Delta/comparison engine without separate proven-gap approval; premature migrated/certified/complete claims |

## 18. Stop boundaries and current status

Human intervention remains required for protected paths, license or contractual ambiguity, PHI/PII and security/data-boundary changes, external/destructive actions, live workspace writes, Entra/Vault or gateway policy changes, unsupported lossy semantics, architecture/business decisions, contradictions, systemic conflicts, exhausted repair, unresolved Reviewer rejection, exceptions, promotion, merge, Project closure and final migration approval.

Technical provider failure does not authorize an invented replacement. It produces a reproducible gap, upstream issue/patch assessment, and a separate fork/build decision package.

### 18.1 Corrected estimates

The Section 7 estimate is superseded only for the newly split/added records:

| Corrected/new record | Estimate |
|---|---:|
| `PKG-DES-01` early portability/dependency design | 4–6 engineer-days |
| `CLICON-01` early CLI contract/scaffold | 4–6 engineer-days |
| `MODAP-01` modernization architecture/business approval mechanism | 3–7 engineer-days plus approver lead time |
| `PKG-QUAL-01` final source-only/offline bundle qualification | 5–8 engineer-days plus intake lead time |

All other record estimates remain as stated in Section 7. The corrected program total is **190–301 engineer-days**, plus Humana software-intake, AI Gateway, Databricks, SAS-baseline, security, Legal, architecture and business-approval lead time. This is engineering effort, not elapsed duration.

### 18.2 Critical path and parallel execution

Critical path:

```text
UPQ/LIC -> PKG-DES -> inventory/binding/local reader -> VS-01
-> distributed reader/canonical policy/special assets -> ingestion/Delta-UC
-> Databricks execution -> distributed reconciliation -> evidence/readiness
-> PKG-QUAL -> CLI E2E/orchestration -> Humana pilot -> COMP-01
```

Parallel plan:

- **Wave 1:** the dependency-safe first execution wave in Section 10.1. Qualification/licensing, CLI scaffold, gateway mock/config, corpus, runtime-policy discovery and source inventory work in bounded parallel.
- **Wave 2:** after `VS-01`, run distributed-reader qualification, canonical descriptor/type policy, special-asset qualification, six-way disposition and `MODAP-01` preparation in parallel where dependencies permit.
- **Wave 3:** conversion/gateway-repair hardening, restartable ingestion, target mapping and Delta/UC integration.
- **Wave 4:** governed Databricks execution, partitioned/distributed reconciliation, immutable evidence/readiness and final bundle qualification.
- **Wave 5:** fast-conversion and modernization E2E CLI acceptance, operational controls, complete orchestration, authorized pilot and terminal competition gate.

### 18.3 Mandatory stop rules

Stop the affected workload or program branch when any of the following occurs:

- source-only preflight finds a missing, incompatible or unapproved native/JVM dependency;
- an offline artifact lacks a license/NOTICE, hash, provenance, SBOM, vulnerability disposition or Humana intake approval;
- physical closure, LIBNAME binding, runtime-generated dependency or asset disposition is unresolved;
- parser/reader observations disagree, chunk/partition schemas drift, decoding is lossy, or corrupt/encrypted data lacks an authoritative path;
- AI Gateway authentication/TLS/policy fails, content is rejected, response is malformed, timeout outcome is uncertain, retries are exhausted, or a direct-provider path is detected;
- AI output introduces unsupported semantics or fails deterministic revalidation, execution or reconciliation;
- Delta/UC or Databricks side effects are uncertain, stale, unauthorized or collide with another run;
- large-table reconciliation would require whole-table local collection, lacks complete partition coverage, or exceeds approved resource limits;
- modernization lacks the named `MODAP-01` architecture/business decision;
- evidence is missing, mutable, stale, cross-context, self-authored or rejected by the independent Reviewer;
- a protected path, contract, security/data boundary, destructive/external action, exception, promotion, merge, lifecycle closure or final completion requires human authority.

- The prior 31-item queue remains withdrawn and is replaced by the proposed P0 program in Section 7.
- No issue, Project, planning file, dependency, priority, lifecycle, commit, push, PR, merge, agent launch or implementation was performed.
- `TASK-06` remains interrupted with uncommitted worktree evidence preserved.
- Existing security, provenance, protected-path, validation, Reviewer independence and human approvals remain in force.

## 19. Single approval requested

> **After the corrected generated planning files, issue specifications, engineering-agent configuration and exact proposed Project mutations agree and a fresh read-only dependency-integrity dry run passes every required check, approve publication of the complete corrected P0 recovery backlog and approve launching only the dependency-safe first execution wave in Section 10.1.** This approval does not authorize downstream records before dependencies pass, live Humana/Databricks writes without their separate in-workflow authority, exceptions, promotion, merge, lifecycle closure, or final migration approval; every promotion requires its own target-specific, unexpired promotion approval bound to the run and sealed evidence.
