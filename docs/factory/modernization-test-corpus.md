# Modernization Test Corpus Architecture

## Purpose

The SMF corpus is evidence infrastructure for proving discovery, modernization planning,
conversion, validation, remediation, and certification behavior. It is not a collection of
sample SAS chosen to make the factory pass.

The corpus uses three complementary evidence classes:

1. **Untouched public SAS** is the realism backbone. Independently authored public workloads
   test whether SMF survives SAS that was not designed around the factory.
2. **Controlled synthetic fixtures** are precision instruments. SMF-authored SAS and data
   isolate deterministic language semantics, edge cases, failure modes, and regression cases.
3. **Private client corpus** is isolated evidence. Client artifacts never enter the public or
   shared regression corpus and require separate storage, access, retention, and sanitization.

No evidence class substitutes for another.

## Governing rules

### Public source integrity

For corpus scenarios classified as `untouched-public`, SMF must adapt to the upstream source.
The source must not be edited, simplified, normalized, or repaired to make SMF pass. A failure
against valid upstream SAS is an observation about SMF.

Each acquired public artifact must record:

- source registry ID and upstream owner;
- upstream repository or authoritative source URL;
- license or usage terms;
- immutable upstream commit, tag, blob ID, or equivalent reference;
- local SHA-256 fingerprint;
- acquisition date;
- modification status;
- named capability or workload pattern under test.

If an upstream artifact must be changed, the result is a derived SMF fixture. It must retain
attribution but must not be represented as untouched public evidence.

### Synthetic fixture role

Synthetic SAS and data are used when the factory needs an exact, deterministic oracle. They
should target semantics and adversarial conditions such as missing values, null behavior,
character/numeric coercion, BY-group behavior, RETAIN/LAG/FIRST./LAST., duplicate keys,
many-to-many joins, date boundaries, precision, empty datasets, dynamic macro behavior, and
other conditions where a small controlled fixture is stronger evidence than a large workload.

Synthetic fixtures are not evidence that SMF handles representative enterprise SAS estates.

#### Semantic oracle framework

CORPUS-02 semantic manifests may declare `semantic_oracles` bound to deterministic,
authoritative JSON `output_evidence`. The canonical result schema preserves ordered column
metadata, decimal numeric text, distinct SAS ordinary/special missing markers, and an optional
positionally aligned formatted-value projection. Every oracle selects underlying, formatted, or
both projections as authoritative; selects ordered, keyed, or unordered-multiset row comparison; pins required SAS session
assumptions, and defaults numeric comparison to exact unless a non-negative per-column tolerance
is explicit.

The corpus reader and comparator are engine-independent. They validate and compare normalized
results but do not execute SAS, convert programs, run Databricks, or establish parity. Checked-in
results are `declared-synthetic-expectation` evidence unless an approved trusted SAS run supplies
separately identified `sas-executed-baseline` evidence.

### Failure promotion

When an untouched public or private workload exposes a defect:

1. preserve the original evidence unchanged;
2. record the failure against the original workload;
3. fix SMF rather than the public source;
4. create a minimal SMF-owned reproduction when one can isolate the defect;
5. promote that reproduction into the permanent regression suite;
6. retain linkage back to the evidence that exposed the defect.

A private-client failure must be independently reproduced or sanitized before entering any
shared regression corpus.

## Public portfolio strategy

SMF intentionally uses multiple independent public sources. No single repository is treated as
representative of enterprise SAS.

The portfolio should include:

- SAS-maintained language and syntax examples for authoritative construct breadth;
- SAS/ACCESS examples for connectivity, LIBNAME, external database, and load patterns;
- production-quality macro libraries for macro expansion, code generation, dependencies, and
  metadata-oriented SAS 9 behavior;
- multi-artifact SAS applications with programs, macros, metadata, configuration, data, and
  reports;
- end-to-end analytical or clinical pipelines where provenance and license permit use.

Source approval and source acquisition are separate decisions. A source may be registered for
research while remaining blocked from vendoring until license, usage terms, and an immutable
upstream reference are verified.

## Evidence authority

Expected output is not automatically authoritative. Baseline/output evidence must distinguish:

- `sas-executed-baseline`: output captured from a trusted SAS execution;
- `declared-synthetic-expectation`: an SMF-authored deterministic oracle;
- `public-reference-artifact`: output supplied by or legitimately derived from a public source.

The evidence origin, producer, content hash, determinism, provenance, and authority must remain
available to downstream validation and certification.

## Coverage model

Corpus reporting must measure more than file counts or repository test counts. Coverage should
be attributable across dimensions including:

- source diversity and independent authorship;
- SAS language and macro constructs;
- procedures and DATA step semantics;
- data-access mechanisms and file formats;
- dependency and scheduler patterns;
- workload topology and external dependencies;
- complexity and modernization dispositions;
- target patterns and validation assertions;
- unsupported and unresolved behavior.

Coverage maturity must distinguish at least `observed`, `tested`, `converted`, `executed`,
`validated`, and `certified`. These levels must never be collapsed into a single percentage.

## Backlog alignment

- **CORPUS-01**: canonical manifest/schema and provenance foundation.
- **CORPUS-02**: targeted SAS semantic fixtures and deterministic edge cases.
- **CORPUS-03**: multi-artifact workload fixture framework.
- **CORPUS-04**: deterministic synthetic data fixture framework.
- **CORPUS-05**: provenance-aware baseline and expected-output evidence framework.
- **CORPUS-06**: dependency and scheduler fixture framework across synthetic and public workloads.
- **CORPUS-07**: curated public-first representative modernization portfolio.
- **CORPUS-08**: evidence-to-regression promotion process.
- **CORPUS-09**: hard isolation boundary for private client corpus evidence.
- **CORPUS-10**: multidimensional corpus coverage and confidence reporting.

## Evidence-to-regression promotion contract

CORPUS-08 makes failure promotion auditable rather than conversational. Promotion records live
under `tests/corpus/promotions/` and validate against
`schemas/corpus-regression-promotion.schema.json`.

The lifecycle is `observed -> reproduced -> fixed -> promoted`:

1. **Observed** records the original scenario, evidence class, artifact paths, factory stage,
   and actual deficient behavior. The evidence is not rewritten to make SMF pass.
2. **Reproduced** isolates the behavior in an SMF-owned fixture. The reproduction is minimal and
   independent when derived from public evidence. Client evidence must be independently
   reproduced or sanitized before it can cross into the shared regression corpus.
3. **Fixed** records the factory correction and commit that addresses the reproduced behavior.
4. **Promoted** requires the original evidence to remain preserved unchanged and requires both
   the permanent fixture and regression-test paths to exist.

A promotion record is not a claim that the original workload is fully supported. It proves a
narrower statement: a specific observed deficiency produced a reproducible contract, SMF was
corrected, and that behavior is now protected against recurrence.

### Required linkage

Every promoted regression carries both directions of traceability:

```text
original corpus scenario + artifact(s)
              |
              v
      observed SMF failure
              |
              v
  independent/minimal reproduction
              |
              v
        factory correction
              |
              v
permanent fixture + regression test
```

This keeps untouched public SAS as evidence and prevents synthetic regressions from silently
becoming substitutes for the real source that exposed the defect.

## Private client corpus isolation contract

CORPUS-09 establishes a hard boundary around client evidence. A private corpus is not another
repository tier. Its manifests, source programs, data, outputs, logs, and derived artifacts live
outside the SMF repository in client-scoped storage.

A private corpus policy must declare and enforce:

- a storage root outside the repository with encryption required;
- explicit least-privilege principals and prohibition of cross-client access;
- a bounded retention period and deletion at engagement end;
- a client-scoped execution workspace and network boundary with shared execution prohibited;
- prohibition on moving client bytes into shared regression evidence;
- independent reproduction and sanitization review before a generic defect crosses the boundary.

The ordinary `load_corpus_manifest` path rejects `private-client` manifests. Private evidence can
only be loaded through `load_private_corpus_manifest`, which requires an explicit validated
client policy, an authorized principal, a manifest beneath the configured external storage root,
and `source_id: client:<client_id>`. Artifacts are checked again to ensure their resolved paths do
not escape that root.

Private client evidence is therefore usable by the factory without becoming repository content:

```text
client-scoped external storage
          |
          v
validated private policy + authorized principal
          |
          v
private manifest / artifacts / execution
          |
          +---- stays private ----> client evidence and diagnostics
          |
          +---- generic defect ----> independently reproduce or sanitize
                                      |
                                      v
                               shared SMF regression
```

A shared regression may describe the generic behavior learned from client evidence, but it must
not contain client bytes, identifiers, credentials, paths, outputs, or another client's evidence.


### Repository leakage guard

Normal repository verification calls `validate_shared_corpus_boundary()` through the unit suite.
The guard fails closed if a `private-client` corpus manifest appears beneath the shared
`tests/corpus` tree or if a forbidden private-corpus storage path exists inside the repository.
`.gitignore` is defense in depth only; it is not treated as the security boundary.

## Multidimensional coverage truth meter

CORPUS-10 implements coverage as attributable evidence, not a readiness percentage. Every claim
retains its dimension, capability, maturity, scenario, source, and evidence reference. The
report always includes every required dimension, including empty dimensions as known gaps.

The maturity vocabulary is deliberately non-collapsible:

- `observed`: the capability or behavior exists in corpus evidence;
- `tested`: a deterministic test explicitly proves the named behavior;
- `converted`: the factory produced a target implementation for the named behavior;
- `executed`: the produced target implementation actually ran;
- `validated`: source/target result equivalence or the applicable assertion was established;
- `certified`: the applicable factory certification gate was satisfied.

A higher level is never inferred from a lower one. In particular, manifest presence creates
only `observed` evidence. Repository test counts are not modernization coverage, and the truth
meter exposes no aggregate percentage, score, or synthetic confidence number.

The required dimensions are source diversity, constructs, procedures, macro behavior, data
access, dependencies, schedulers, topology, complexity, modernization patterns, validation
assertions, unsupported behavior, and unresolved behavior. Current evidence is reported where
it exists; dimensions without attributable evidence remain explicit known gaps for later proof
work such as SAS semantics, trusted SAS baselines, Databricks execution, parity, semantic
validation, and certification.

### Persistent proof evidence

Higher maturity claims are persisted under `tests/corpus/coverage-evidence/` and validate against
`schemas/corpus-coverage-evidence.schema.json`. The registry accepts only `tested`, `converted`,
`executed`, `validated`, and `certified` claims. `observed` remains derived from corpus manifests.

Each record names exactly one dimension, capability, maturity, scenario, source, and local
`evidence_ref`, and binds the referenced canonical regression result by content digest. The loader
verifies the sibling qualification, immutable source snapshot, stage artifacts, terminal identity,
telemetry projection, scenario/source identity, and maturity-specific derived outcome. Loading a registry
does not infer adjacent maturity states. An executed claim does not manufacture a converted claim;
a validated claim does not manufacture execution or certification.

The repository registry intentionally starts empty. CORPUS-10 creates the proof contract, not
fictional maturity. Evidence is added only when later work produces the corresponding artifact,
test, execution, validation, or certification record.

### Regression admission and stage evidence safeguards

Literal dependency discovery ignores SAS comments and tokens inside quoted strings, while
still resolving quoted arguments of active `%include`, `infile`, and `file` statements.
Active literal dependencies must resolve uniquely inside the workload root and belong to
the qualified closure; missing or ambiguous dependencies fail closed.

A passed PySpark conversion requires a recognizable data operation in a top-level
expression or assignment (for example, `select`, `withColumnRenamed`, or a literal SQL
data statement). Imports, Spark session creation, configuration, constant assignments,
logging, and uncalled function definitions alone do not establish generated workload logic.
This is a conservative syntactic eligibility check, not execution, correctness, or semantic
equivalence proof; unsupported output shapes remain blocked pending a stronger verifier.

Stage artifact content, checks, and reasons use the shared credential sanitizer. Identity
metadata (execution/decision IDs, input digest, validation kind, evidence origin, and baseline
bindings) is rejected if sanitization would change it, before artifacts or stage identities
are persisted. Identity values are not silently redacted into potentially colliding IDs.
This safeguard recognizes the shared sanitizer's credential patterns; it is not a guarantee
that arbitrary unlabeled sensitive text can be detected.

Run `bash scripts/test-corpus-confidence.sh` for the canonical evidence, integration, and
human-review regression cases. Generated, executed, validated, and parity-passed remain
separate claims; accepting a data operation does not establish any of the latter three.

Run `bash scripts/test-cv03-golden-confidence.sh` for the CV-03 golden-conversion gate. Golden
fixtures declare an exact provider/strategy version, expected terminal conversion disposition,
change rationale, and review reference. Generated expectations use immutable exact-byte target
snapshots; unsupported and human-pending expectations contain no target artifact. The comparator
reloads canonical attempt evidence and reconstructs the exact package-owned plan, registry, rule
applications, source-artifact identity, and generated digest. Generated golden matches additionally
require descriptor-bound package qualification evidence whose source and output digests match the
reviewed behavioral fixture. Caller-authored plan metadata, review labels, or coordinated
source/golden changes cannot authorize a match. SAS date/time literals remain outside the qualified
SQL subset. `golden_matched` is regression stability only and cannot set execution, validation,
parity, certification, or approval claims.
