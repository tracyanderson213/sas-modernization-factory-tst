# Validation Roadmap

Validation is intentionally layered. Passing an earlier layer is evidence required to progress, not proof that later layers will pass.

## v1: Static and traceability validation

**Implemented foundation.**

Current capabilities include:

- generated-artifact presence checks
- Python/PySpark syntax parsing
- Spark SQL structural checks
- residual SAS syntax detection
- manual-review marker detection
- assessment-risk gating
- dependency traceability heuristics
- weighted confidence scoring
- structured validation evidence

v1 does not prove data or business-semantic equivalence.

## v2: Execution validation

**Partially implemented.**

Implemented:

- static-validation gate before execution
- local runtime provider for engineering tests
- timeout, exit-code, stdout, stderr, and duration evidence
- execution manifest
- Databricks provider contract
- required Databricks configuration checks
- explicit Databricks write blocking

Still required:

- real remote Databricks job submission
- approved enterprise authentication
- isolated validation compute policy
- Unity Catalog/catalog/schema integration
- Databricks run ID and runtime evidence
- output dataset/schema evidence
- row-count and performance evidence

Remote Databricks execution remains intentionally feature-gated.

## v3: Data parity

**Structural comparison foundation implemented; runtime data parity not implemented.**

Implemented:

- strict source and target schema snapshot contracts
- deterministic column, type, nullability, attribute, and policy-significant order comparison
- versioned compatibility policies and fail-closed provenance/digest checks
- schema-valid structural parity manifests and a separate `smf validate-schema` command

Still required:

- source vs target row counts
- null and distribution profiles
- aggregate reconciliation
- deterministic sample comparison
- configurable tolerances
- approved source/target dataset mapping and baseline acquisition

The implemented comparator operates only on supplied authoritative snapshots. It does not acquire
runtime schemas or prove end-to-end source-to-target parity.

## v4: Semantic parity

**Not implemented.**

Planned capabilities:

- workload-specific business assertions
- population inclusion/exclusion validation
- financial reconciliation
- healthcare measure equivalence
- advanced statistical comparison
- predictive-model behavior comparison

## v5: Performance validation

**Not implemented.**

Planned capabilities include representative runtime baselines, regression thresholds, and evidence suitable for certification without treating performance as a substitute for correctness.

## v6: Automated remediation and review

**Not implemented.**

Failed eligible checks can eventually be routed to bounded remediation. The remediation path is expected to consume:

- SAS source
- generated artifact
- assessment
- conversion manifest
- validation evidence
- execution/runtime evidence when available

Retries must remain bounded. Exhausted, protected, ambiguous, or high-risk failures route to a human-review workflow.

## Certification Boundary

No individual validation layer should directly imply production promotion.

Certification and promotion require an evidence-based gate that evaluates the validation layers required by workload risk and policy.
