# HMET-01 automation KPI acceptance

HMET-01 measures a versioned cohort from immutable, root-confined attempt
receipts. The cohort policy fixes distinct workload and script denominators,
the source revision for each workload, the evidence authority, and the
measurement window. Missing members remain unresolved in the denominator.

## Metric definitions

- **Straight-through parity:** parity on attempt one through the deterministic
  path, with no repair and no human touch.
- **Eventual automated parity:** parity without human touch after a retry,
  bounded automated repair, or the governed AI-assisted path.
- **Human-assisted parity:** parity with an explicit review, repair, or business
  decision and measured human minutes.
- Generated, executed, validated and parity-passed workloads are independent
  cumulative counts. None is inferred from an earlier stage.
- Throughput uses distinct parity-passed workloads divided by the policy's
  fixed wall-clock window. Summed elapsed and machine time are reported
  separately and are not mislabeled as wall-clock throughput.

Retries remain attached to one workload, and a human touch on any attempt makes
the eventual passing workload human-assisted. A second success, an attempt after
parity, a duplicated attempt, a gap in attempt ordinals, a source/cohort/
authority mismatch, or a stage-claim contradiction fails closed. Blockers from
earlier attempts remain visible even when a later attempt passes. Skipped work
is a named non-parity outcome and remains in the denominator.

## Acceptance matrix

| Criterion | Evidence |
| --- | --- |
| HMET-01-AC01 | Mixed synthetic cohort tests derive mutually exclusive straight-through, eventual automated, human-assisted, blocked and unresolved workload outcomes. |
| HMET-01-AC02 | Strict schemas and result invariants publish workload/script denominators, stage numerators, category counts, rates, wall-clock throughput, elapsed/machine time, repair count and human minutes separately. |
| HMET-01-AC03 | Duplicate attempts, multiple success, post-success attempts, human-touch relabeling, claim progression and missing members fail closed or remain visible. |
| HMET-01-AC04 | Source, cohort, evidence-authority, lifecycle-result, run and attempt identities are digest-bound; immutable replay, mutation and two-cohort isolation are tested. No Humana execution is claimed. |
| HMET-01-AC05 | Distinct script and workload denominators, attempt deduplication and explainable exclusive outcomes are machine-readable. Generated-only and executed-unvalidated cases do not increase parity. |
| HC-01 | Generated, executed, validated, parity, human assistance and higher-order customer claims remain separate. |
| HC-02 | Not applicable by design: current immutable evidence is evaluated without recall, embeddings or advisory memory. |
| HC-03 | The KPI layer does not convert SAS or treat workshop/target output as a baseline. |
| HC-04 | Secret-like identities and unsafe paths are rejected before persistence; attempt details are categorical and contain no source rows or provider errors. |
| HC-05 | Positive, negative, adversarial, mutation, retry and isolation tests keep blocked/failed/skipped outcomes visible. |

The checked-in fixtures prove only synthetic contract mechanics. The attempt
receipt does not independently qualify its upstream lifecycle evidence; the
policy must name the admitted evidence authority, and a real competition report
requires independently qualified current lifecycle, execution, validation and
parity receipts. No real Humana cohort, production throughput, customer
validation, readiness or migration-completion claim is established.

Full-suite, vulnerability, combined-train and remote-CI results belong to the
integration boundary and must not be inferred from focused HMET-01 tests.
