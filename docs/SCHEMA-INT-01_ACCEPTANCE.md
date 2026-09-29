# SCHEMA-INT-01 bounded acceptance evidence

SCHEMA-INT-01 proves that the completed DP-01 structural comparator consumes the current
authoritative BASE-04 cross-provider source descriptor and the BASE-02 governed target descriptor.
The integration replays the DBPKG-04 local Delta evidence and DBPKG-01 offline target-validation
plan through their official current-input verifiers before it constructs either DP-01 snapshot.
Caller-supplied identifiers and digests cannot substitute for current upstream evidence.

The source and target snapshots retain distinct provider provenance while sharing an explicit
logical comparison identity. The target is schema-enforced as a governed BASE-02 plan bound to a
reconciled local Delta result; it is not represented as an observed Delta or Unity Catalog schema.
Type, order, name, width and nullability differences remain visible through DP-01 checks. Results
are request-bound, immutable, deterministic and replayed against the current upstream chain.
Unknown physical types, incomplete mappings, content drift, identity drift, unsafe identifiers and
incompatible ingestion evidence fail closed.

## Acceptance matrix

| Criterion | Evidence |
| --- | --- |
| SCHEMA-INT-01-AC01 | The existing DP-01 comparator consumes projected BASE-04 and BASE-02 descriptors; passing and renamed-target tests prove comparison behavior. |
| SCHEMA-INT-01-AC02 | Request, upstream result/content/descriptor identities, DP snapshots, comparison and implementation contract are deterministically sealed. |
| SCHEMA-INT-01-AC03 | Strict nested-schema negatives, digest drift, unsupported physical types, unqualified targets, unsafe identities and coherent result mutation fail closed. |
| SCHEMA-INT-01-AC04 | Current official verifier composition binds the descriptor comparison to BASE-04, BASE-02, DBPKG-04 and DBPKG-01 evidence. |
| HC-01 / HC-02 | Client, workload, source, run, attempt, dataset and exact upstream identities remain attributable and replayable. |
| HC-05 | Two-workload evidence isolation, mutation and plan-reclassification negatives remain fail closed. |
| HC-03 / HC-05 | DP-01 pass/fail/blocked results stay explicit; generated target descriptors alone never establish data or semantic parity. |
| HC-04 | Safe identifiers and existing no-follow immutable evidence boundaries prevent secret-bearing identity and path substitution. |

Run `make schemaint-confidence` for the focused gate.

This gate proves descriptor integration only. It does not contact Databricks or Unity Catalog,
perform a remote write, prove row/cell reconciliation, establish SAS semantic parity, validate a
Humana environment, certify production readiness, or declare migration completion.
