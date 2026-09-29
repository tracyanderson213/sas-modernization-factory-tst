# BASE-01 Acceptance Matrix

Status: implemented offline contract; live competition qualification blocked. Commands and artifacts
below are deterministic repository evidence, not a claim of Humana execution.

| Criterion | Concrete proof | Expected and actual offline result | Live status |
|---|---|---|---|
| BASE-01-AC01 | `test_approved_export_acquires_attributable_immutable_output`; CLI integration test | Signed approved export is acquired; unsupported direct SAS mode blocks | Real signed export not supplied |
| BASE-01-AC02 | positive acquisition, readiness binding, replay tests | Source/input/runtime/execution/output/policy/approval identities and hashes persist | Owner review pending |
| BASE-01-AC03 | missing approval, source replay, target-origin, byte-mutation, schema and signature tests | False, stale, altered, and target-derived claims fail closed | Humana access absence remains an environment blocker |
| BASE-01-AC04 | corruption, recovery, boundary inventory, duplicate identity and conflicting-baseline readiness tests | Exact selected-boundary output is immutable and replay checked; conflicting authoritative results block | Cohort and business-policy review pending |
| BASE-01-AC05 | signed receipt subject and separate approval tests | Synthetic contract proves stale/altered rejection only | Ten-week real proof not executed |
| HC-01 | approval replay, producer-controlled approval-root rejection, readiness result/artifact replay | Evidence binds workload revision, source closure, run, attempt, boundary, exact trusted acquisition policy, distinct trust domains, execution, and outputs | Pass for offline contract |
| HC-02 | no baseline code imports a recall subsystem | Acceptance does not depend on remembered or derived advice | Pass; no recall consumer |
| HC-03 | target-derived origin and corpus evidence gates | Only independently signed `sas_execution` origin can acquire; synthetic corpus remains synthetic | Pass for offline contract |
| HC-04 | unsafe identity, sensitive metadata, traversal, symlink and immutable-path controls | Unsafe metadata/path references reject before trusted persistence | Pass for offline contract |
| HC-05 | focused positive/negative suite and truthful telemetry assertions | Generated/executed/validated/parity/certified stay false; missing/pending/denied are distinct | Live proof blocked |

Focused gate:

```bash
./scripts/test-baseline-confidence.sh
```

Required repository gate:

```bash
make verify
```

The confidence report records the repository revision, exact commands, return codes, and SHA-256
digests for BASE-01 implementation and schema artifacts. A green offline report does not replace the
real-environment evidence and human integration review named above.
