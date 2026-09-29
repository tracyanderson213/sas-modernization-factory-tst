# Governed workload complexity

The workload-complexity contract provides deterministic, explainable classification over canonical
discovery evidence. It does not authorize migration readiness, conversion, execution, validation,
parity, certification, deployment, or human approval.

## Inputs and boundaries

`WorkloadComplexityRequest` binds one client, workload, boundary, run, attempt, and assessment
execution to a canonical discovery snapshot and a source closure rooted under an authorized local
directory. Assessment requires:

- exactly one matching workload and boundary;
- a non-empty boundary with one meaningful SAS entry point;
- byte size and SHA-256 agreement for every closure artifact;
- a dependency graph that reconstructs the complete boundary closure;
- an authoritative macro strategy, exact source-inventory checksums, and byte-verified observation
  spans when macro evidence is supplied; and
- one canonical, active, digest-valid policy scoped to the client.

Absolute, remote, traversal, encoded-traversal, symlinked, missing, mutated, protected-data-bearing,
duplicate, and ambiguous inputs fail closed.

## Scoring and unknowns

The supported dimensions are static constructs, macro behavior, dependency topology, data access,
source scale, and static validation difficulty. Policies assign integer feature weights, per-feature
limits, dimension caps, and ordered tier thresholds. Observations are extracted from canonical source,
graph, dataset, relationship, and macro records; caller-projected scores and pass booleans are not
inputs.

Canonical observation identity includes the dimension, feature, subject, evidence identity, method,
and origin digest. Repeated identical evidence is counted once, while duplicate canonical entity IDs
are rejected. A required or tier-critical dimension that is partial or unknown prevents a tier; it
never defaults to `simple`. Sensitivity reports the current score, policy-bounded possible maximum,
unknown dimensions, and distance from every threshold.

## Result authority and persistence

The canonical result binds discovery, workload, boundary, source closure, artifact bytes, dependency
graph, macro analysis/strategy, policy, run, attempt, and assessment execution identities. Its boolean
authorization and success claims are fixed to false. A governed consumer requires an Ed25519 proof
from an authority and key allowed by the exact policy; a locally inspectable unsigned result has no
governed authority. Consumption also reconstructs policy-derived counts, contributions, score, tier,
unknowns, blockers, and sensitivity, and rejects inactive, pending, denied, or expired policy state.

Estate reporting requires the trusted policy set and authorized source root. It revalidates the
schema, result digest, signature, policy semantics, and current source bytes before a workload can
count as classified evidence; arbitrary or digest-recomputed dictionaries cannot enter the
distribution.

`write_workload_complexity_result()` publishes beneath:

`out/runs/<run-id>/workloads/<workload-id>/attempts/<attempt-id>/complexity/<boundary-id>/`

Publication requires the authorized `source_root` and re-hashes every qualified artifact immediately
before the canonical write. The canonical result is append-only. An identical retry returns it
unchanged and recreates a missing derived explanation. A conflicting retry for the same decision path
fails.

## Humana boundary

`deployments/humana/complexity.yaml` is a structurally valid `pending` template with zero weights.
It cannot classify the Humana estate. Named owners must approve weights, caps, thresholds, authority
keys, source inventory, and cohort semantics before activation. The implementation does not claim an
official 1,000-script distribution or ten-week competition proof.
