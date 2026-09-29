# Cross-Program Dependency Graph

AD-02 exposes `Workload.dependency_graph`, a deterministic projection of the canonical
discovery entities and relationships. `Workload.relationships` remains authoritative; the
projection can be rebuilt with `derive_dependency_graph()` and does not run a second parser.

WLD-03 additionally exposes `Workload.code_dependency_analysis`, a versioned static code-closure
envelope. It binds acquisition-backed artifact revisions, every `%include` and macro-call
occurrence, resolver/strategy digests, explicit unresolved outcomes, and deterministic strongly
connected ordering groups to one source-closure digest. Its analysis ID and closure digest are
inputs to graph identity, so a source revision cannot silently reuse an earlier graph ID.

## Contract

The graph contains:

- nodes that reference canonical artifact, dataset, and external-dependency IDs;
- direct code (`CALLS` and `INCLUDES`), data, scheduler, runtime-launch, and external edges;
- the canonical relationship ID and evidence supporting every edge;
- all dataset IDs and names supporting an aggregated cross-program lineage edge; and
- typed unresolved observations for dynamic, ambiguous, missing, or external targets, without
  asserting a target edge where none was resolved.

Literal macro calls resolve only when one inventoried artifact defines the macro. Duplicate
definitions and missing or dynamic invocations remain unresolved. Cycles and multiple observed
dataset producers are preserved; the graph does not invent a transitive edge or execution order.
Code ordering uses only source-bound code observations. Dependencies appear before their callers;
resolved SAS configuration dependencies remain in the closure even though they are not independently
convertible subjects; cycles remain a typed group and unresolved, cyclic, or boundary-crossing
references make ordering ineligible rather than disappearing.

IDs and collection order are stable for the same logical estate, including across checkout
locations. CLI JSON includes this dataclass projection, but it remains an evolving internal
discovery contract; the legacy `schemas/workload.schema.json` describes a different workload
shape and is not silently repurposed.

An exact eligible SAS subject can be bound to client, workload, source closure, policy, run,
attempt, and execution identities and published append-only under
`runs/<run>/workloads/<workload>/attempts/<attempt>/code-dependencies/<subject>/result.json`.
Qualification independently replays the attached analysis from discovery evidence, and initial
publication reverifies acquired source bytes. Identical retry is idempotent, conflicting bytes fail,
and missing telemetry can be reconstructed from the canonical result without consulting later-mutated
or removed source bytes.

## Scope

`complete_enterprise_graph` is always `false`. The graph reports statically and operationally
observed estate evidence, not complete runtime lineage, proof that a static call executed, or
federation across independently acquired workloads. Dynamic resolution and enterprise metadata
can enrich the canonical relationships in later stages and then regenerate the projection.
Code qualification similarly never claims generation, execution, validation, parity,
certification, or human approval. It does not execute SAS, expand macros, select an ambiguous entry
point, infer a runtime-only target, or supply missing Humana policies and owner decisions.
