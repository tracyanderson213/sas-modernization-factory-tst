# PKG-DES-01 Portability and Dependency Design

## Decision boundary

PKG-DES-01 establishes an offline, non-installing design gate for two deployment profiles:

- `source-only`: SMF source is transferred only after an exact runtime observation proves every
  required wheel, native library, JAR, JVM/Spark/Scala/DBR component is present at the locked
  version and digest and has an explicit intake disposition.
- `offline-packaged`: every missing source-only requirement is named as an intake artifact with an
  exact filename, kind, version, platform, SHA-256, source revision, license, NOTICE, SBOM,
  provenance, vulnerability and intake disposition binding.

The gate loads a closed JSON contract, rejects duplicate keys and unsafe files, reconstructs all
digests, evaluates requirements without fetching or installing anything, and emits an immutable,
request-bound result. A real observation cannot produce an authorization claim in this increment.
`PKG-QUAL-01` remains responsible for qualifying the final provider and transitive artifact set.

## Trust and data flow

1. A caller supplies a local regular-file design contract beneath an explicitly authorized root.
2. The loader rejects symlinks, traversal, duplicate keys, unknown fields, unsafe identities and
   protected values before evaluation.
3. Runtime-matrix, dependency-lock and offline-intake digests are independently reconstructed.
   Each observation binds the exact matrix ID and matrix digest, preventing OS, architecture,
   Python, JVM, Scala, Spark or DBR observations from being interchanged.
4. Source-only eligibility requires exact component/version/platform/digest agreement and an
   `approved` observation for every requirement. Missing or unapproved components are projected
   into the offline artifact plan with filename, kind, version, complete runtime coordinates,
   expected SHA-256 and intake-evidence identities; the evaluator never downloads, installs,
   compiles or substitutes. Observation age is computed against a governed evaluation time and
   maximum age; caller-authored state cannot make future or stale evidence current.
   An absent plan remains an explicit diagnostic blocker and emits no descriptor, but that
   diagnostic cannot pass verification, publication or loading. An incomplete or
   lock-mismatched plan cannot appear in `required_offline_artifacts`. Every emitted descriptor is
   complete and non-null.
5. The canonical result is published with no-replace semantics under the run/workload/attempt
   identity. Replay re-reads the original contract and reconstructs the exact decision.

## Outcomes and claims

`denied`, `failed`, `ambiguous`, `incompatible`, `stale`, `pending`, and `blocked` are distinct.
Only a complete synthetic contract fixture can produce `contract_pass`. All results fix
`authorizes_installation`, `authorizes_distribution`, `authorizes_runtime`,
`qualifies_final_bundle`, and `establishes_humana_readiness` to `false`.

The source-only profile blocks when any dependency is absent, incompatible, unapproved, stale or
ambiguous. Its result identifies the corresponding exact offline artifact. The offline-packaged
profile remains pending or denied until every required artifact has complete hash-locked metadata
and an approved intake disposition. Runtime network access and public downloads are prohibited in
both profiles.

## Acceptance mapping

| Gate | Design evidence |
|---|---|
| PKG-DES-01-AC01 | Runtime matrix, source-only preflight, offline artifact plan and strict lock/intake contract |
| PKG-DES-01-AC02 / HC-01 | Stable result identity and content digest bind client, workload, source, upstream revision, run, attempt, contract and output |
| PKG-DES-01-AC03 / HC-05 | Closed outcomes plus missing, mutation, duplicate-key, traversal and unapproved-input tests |
| HC-02 | Each artifact retains source revision, provenance and applicability digests |
| HC-03 | Exact lock-to-observation reconciliation; generated plans never assert runtime success |
| HC-04 | Root confinement, no-follow reads, protected-data rejection and no secrets in evidence |
| PKG-DES-01-AC04 | Immutable publication and deterministic replay; unresolved inputs remain explicit |

## Prohibited claims

This design does not qualify a final bundle, approve a real package or license, authorize an intake
artifact, inspect a Humana runtime, establish production readiness, or prove migration/parity. It
does not access package registries, public repositories, Azure, Databricks, Humana, Vault or an AI
provider.
