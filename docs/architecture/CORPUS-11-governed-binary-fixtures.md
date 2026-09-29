# CORPUS-11 Governed Binary Fixture Qualification

## Decision and boundary

CORPUS-11 supplies an offline, deterministic qualification contract for SAS binary fixtures. It
classifies each admitted byte artifact as `licensed`, `evaluation_only`, `customer_controlled`, or
`prohibited`, and emits immutable evidence suitable for later reader testing. It does not acquire
fixtures, accept a license, authorize redistribution, inspect customer systems, prove reader
behavior, or establish migration readiness.

The contract is default-deny. A fixture is usable only in a declared purpose when its byte digest,
source revision, producer metadata, license/provenance evidence, authority, and completed UPQ-01
and LIC-01 prerequisite evidence reconcile exactly. Synthetic contract fixtures can prove mechanics
but can never authorize a real artifact.

## Inputs and trust boundaries

- A strict, independently signed policy identifies the client boundary, approved purposes,
  verification keys, separate policy/manifest/prerequisite/evaluator trust domains, authority
  allowlists, and the exact accepted UPQ-01 and LIC-01 result digests. Its admitted canonical bytes
  and digest are immutable and reverified at every evaluation/replay boundary. Unknown and
  duplicate fields are rejected. Trust-domain separation compares canonical Ed25519 public-key
  bytes as well as key IDs, so aliases cannot reuse one key under multiple names.
- A signed manifest binds client, workload, source, run, attempt, manifest revision, collection
  time, evidence class, and every fixture's stable ID, relative logical name, media type, byte
  length, SHA-256 digest, producer, producer version, SAS artifact/version metadata, source
  revision, asset class, allowed purposes, redistribution state, license evidence, provenance
  evidence, and authority.
- Signed prerequisite receipts bind the same client/workload/source/run/attempt and their exact
  canonical result digest. Project status alone is never prerequisite evidence.
- Fixture bytes are optional inputs to this gate. When supplied, they are read only from a
  caller-authorized local root using no-follow, regular-file checks. Their length and digest must
  match the signed manifest. Missing bytes remain visibly blocked rather than inferred from names.

## Deterministic decision

The evaluator sorts fixtures and blockers, rejects duplicate or case-ambiguous identities and
logical paths, and derives a stable result identity from the complete policy and manifest digests.
Outcomes are exactly `qualified_contract`, `blocked`, `denied`, `incompatible`, or `stale`.

- `licensed` may be admitted only for an approved purpose when redistribution and license evidence
  explicitly permit that purpose.
- `evaluation_only` may be used only for evaluation and can never be redistributed or treated as a
  customer baseline.
- `customer_controlled` requires customer authority and remains non-redistributable; synthetic
  evidence cannot satisfy it.
- `prohibited` is always denied.

Every result fixes authorization claims for customer access, redistribution, migration, parity,
and readiness to `false`. A `qualified_contract` result means only that the offline fixture-use
contract was satisfied for the declared purpose.

## Evidence and recovery

The canonical result is signed by the evaluator and published under a run/workload/attempt path
using the repository's immutable no-replace publisher. Replay revalidates signatures, current
policy and manifest bytes, prerequisite receipts, optional local fixture bytes, and reconstructs
the complete decision. Identical retry is idempotent; mutation or cross-workload substitution is
rejected.

## Acceptance map

| Criterion | Design evidence |
|---|---|
| CORPUS-11-AC01 | Closed four-class model and purpose-specific, default-deny disposition rules |
| CORPUS-11-AC02 / HC-01 | Signed policy, manifest, prerequisites, evaluator result and stable digest-bound identities |
| CORPUS-11-AC03 / HC-05 | Closed schemas plus missing, unauthorized, stale, mutation and rejected ambiguous-input tests |
| CORPUS-11-AC04 / HC-02 | Exact revision, producer, license, provenance, upstream-result and byte identities retained |
| HC-03 | No reader, conversion, parity or migration-success claim; optional bytes reconcile independently |
| HC-04 | Root-confined no-follow reads, safe identities/paths, separate trust domains and workload isolation |

## Stop rules

Stop and retain a non-success outcome for missing or inconsistent prerequisite evidence, unknown
license/redistribution authority, prohibited assets, customer-controlled assets without explicit
customer authority, absent or changed bytes, or stale evidence. Unsupported or ambiguous inputs
are rejected by the closed schemas rather than represented as extra outcomes. No exception or
implicit approval is available in CORPUS-11.
