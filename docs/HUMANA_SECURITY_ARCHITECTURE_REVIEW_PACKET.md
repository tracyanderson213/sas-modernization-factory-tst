# Humana security and architecture review packet

HENV-03 provides an offline, immutable review-evidence packet. It does **not** authorize protected-data execution, competition acceptance, certification, or promotion. Protected execution remains governed by the separate signed, exact-subject HENV-01 activation contract.

## Packet contents and boundaries

`smf architecture-review assemble` replays a canonical discovery manifest and binds one meaningful SAS
entry point to the exact discovered workload, boundary, complete artifact closure, dependency graph,
client, deployment, environment, run, attempt, repository revision, deployment bundle, security threat
model, competition requirements, and optional replay-validated readiness manifest. The entry point must
contain an executable SAS `DATA` or `PROC` construct; empty, comment-only, `%let`-only, `%include`-only,
substituted, omitted, changed, symlinked, or caller-invented source identities fail closed. Every artifact
in the complete source closure is sensitive-scanned before its digest is admitted. Governed locators are
recorded and the complete closure is re-hashed when a packet is written or loaded, so post-assembly entry
or include mutation prevents persistence/use.

The command is network-free. It performs no authentication, endpoint probe, deployment, source or target execution, validation, external transmission, or approval. Missing HENV-01 evidence and every pending client requirement remain distinct blockers. Generated, executed, validated, parity-passed, certified, human-approved, human-assisted, and blocked telemetry claims remain separate.

Canonical evidence is published beneath:

```text
runs/<run>/workloads/<workload>/attempts/<attempt>/architecture-review/<packet-id>/
```

`packet.manifest.json` is canonical. `packet.internal.json` and `packet.telemetry.json` are derived and can be recovered idempotently after interrupted publication. Existing conflicting canonical bytes are rejected. Workload and attempt identities are path-isolated.

The internal projection remains controlled evidence. Shared publication is not authorized by three request
strings: it requires a signed, unexpired disclosure decision bound to client, deployment, environment,
assessed revision, recipient class, disclosure-policy revision, and retention reference. The shared payload
uses a strict schema and a minimal allowlist of identifiers, digests, lifecycle state, and approval states;
it excludes endpoint values/digests, free-text roles, configuration locators, and assignment evidence.

Requirement references and owner evidence are separate. Each readiness prerequisite has validated
`requirement_refs` stating which client requirements apply. Its nullable `owner_assignment_ref` is an
independent governed assignment identity; a missing/pending assignment cannot qualify. An
`assignment_decision` exists only after signature, authority, environment, revision, scope, validity, and
provenance checks. HC requirement identifiers are never used as owner-assignment evidence.

A signed HENV-01 activation decision is accepted only alongside a replay-valid `READY` readiness manifest
whose workload digest, entry point, complete artifact closure, and selected boundary exactly match
canonical discovery. The decision is then verified against the exact workload/source digest, boundary,
run, attempt, environment, configuration, readiness result, validity window, authority, and signature.
Forged, stale, expired, cross-environment, cross-boundary, or differently bound evidence is rejected. The
packet still has `authority: non_authorizing`; `HashiCorpVaultSecretProvider.resolve` rejects the packet
or invalid activation before Entra/Vault transport and independently verifies the signed HENV-01 evidence.

## Current Humana disposition

The checked-in Humana bindings remain placeholders or pending. HC-REQ-03, HC-REQ-06, HC-REQ-09, and HC-REQ-10 are explicitly included along with the existing requirement set. SAS baseline ownership maps to HC-REQ-03; Databricks environment and data scope to HC-REQ-05; validation rules to HC-REQ-04; capacity limits to HC-REQ-07; model/data retention controls to HC-REQ-06; signatories and evidence handoff to HC-REQ-09; and Entra/Vault authority to HC-REQ-10.

No real Humana endpoint, signed approval, protected-data execution, or parity result is present in the repository. An offline packet therefore correctly terminates as `blocked` while still providing reviewable architecture evidence.

## Acceptance evidence matrix

The source baseline for this local repair is Git commit
`8f7f2d3ae62557094e749316b5e4a912a88788df`; configuration inputs are the exact working-tree files
validated and digested by the tests. The candidate changes are uncommitted, so no immutable release
artifact exists yet. Local test results below are reproducible evidence, not live-Humana or release proof.

| Criterion | Source/config revision | Exact procedure | Expected | Actual | Safe immutable evidence reference |
|---|---|---|---|---|---|
| HENV-03-AC01 | baseline above + candidate schemas/discovery replay | focused command below; `test_static_only_sas_is_not_a_meaningful_execution_subject`, `test_sensitive_canary_in_transitive_source_closure_is_rejected` | Executable entry and complete canonical closure qualify; substitution/static-only/sensitive closure fail | PASS locally in 34-test packet/CLI subset and 214-test focused set | Unavailable until candidate commit; release verification remains unverified |
| HENV-03-AC02 | candidate readiness schemas/policy/template + requirement contracts | focused command below; `test_humana_prerequisites_keep_requirement_ownership_separate` and readiness engine cases | Per-prerequisite requirement refs validate; assignment evidence remains independent and fail-closed | PASS locally in 214-test focused set | Unavailable until candidate commit; no governed Humana assignments supplied |
| HENV-03-AC03 | candidate signed-decision, exact-source READY binding, real Vault admission, strict shared schema | focused command below; activation mutation/consumer-transport/disclosure tests | Only exact READY-bound signed evidence verifies; packet never authorizes; rejection makes zero provider calls | PASS locally in 214-test focused set | Unavailable until candidate commit; no live Humana decision or transport supplied |
| HENV-03-AC04 | candidate append-only manifest/source replay | focused command below; `test_persisted_packet_revalidates_entry_and_closure_before_use`, recovery, mutation and isolation cases | Post-assembly source mutation fails; conflicting canonical bytes fail; derived output recovers; attempts remain isolated | PASS locally in 214-test focused set | Unavailable until candidate commit; no competition exit artifact supplied |
| HC-01 | candidate packet/source/readiness schemas | focused command below | Local identities and source/config/policy/readiness digests bind exactly | PASS locally in 214-test focused set | Unavailable until candidate commit; live environment binding unverified |
| HC-02 | architecture-review import/code-path inspection | `rg -n "recall|memory" src/smf/architecture_review` | No recall dependency | No recall dependency found; N/A to packet runtime | Baseline/candidate source only; no separate immutable experiment artifact |
| HC-03 | non-authorizing lifecycle schema and real Vault admission guard | focused command below | Packet asserts no execution/parity/certification/approval and cannot invoke provider transport | PASS locally in 214-test focused set | Unavailable until candidate commit; semantic parity remains unverified |
| HC-04 | full-closure source/requirements canaries and governed shared projection tests | focused command below | Sensitive free text is rejected before hashing/persistence; shared schema rejects extras | PASS locally in 214-test focused set | Unavailable until candidate commit; no protected Humana data used |
| HC-05 | positive/negative/mutation/CLI/reload/transport-call tests | focused command below | Missing/denied/replayed states remain visible; exact-bound synthetic positive works; mocks do not imply live success | PASS locally in 214-test focused set | Unavailable until candidate commit; live environment remains unverified |

Focused commands:

```bash
pytest -q -p no:cacheprovider \
  tests/unit/test_architecture_review_packet.py \
  tests/integration/test_architecture_review_cli.py \
  tests/unit/test_secret_provider.py \
  tests/unit/test_readiness_engine.py \
  tests/unit/test_deployment_configuration.py
```
