# File and external-feed inventory (BASE-07)

## Bounded capability

BASE-07 consumes the occurrence-bound static data-access evidence produced by WLD-03 and
TASK-04. It does not parse SAS a second time. For each eligible literal access it records the
source occurrence, immutable source checksum and span digest, input/output direction, physical
asset kind, root-relative path identity, acquired byte digest, observed filesystem metadata,
contract fields, delivery evidence, state, and blockers.

The production authorized-root set is deliberately empty. Acquisition is available only for a
marked synthetic fixture root beneath the operating system's temporary directory. Each path
component and file is opened descriptor-relative with no-follow semantics. Static source bytes are
re-read in the same manner and must still match the admitted artifact checksum before inventory
evaluation proceeds.

Filesystem modification timestamps are observations only. They never establish freshness.
Freshness requires an Ed25519-verified delivery receipt bound to the client, workload, exact source
closure, policy, run, attempt, source occurrence, and acquired asset bytes. Missing receipts remain
pending; invalid or replayed receipts are denied; stale verified receipts are blocked. Missing owner,
cadence, timezone, or freshness requirements remain explicit contract blockers. Caller-added `exists`,
`fresh`, `approved`, `authorized`, or `complete` metadata is ignored.

The immutable result and consumer projection are separate artifacts. Publication is create-only and
idempotent: the first immutable result remains canonical, and a retry recreates a missing projection
from that persisted result even if mutable asset bytes were reevaluated later. Canonical digest or
projection collisions fail closed. Telemetry reports an inventory evaluation, never execution,
validation, parity, certification, human approval, production qualification, or completion.

## Acceptance evidence matrix

| Criterion | Test or review artifact | Procedure | Expected and actual result | Immutable reference |
|---|---|---|---|---|
| BASE-07-AC01 | `test_incomplete_contract_fields_remain_explicit_blockers`, `test_freshness_requirement_without_receipt_remains_blocked`, and `test_signed_receipt_is_bound_and_freshness_is_evidence_backed` | Run the focused BASE-07 unit suite. | Owner, cadence, timezone, freshness, authority, accessibility, and receipt fields are explicit; missing requirements stay pending, a fresh signed delivery satisfies the contract, and a stale one blocks. Passed. | Test source plus deterministic result `content_digest`. |
| BASE-07-AC02 | Input/output, source-scoped path, and occurrence-retargeting tests in `test_base07_asset_inventory.py` | Run the focused suite against marked local fixture roots and mutate dataset location/name plus access reference/source path independently. | Literal inputs and outputs remain separate; only root-confined bytes are observed; occurrence evidence cannot be retargeted to other physical bytes. Passed. | Occurrence `access_id`, source/span digests, path identity, and asset SHA-256. |
| BASE-07-AC03 | Missing, traversal, mutation, malformed-enum, duplicate-ID, stale, and replay tests in `test_base07_asset_inventory.py` | Run the focused suite. | Each condition blocks or is explicitly pending/denied; output existence does not prove input existence. Passed. | Deterministic blocker values in immutable results. |
| BASE-07-AC04 | Focused suite, canonical-result publication recovery tests, and this review record | Run focused tests, then `make verify`; inspect claims and production-root count. | Offline mechanics are evidenced; production inventory, execution, validation, parity, certification, human approval, and completion remain false. Ruff, mypy, 21 focused tests, and all 1,871 repository tests passed; `pip-audit` was blocked by DNS failure resolving `pypi.org`, so the full gate remains incomplete. | Result/projection IDs bind workload, source closure, policy, run, and attempt; recovered projection binds the persisted canonical `content_digest`. |
| HC-01 | Result/item identity construction, canonical lineage re-derivation, retargeting regressions, and receipt-binding tests | Inspect identities and run focused tests. | Evidence binds client, workload, source closure/bytes, policy, run, attempt, occurrence, literal path, and asset bytes; mismatched dataset/access bindings fail before asset acquisition. Passed. | `inventory_result_id`, `inventory_item_id`, `content_digest`. |
| HC-02 | Non-consumer review of `smf.asset_inventory` | Search the package for recall or memory consumers. | No recall store or recalled advice is consumed; acceptance has no recall dependency. Not applicable with evidence. | Package source review. |
| HC-03 | Source mutation, canonical occurrence-binding, source-scoped path, and direction tests | Mutate qualified SAS bytes, dataset identity, access identity, and relative locations. | Mutated source or retargeted occurrence identity is rejected; physical evidence is not a SAS oracle or target parity claim. Passed. | Source checksum and occurrence span digest. |
| HC-04 | Marker/root confinement, traversal, caller-assertion, and signed-receipt tests | Run focused negative tests. | Only marked temporary fixture roots are readable; traversal and unsigned authority fail closed. Passed. | Policy digest and explicit blocker state. |
| HC-05 | Empty, missing, denial, stale, recovery, and telemetry tests | Run focused suite and full repository gate. | Empty/skipped/generated-only work cannot become complete; blocked and pending outcomes stay visible. All 21 focused tests and 1,871 repository tests passed. The dependency-security audit could not resolve `pypi.org`, so HC-05 remains blocked for closure. | Immutable result, projection, and bounded telemetry event. |

## Scope and non-applicability

This is a read-only evaluator plus create-only evidence publication; it has no external execution to
cancel. Cancellation evidence is therefore not applicable to this increment. Publication restart is
applicable and tested. Two evaluations are isolated by workload/run/attempt identity; no mutable
global inventory state exists. No Humana paths, SAS servers, databases, feeds, schedulers, mounts, or
external services are accessed. No customer owner, cadence, freshness, endpoint, retention policy,
or delivery authority is supplied by this implementation.
