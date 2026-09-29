# Discovery Pipeline Overview

Discovery builds an evidence-backed model of a SAS workload system. The unit of understanding is broader than a `.sas` file.

## Current flow

```text
                       smf discover <source>
                                |
                                v
                  +---------------------------+
                  |     Acquisition Provider  |
                  |---------------------------|
                  | Filesystem                |
                  | SAS 9.4 Content Assessment|
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |      Artifact Inventory   |
                  | paths, type, hash, evidence|
                  +-------------+-------------+
                                |
                 +--------------+---------------+
                 |              |               |
                 v              v               v
        +----------------+ +-------------+ +----------------+
        | SAS Static Refs| | Data Endpoint| | Scheduler /    |
        | READS / WRITES | | + External   | | Launch Context |
        | INCLUDE / macro| | Dependencies | | shell/JIL/cron |
        +--------+-------+ +------+------+ +--------+-------+
                 |                |                 |
                 +----------------+-----------------+
                                  |
                                  v
                    +---------------------------+
                    | Canonical Workload Graph  |
                    |---------------------------|
                    | artifacts                 |
                    | datasets                  |
                    | external dependencies     |
                    | evidence                  |
                    | relationships             |
                    | outputs + consumer state  |
                    +-------------+-------------+
                                  |
                                  v
                    +---------------------------+
                    | Deterministic Enrichment  |
                    | producer/consumer lineage |
                    | downstream output state   |
                    | program ordering/deps     |
                    +-------------+-------------+
                                  |
                                  v
                         Assessment / Planning
```

## What is modeled

```text
SAS Program A --WRITES--> Dataset X --CONSUMED_BY--> SAS Program B
     |                                                   |
     +--INCLUDES--> Macro/Include                        +--WRITES--> Dataset Y
     |
Scheduler Job --TRIGGERS--> Shell Wrapper --TRIGGERS----+
```

Every edge is backed by observed evidence. Unknown or dynamic references remain unresolved instead of being guessed.

## SAS macro strategy contract

Filesystem discovery emits `macro_analysis` under the canonical workload using
`smf-sas-macro-discovery/1.0`. The strategy has `expansion_mode: none`: it discovers
literal definitions, calls, variables, quoting operations, and `%include` references, but
does not execute or emulate the SAS macro processor. A `unique_static_definition` means
one occurrence was visible in the calling artifact or its uniquely resolved literal-include
closure. It is dependency evidence, not expanded source or semantic equivalence.

Every occurrence records the physical artifact ID, exact source SHA-256, byte range,
line/column, span digest, normalized identity, strategy digest, and discovery identity.
Definition IDs include the occurrence range, so duplicate definitions in one file remain
ambiguous. Missing, dynamic, recursive, cyclic, runtime-dependent, unsupported, boundary-
escaping, encoding, and limit outcomes remain blockers. SAS intrinsic operations,
`PROC FORMAT` definitions, and target-template constructs have separate types.

The scanner reads and hashes one byte acquisition, decodes UTF-8 strictly, applies
deterministic limits, and stores no macro body, argument, or `%let` value. It has no runtime
network, embedding, LLM, hook, scheduler, transcript, or external-memory dependency.

Before the canonical workload exists, one recursive sanitization boundary removes
credential values from provider evidence, including nested metadata, shell/JIL/cron
commands, environment assignments, authenticated URIs, and connection strings.
Downstream enrichments therefore consume sanitized facts and do not implement their
own redaction rules. The observed source tree is read-only during this operation.

## Current discovery foundation

Implemented foundations include:

- stable canonical workload/artifact/dataset identities;
- filesystem inventory and SAS 9.4 Content Assessment inventory ingestion;
- deterministic SAS source-reference discovery;
- canonical recursive discovery-evidence credential sanitization;
- external connection, filesystem, executable, environment-variable, and unresolved-connection inventory;
- deterministic producer/consumer data-lineage derivation;
- canonical output inventory with observed downstream consumers and explicit unresolved state;
- shell-wrapper, AutoSys JIL, and cron scheduler/launch dependency discovery;
- controlled, adversarial, and untouched-public-corpus discovery tests.

## Important boundaries

The current implementation is not full enterprise discovery. It does not provide executable macro expansion, resolution of ambiguous or runtime-generated `%include` paths, SAS runtime history, SAS Job Flow Scheduler/Platform Process Manager ingestion, Control-M/API integration, database catalog inspection, enterprise BI/report/application consumer enrichment, or final business workload boundary detection.

Those are enrichment layers around the same canonical graph rather than reasons to replace the model.


## Workload boundary proposals

After lineage and downstream-output derivation, filesystem discovery now derives
evidence-backed workload boundary proposals. Connected artifacts are grouped from
deterministic `INCLUDES`, `CALLS`, `TRIGGERS`, `PRECEDES`, and artifact-to-artifact
`DEPENDS_ON` relationships. Dataset, output, and external-dependency context is then
attached to each proposal. Referenced-only external scheduler artifacts remain
unresolved adjacency rather than silently becoming workload members.

See `workload-grouping-boundary-detection.md`.


## Current-state topology

After boundary detection, discovery projects canonical entities and relationships into a navigable current-state topology. Boundary-level edges preserve source relationship evidence, referenced-only external artifacts remain visible, and the topology explicitly does not claim complete enterprise coverage. See [Current-State Workload Topology](current-state-workload-topology.md).
