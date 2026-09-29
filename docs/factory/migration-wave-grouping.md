# Migration Wave Grouping

## Purpose

WLD-13 turns canonical workload evidence into **migration grouping and relative sequencing proposals**. It answers a planning question that is different from code conversion: which workload boundaries have evidence that they should be planned together, and which groups have deterministic predecessor relationships?

The output is not a committed delivery schedule. The factory does not assign calendar dates, sprint capacity, staffing, business blackout windows, or final migration waves in this foundation.

## Inputs

Wave grouping consumes the canonical workload model established by discovery and modernization decision inputs. Relevant evidence includes:

- proposed workload boundaries;
- artifact-to-artifact execution dependencies;
- shared datasets;
- shared external dependencies;
- target-state pattern input unknowns and unresolved consumer/boundary evidence; and
- provenance attached to the underlying canonical facts.

## Grouping Semantics

The grouping engine uses two different concepts deliberately.

### Affinity

Boundaries that share a dataset or external dependency have migration affinity. The foundation groups them for joint planning because independent migration could create avoidable coordination or cutover risk. Shared infrastructure is not treated as proof that the workloads are the same business workload.

### Dependency order

Canonical `PRECEDES`, `TRIGGERS`, and `DEPENDS_ON` relationships are normalized into predecessor-to-successor direction. Independent groups retain predecessor group IDs and a relative `sequence_rank`.

Circular dependencies are kept in one group so the cycle is visible as a joint-planning problem rather than hidden behind an arbitrary ordering.

## Canonical Output

`MigrationWaveGroup` contains:

- stable `wave_group_id`;
- participating `boundary_ids`;
- `predecessor_group_ids`;
- relative `sequence_rank`;
- evidence-backed `coupling_reasons`;
- unresolved items inherited from target-state recommendation inputs;
- merged discovery evidence; and
- metadata explicitly stating that no calendar wave has been assigned.

## Governance Boundary

The factory proposes dependency-aware planning structure. It does not autonomously commit a workload to Wave 1, Wave 2, a sprint, a date, or a staffing plan.

Final sequencing may require evidence that discovery cannot determine from SAS code, including business priority, SME availability, blackout periods, target-platform readiness, data-domain release plans, regulatory/control windows, and organizational change constraints.

```text
Canonical workload evidence
          |
          +-- dependency direction
          +-- shared datasets
          +-- shared external dependencies
          +-- unresolved evidence
          |
          v
MigrationWaveGroup proposals
          |
          +-- affinity cohorts
          +-- predecessor groups
          +-- relative sequence rank
          +-- unresolved planning inputs
          |
          v
Governed wave planning
          |
          +-- capacity
          +-- business priority
          +-- blackout windows
          +-- SME readiness
          +-- target readiness
          |
          v
Committed migration waves   FUTURE
```

## Non-Claims

WLD-13 does not claim that:

- the discovered estate is complete;
- a shared dependency alone proves business coupling;
- `sequence_rank` is a calendar wave number;
- all business sequencing constraints are discoverable from source artifacts; or
- the factory can autonomously commit enterprise migration waves.
