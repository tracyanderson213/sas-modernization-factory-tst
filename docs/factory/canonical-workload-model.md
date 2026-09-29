# Canonical Workload Model

## Purpose

The Canonical Workload Model is the factory's internal representation of a
discovered workload. It is not a questionnaire and is not intended to require
customers to author YAML or JSON.

Discovery providers inspect available evidence and normalize their findings
into this model.

## Core model

A workload contains:

- artifacts, such as SAS programs, macros, includes, configuration, scripts,
  scheduler jobs, and other executable or supporting assets
- datasets, such as SAS datasets, database tables, files, APIs, external feeds,
  and intermediate data
- external dependencies, such as database connections, filesystem prerequisites, executables, and environment requirements
- outputs that reference produced datasets/files and preserve observed downstream-consumer state
- workload-boundary proposals that group connected artifacts while preserving evidence, confidence, and unresolved adjacency
- relationships connecting artifacts, data, and external dependencies
- evidence explaining how each fact was discovered
- optional business and operational context when it is known

Unknown information remains unknown. Missing metadata does not block discovery.

## Secret-sanitization invariant

Canonical `Workload` construction is the sanitization boundary for all discovery
providers. Credential-bearing values are recursively replaced with `<redacted>`
before canonical state can be serialized or used to derive lineage, topology,
scheduler, or planning evidence. This applies to nested metadata as well as command
strings. Safe identity context such as host, database, schema, DSN, username,
executable, and schedule remains available. Sanitization copies in-memory values;
it never rewrites acquired source files or corpus bytes. Durable serialization
re-applies the same sanitizer as defense in depth because nested metadata containers
remain mutable for compatibility with existing canonical consumers.

## Evidence and confidence

Discovered relationships must preserve provenance. Evidence records identify
the discovery method, source, optional locator, observed value, confidence,
and whether the fact has been explicitly confirmed.

Deterministic evidence and inferred evidence are therefore distinguishable.
For example, a SAS `SET` statement can produce high-confidence static-analysis
evidence, while an AI-proposed downstream consumer can remain an inference
requiring confirmation.

## Stable identity

Workload, boundary, artifact, dataset, external-dependency, relationship, and evidence identifiers are
derived from logical identity rather than absolute checkout paths. Moving the
same estate between machines must not create a new workload identity solely
because the filesystem root changed.

## Discovery provider boundary

Discovery is provider-based. SAS source analysis, filesystem crawling, runtime
metadata, scheduler metadata, data-system inspection, and future discovery
mechanisms can independently contribute facts while targeting the same
canonical representation.

The first model deliberately does not attempt to implement every discovery
provider. It establishes the contract those providers will use.

## Human interaction

Human input is an exception-resolution and confirmation mechanism. The normal
flow is:

1. discover available evidence automatically
2. construct the workload graph
3. identify unresolved or low-confidence facts
4. ask targeted questions only where human knowledge is required

The factory should not require a person to document the estate before the
factory can begin understanding it.

## Acquisition

See `docs/factory/discovery-acquisition.md` for the initial filesystem and SAS 9.4 Content Assessment acquisition providers.


## Current-state topology projection

`WorkloadTopology` is a projection of canonical discovery facts, not a competing model. `TopologyNode` references an existing boundary, dataset, external dependency, or referenced-only external artifact. `TopologyEdge` retains the canonical relationship kind and evidence. This allows system-level navigation while preserving artifact-level drill-down and provenance.
