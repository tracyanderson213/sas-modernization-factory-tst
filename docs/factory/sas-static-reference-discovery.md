# SAS Static Reference Discovery

## Purpose

WLD-03 adds deterministic source analysis to filesystem discovery so SMF can
move beyond file inventory and begin building the code and data dependency graph
for a SAS workload.

This capability is deliberately evidence-first. It extracts references that are
visible in SAS source text and records them in the Canonical Workload Model. It
does not execute SAS, expand macros, call an AI model, or infer relationships
that are not present in the source.

## Initial deterministic coverage

The first static analyzer recognizes:

- DATA-step output datasets
- `SET` inputs
- `MERGE` inputs
- `BY` variables
- common `PROC ... DATA=` inputs
- `PROC DELETE DATA=` targets
- common `PROC ... OUT=` targets
- PROC SQL `CREATE TABLE`, `INSERT INTO`, and `UPDATE` targets
- PROC SQL `FROM` and `JOIN` inputs
- literal `INFILE` and `FILE` paths
- literal `%INCLUDE` paths
- `LIBNAME` librefs
- macro definitions
- macro invocations
- macro variable references
- unresolved macro-driven dataset references

Literal dataset and file relationships are normalized into workload datasets and
`reads`, `writes`, and `includes` relationships. Every generated relationship
carries `static_analysis` evidence with a source file and line number.

Literal `%INCLUDE` references are reconciled after filesystem inventory. When an
include path maps unambiguously to an inventoried artifact, the `includes` edge
targets that real artifact and the temporary placeholder is removed. Missing or
ambiguous include paths remain explicit placeholders rather than being guessed.

## Dynamic SAS behavior

Macro-generated references are not guessed. For example:

    create table &output as
    select * from &input;

SMF records `&output` and `&input` as unresolved dynamic dataset references.
Later discovery increments can resolve them from invocation parameters, runtime
metadata, or other deterministic context. If they remain unresolved, they stay
as discovery gaps.

This distinction is important. The canonical graph must separate observed facts
from inferred or runtime-resolved relationships.

## Corpus use

WLD-03 is tested against both SMF-authored semantic fixtures and curated public
SAS source artifacts. The public SAS/ACCESS examples provide genuine SAS source
syntax, while the semantic fixtures give SMF focused assertions for constructs
such as `MERGE`, `BY`, macros, and PROC SQL lineage.

These tests validate reference discovery. They do not claim that the workloads
have been converted, executed in SAS, executed in Databricks, or behaviorally
certified.

## Known limits

This is intentionally not a full SAS parser. The first pass does not resolve:

- macro expansion and conditional macro execution
- dataset names assembled from multiple macro variables or functions
- dynamic SQL generated at runtime
- SAS metadata or scheduler dependencies
- runtime library resolution and credentials
- business workload boundaries
- downstream consumers outside the scanned source

Those concerns remain separate discovery-provider and graph-enrichment
capabilities.
