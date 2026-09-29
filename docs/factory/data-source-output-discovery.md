# Data Source and Output Discovery

WLD-04 characterizes literal data endpoints found during SAS static discovery. It builds on WLD-03 rather than creating a second discovery graph.

## Current capability

For each literal SAS dataset reference, SMF now distinguishes:

- temporary WORK or unqualified intermediate datasets;
- SAS datasets backed by a literal filesystem `LIBNAME`;
- external database tables backed by recognizable SAS/ACCESS engines such as ODBC, Oracle, PostgreSQL, Teradata, Snowflake, and SQL Server;
- unresolved librefs where the source proves a reference exists but does not prove its physical binding;
- literal input and output files already discovered through `INFILE` and `FILE`.

Discovered connection options are evidence, not credentials. Credential-like options
are redacted by the canonical recursive boundary before they enter the workload,
including URI userinfo and nested connection strings. Safe endpoint identity remains.

## Resolution semantics

`resolved` means source text provides enough deterministic evidence to characterize the endpoint. `partial` means the technology or connection binding is visible but the factory has not contacted the external system. `unresolved` means a logical reference exists without a discovered binding.

SMF does not test connectivity, expand macros, query database catalogs, or infer missing LIBNAME definitions in WLD-04. Those capabilities belong to connection-resolution and runtime/data-system providers.

## Relationship to later backlog

WLD-04 identifies and characterizes endpoints. WLD-05 can use those endpoints plus WLD-03 read/write edges to construct producer/consumer data lineage. BASE-05, BASE-06, and BASE-07 can later resolve connections, libraries, and external feeds against runtime or environment evidence.
