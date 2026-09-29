# External Dependency and Connection Inventory

## Purpose

WLD-07 inventories external prerequisites that a discovered workload depends on. It answers a different question from WLD-04:

```text
WLD-04: What data endpoint is referenced?
                   |
                   v
          wh.claims / mart.out
                   |
                   v
WLD-07: What must exist outside this workload for that reference to work?
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
   DB connection  Filesystem  Runtime prerequisite
   ODBC / DSN     /sas/mart   env var / executable
```

## Canonical model

External prerequisites are first-class workload entities rather than loose strings in artifact metadata.

```text
SAS Program ----------------DEPENDS_ON--------------> libref:wh
                                                        |
                                                        +-- kind: database_connection
                                                        +-- engine: odbc
                                                        +-- dsn: EDW
                                                        +-- schema: CLAIMS
                                                        +-- password: <redacted>

Shell Wrapper --------------DEPENDS_ON--------------> curl
     |
     +-----------------------DEPENDS_ON--------------> CONTROL_API
                                                       environment variable
```

Each dependency has stable identity, evidence, confidence, system/location information where observable, and metadata. Relationships connect the originating artifact to the dependency.

## Current deterministic coverage

The foundation currently inventories:

- literal SAS `LIBNAME` database connections;
- literal filesystem-backed SAS libraries;
- referenced librefs that have no observable binding, retained as unresolved connections;
- SAS `%sysget(NAME)` environment requirements;
- shell environment-variable references that are not assigned locally;
- external shell executables while excluding common shell built-ins and the SAS launcher itself.

## Credential handling

Credentials are evidence boundaries, not inventory values.

```text
Source
  password='secret'
        |
        v
Discovery
        |
        +----> password = <redacted>
        |
        +----> secret value MUST NOT enter workload JSON
```

Connection options such as DSN, server, database, schema, and user may be retained when literal because they help identify the dependency. Credential-like values remain redacted.
The same canonical rule covers nested provider metadata, prefixed secret environment
variables, tokens and API keys, authorization values, connection strings, and URI
passwords. `<redacted>` means material was observed but deliberately withheld.

## Resolution semantics

```text
Observable literal binding --------> resolved / partial dependency
Referenced unknown libref ---------> unresolved dependency
Dynamic runtime value -------------> unresolved requirement
No evidence -----------------------> no invented dependency
```

SMF does not connect to databases, test credentials, query catalogs, resolve secrets, or infer unknown hosts during WLD-07 discovery.

## Deliberate boundaries

This foundation is not yet enterprise connection validation. Later work can enrich these same dependency identities with approved SAS runtime metadata, database/catalog inspection, secret references, network reachability, authentication policy, or enterprise configuration APIs.
