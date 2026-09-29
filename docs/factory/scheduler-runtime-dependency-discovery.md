# Scheduler and Runtime Dependency Discovery

WLD-06 adds deterministic execution-context relationships to the canonical workload graph. It uses scheduler configuration and launch wrappers present in the acquired source tree. This complements code-reference discovery, endpoint characterization, and data lineage.

## Current flow

```text
AutoSys JIL ---------+
                     |
cron ----------------+----> Scheduler Job ----TRIGGERS----+
                     |                                     |
shell wrapper -------+-------------------------TRIGGERS----+
                                                           v
                                                    SAS Program A
                                                           |
                                                      WRITES/READS
                                                           |
                                                           v
                                                    SAS Program B
```

## Current foundation

The filesystem provider recognizes:

- shell wrappers (`.sh`, `.bash`, `.ksh`) that launch SAS with `sas -sysin` or invoke other wrappers;
- AutoSys JIL job definitions, commands, conditions, machines, start times, and days of week;
- cron sources (`.cron`, `crontab`, `cron.tab`) with five-field schedules and executable commands.

Scheduler jobs become canonical `scheduler_job` artifacts. Relationships include `TRIGGERS`, `DEPENDS_ON`, and corresponding `PRECEDES` ordering edges.

Scheduler-derived evidence is labeled `scheduler_metadata`. Shell-wrapper launch evidence is `static_analysis` because the command is observed in source, not execution history.

Commands and nested metadata cross the canonical secret-sanitization boundary before
durable evidence is created. Passwords, secret environment assignments, tokens,
authorization values, connection credentials, and URI passwords become `<redacted>`;
launch targets, conditions, machines, and schedules remain available for resolution.

## Conservative resolution

```text
Known logical path --------------------> link
Unique filename -----------------------> link
Dynamic ${VAR}/macro target -----------> unresolved
Ambiguous filename --------------------> unresolved
External AutoSys dependency -----------> referenced_only scheduler artifact
```

SMF does not invent a target when evidence is insufficient.

## Scope boundary

This foundation does **not** claim full runtime history discovery. It does not yet ingest SAS Management Console scheduling metadata, SAS Job Flow Scheduler exports, Platform Process Manager history, Control-M metadata, enterprise scheduler APIs, OS process history, or SAS execution logs. Those belong in provider-specific adapters and should use `runtime_metadata` or `scheduler_metadata` only when actually observed.

The discovery confidence harness exercises this foundation with controlled, adversarial, and public-source inputs. See `docs/factory/discovery-confidence-testing.md`.
