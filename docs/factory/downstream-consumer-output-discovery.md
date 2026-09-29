# Downstream Consumer and Output Discovery

## Purpose

WLD-08 makes produced data a first-class part of the canonical workload model. It answers two separate questions without conflating them:

1. What outputs does this discovered estate produce?
2. Which downstream consumers have actually been observed so far?

A missing observed consumer is **not** evidence that an output has no consumer.

## Canonical output model

```text
Producer Artifact
      |
      | PRODUCES
      v
Canonical Dataset/File ---------> Canonical Output Record
      |                                  |
      | CONSUMED_BY                      +-- producer_ids
      v                                  +-- consumer_ids
Observed Artifact Consumer               +-- consumer_resolution
                                         +-- evidence
                                         +-- consumer_scope
```

The output record references the existing canonical dataset rather than copying it. This keeps dataset identity, location, endpoint characterization, and lineage in one place.

## Consumer resolution

```text
UNRESOLVED
No downstream consumer has been observed in available evidence.
This does not mean "no consumer exists."

PARTIAL
One or more consumers were observed inside the discovered estate.
Additional external consumers may still exist.

CONFIRMED
Reserved for future evidence that can establish a confirmed consumer set.
The current static/filesystem foundation does not assign this state.
```

## Current deterministic foundation

WLD-08 derives outputs from canonical `PRODUCES` relationships created by WLD-05. Existing `CONSUMED_BY` relationships identify consumers observable inside the acquired estate. Files written through literal SAS `FILE` statements are therefore represented as outputs even when their downstream consumer is unknown.

```text
publish_claims.sas
      |
      | WRITES / PRODUCES
      v
output/claims_report.csv
      |
      +--> consumer_resolution = unresolved
```

This is intentionally different from asserting that the report file is unused.

## Future enrichment

Future providers can add downstream evidence from SAS metadata, scheduler/runtime history, database catalogs, BI metadata, file-transfer systems, APIs, application inventories, and targeted human confirmation. Those providers should enrich the same canonical output/consumer representation rather than create parallel consumer models.

## Boundaries

The current foundation does not discover Power BI reports, external applications, SFTP recipients, human recipients, or other enterprise consumers unless evidence for those consumers is already represented in the discovered workload graph. It does not infer consumers from naming similarity or AI guesses.
