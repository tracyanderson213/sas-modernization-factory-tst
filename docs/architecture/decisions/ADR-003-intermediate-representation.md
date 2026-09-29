# ADR-003: Intermediate Representation

## Status
Accepted

## Context
Direct SAS-to-PySpark text conversion makes transformation behavior difficult to test, reason about, and extend.

## Decision
Normalize SAS constructs into a versioned intermediate representation before target artifact emission wherever practical.

## Consequences
Parsers and emitters can evolve independently. IR compatibility becomes a versioned contract and requires regression testing.
