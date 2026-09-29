# Intermediate Representation

## Purpose

The IR provides a normalized representation of source SAS behavior between parsing and target emission.

## Goals

- preserve source lineage
- represent data dependencies
- represent transformations
- represent procedural behavior
- represent macros and parameterization where feasible
- carry unsupported/ambiguous nodes explicitly
- support multiple target emitters
- enable validation planning

## Versioning

Every IR document should declare an IR version. Breaking changes require migration or compatibility handling.

## Non-Goal

The IR is not intended to perfectly reproduce the entire SAS language in the first release. Unsupported behavior should be explicit rather than silently approximated.
