# SAS Support Matrix

This matrix begins as an engineering planning artifact and should be updated from tests and migration telemetry.

| SAS Capability | Initial Strategy | Validation Need | Status |
|---|---|---|---|
| PROC SQL SELECT | Deterministic | Structural + data | Planned |
| PROC SQL JOIN | Deterministic | Structural + data | Planned |
| GROUP BY / aggregates | Deterministic | Aggregate parity | Planned |
| Basic DATA step filters | Deterministic | Row/data parity | Planned |
| Basic assignments | Deterministic | Data parity | Planned |
| Macro discovery/static dependency resolution | Versioned byte-bound evidence; no expansion | Source and resolution reconstruction | Implemented foundation |
| Macro variables | Observed; symbol-table semantics unresolved | Source execution + semantic parity | Human review |
| Macro code generation | Explicitly unsupported by static strategy | Source execution + enhanced parity | Human review |
| Formats | Deterministic mapping where supported | Data/semantic | Planned |
| PROC MEANS/SUMMARY | Deterministic | Aggregate parity | Planned |
| PROC FREQ | Deterministic | Aggregate parity | Planned |
| Statistical procedures | Case-specific | Semantic | Planned |
| Predictive models | Human-supervised initially | Semantic/model | Planned |

Do not represent "planned" as validated support. Support should move to validated only when covered by regression tests.
