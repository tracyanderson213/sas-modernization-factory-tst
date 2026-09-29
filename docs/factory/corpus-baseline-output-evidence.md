# Corpus Baseline and Output Evidence

CORPUS-05 adds an explicit evidence contract for expected and baseline outputs. An artifact with role `expected-output` is only a file classification; it does not establish where the output came from or how much authority it carries.

Each `output_evidence` record binds a logical output to a declared artifact and preserves its evidence origin, producer, SHA-256 content hash, determinism, authority, and optional source execution identity. Supported origins are `sas-executed-baseline`, `declared-synthetic-expectation`, and `public-reference-artifact`.

A `sas-executed-baseline` must carry `source_execution_id`. The loader does not infer that an expected file came from SAS. Public reference artifacts likewise do not become authoritative merely because they are distributed by an upstream source. Authority is explicit and remains available to future validation and certification stages.

The CORPUS-05 fixture is intentionally a declared synthetic expectation. It proves the evidence contract without falsely representing an SMF-authored CSV as captured SAS execution. Trusted SAS baseline acquisition remains a later BASE capability.
