# Multi-artifact workload fixtures

CORPUS-03 extends the regression corpus from artifact collections to an explicit workload-level fixture contract.

A corpus manifest may now declare a `workload` with a scenario root, one or more entrypoints, and explicit relationships among artifacts already declared by the manifest. Relationship references are validated against the manifest so a workload fixture cannot silently depend on an undeclared file.

The framework is intentionally evidence-oriented. It records fixture structure; it does not claim that `%include` relationships have been dynamically resolved by SAS, that macro behavior is semantically equivalent on a target platform, or that expected source/target outputs exist.

The initial representative scenario contains a SAS entrypoint, include, macro library, and configuration artifact. Synthetic input datasets, authoritative expected outputs, scheduler fixtures, and broader representative scenarios belong to CORPUS-04 through CORPUS-07.
