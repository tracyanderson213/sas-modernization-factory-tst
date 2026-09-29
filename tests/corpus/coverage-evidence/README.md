# Coverage proof evidence registry

This directory stores explicit repository-safe proof claims above `observed` maturity.

Do not infer entries from test counts, filenames, successful commands, or lower maturity states.
Each YAML record must identify one dimension/capability/maturity claim and a local
`evidence_ref` plus `result_digest` for a canonical corpus regression result. The loader verifies
the result's scenario, source, digest, and maturity-specific telemetry; labels or booleans cannot
upgrade coverage. `observed` evidence remains manifest-derived and is not accepted here.

Private-client bytes or client-identifying evidence must not be placed here. Shared proof learned
from private evidence must first cross the CORPUS-09 independent reproduction/sanitization
boundary.
