# Synthetic Data Corpus Fixtures

CORPUS-04 adds deterministic synthetic input datasets to workload-level corpus scenarios.

Each fixture has a stable fixture ID, an explicit logical dataset binding, a declared artifact, a portable data format, and artifact fingerprinting. Fixture artifacts must be declared with the `input-data` role. Synthetic fixtures are rejected if they claim to contain private data.

The representative multi-artifact scenario now carries two small SMF-owned CSV inputs. The manifest declares the workload's read relationships to those inputs so later baseline and parity stages can consume the same controlled evidence.

This stage does not create authoritative SAS baseline outputs, target outputs, or semantic-equivalence claims. Those remain later corpus, baseline, and validation responsibilities.
