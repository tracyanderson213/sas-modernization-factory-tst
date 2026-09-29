# SMF Modernization Test Corpus

The corpus is a regression asset for discovery, modernization planning, conversion,
validation, remediation, and certification. It is not a folder of anonymous sample SAS.
Every scenario must have explicit provenance, licensing, capability tags, and artifact
fingerprints.

Regression-capable scenarios additionally declare a unique non-empty SAS subject, its complete
in-workload source closure, target, stages, and validation policy. Admission snapshots verified bytes
into an isolated run/workload/attempt namespace. Its evidence is test-only or shared regression
evidence and must never be relabeled as private-client or Humana proof.

## Structure

- `sources.yaml` is the approved-source registry.
- `manifests/` contains one manifest per regression scenario.
- `workloads/` contains vendored or SMF-authored scenario artifacts.
- Public artifacts must retain their upstream attribution and license obligations.
- Private client artifacts must never be mixed with the public corpus.

## Corpus tiers

1. `bootstrap`: small SMF-owned fixtures that prove corpus plumbing.
2. `semantic`: focused SAS language behavior with authoritative expected behavior.
3. `representative`: public-first, independently authored multi-artifact workloads; synthetic representative scenarios are used only where public evidence cannot supply a required controlled case.
4. `healthcare`: healthcare-shaped scenarios, beginning with CMS synthetic claims assets.
5. `private-client`: isolated client fixtures that are never committed to the public corpus.

## Import policy

Public realism scenarios should use curated workload slices rather than indiscriminate repository copies. Record the upstream source, immutable upstream reference, license, acquisition date, modification status, and SHA-256. Artifacts classified as untouched public evidence must not be edited to make SMF pass. If an artifact is changed, treat the modified version as an SMF-derived fixture, preserve attribution, and do not represent it as untouched public evidence.

See `docs/factory/modernization-test-corpus.md` for the governing evidence architecture, public-first portfolio strategy, regression-promotion rules, and coverage model.

CMS public-use assets require review of the applicable CMS Data Disclaimer / User Agreement
before data or code is vendored into the repository. Until that review is complete, the CMS
source remains approved for acquisition but not automatically copied into the repo.
