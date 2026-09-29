# BASE-08 qualified local SAS binary reader acceptance

## Boundary

BASE-08 wraps the `pyreadstat 1.3.6` release sourced at tag commit
`ae4bfa5d84ed1ceaf847ab242118da730a4084ec`. Qualification evaluated upstream through
`12cc1495d468ae8a170c57cce7557c147b972eac` (two later changelog-only commits). The release embeds ReadStat revision
`5850fb57dfc0301f62c745c547763610e5a6c347`. It does not contain a SAS parser.
The provider is bounded local/eager execution; distributed and large-file qualification remains
SCALE-01 scope.

The provider opens an authorized relative `.sas7bdat` through descriptor-relative, no-follow,
regular-file checks. It verifies byte identity before and after the read, stages those exact bytes
in a private mode-0700 ephemeral directory because the native provider requires a pathname, and
verifies the staging copy before and after provider execution. Requests bind client, workload,
source, run, attempt, exact source digest/size, configuration, installed distribution RECORD digest,
Python, platform, and
provider authority. Only the exact imported installed `pyreadstat` module can authorize a complete
or publishable result; injected test doubles are explicitly synthetic and fail closed even when
they claim version 1.3.6.

Rows are transient and returned in deterministic chunks. Durable evidence contains descriptor and
chunk digests, not source row values. Temporal values remain their underlying SAS numerics through
`disable_datetime_conversion=True`; format and informat metadata stay explicit. BASE-02 owns the
later governed semantic mapping. No inferred key is produced.

## Dependency and artifact design

The `conversion` extra pins `pyreadstat==1.3.6`, `narwhals==2.26.0`, and the latest compatible
NumPy patch (`2.4.6` on Python 3.11; `2.5.3` on Python 3.12); it does
not pull the broad `ai` extra or any direct model-provider SDK. The runtime evidence binds every
installed distribution's version and RECORD digest. A deployment must select a platform-specific approved wheel and its full
transitive closure through PKG-DES-01/LIC-01/PKG-QUAL-01. Known evaluated pyreadstat wheel hashes are:

| Runtime | SHA-256 |
|---|---|
| CPython 3.11 manylinux x86_64 | `db275cc6a96b259a6369cd8b2d8ad159cf6c81b296c1a8205bb23e51686b0f24` |
| CPython 3.12 manylinux x86_64 | `93182fc101e2adf27c36fb935e8144e5bc92a3da8d7577a1dabfcacf29b672e8` |
| CPython 3.12 macOS 11 ARM64 | `6949c7535dc57115f3d5620b3f381ca76589f0fb079c20c26b7cbcdd5fca54db` |

The ordinary development suite reports this optional provider module as skipped when the
`conversion` extra is absent. The authoritative fixture gate never skips: `make
base08-confidence` requires `pyreadstat==1.3.6` and fails before test execution if it is
unavailable. CI installs `.[dev,conversion]` and runs that exact target on Python 3.11 and 3.12.
This keeps the core installation optional without representing a missing provider as qualified.

`config/dependencies/sas-reader-runtime.json` records these observations and leaves the two
transitive offline-artifact hashes explicitly pending PKG-QUAL-01. These hashes are artifact
observations, not license/security/runtime approval. A source-only profile
may run only when the exact native dependency is already approved and present; otherwise preflight
must name the required offline wheel. No runtime download is permitted by this contract.

## Acceptance matrix

| Criterion | Evidence | Disposition |
|---|---|---|
| BASE-08-AC01 | Actual compressed SAS7BDAT read proves names, formats, informats, widths, encoding, row/column counts, nullability observations, absent keys/units | Bounded provider mechanics complete; business keys/units remain undeclared and are never inferred |
| BASE-08-AC02 | Request, source snapshot, provider/runtime/config and immutable result/chunk digests; mutation replay tests | Complete for the public fixture |
| BASE-08-AC03 | Declared and observed fields are separate; conflicts fail closed; `declared_keys=[]` and `key_authority=unavailable_not_inferred` | Complete |
| BASE-08-AC04 / HC-01 | Run/workload/source/attempt bindings and exact provider/source identities | Complete for bounded local read only |
| HC-02 | Exact upstream revision, distribution fingerprint, fixture revision/license/provenance | Complete; no recall dependency |
| HC-03 | Raw temporal numerics retained; no conversion, Delta, validation or parity claim | Complete |
| HC-04 | No-follow root confinement, safe durable metadata, row values excluded from evidence, canary tests | Complete for the bounded contract |
| HC-05 | Real-fixture, corrupt, encoding, encrypted-provider, symlink, mutation, retry and cross-workload tests | Complete for bounded provider mechanics |

## Stop rules and prohibited claims

Missing provider/version, distribution mismatch, changed source, symlink/non-regular/traversal,
corruption, encryption/password protection, unsupported encoding/value types, protected durable
metadata, and configured local size/row bounds all fail closed. No fallback parser is attempted.

BASE-08 does not establish arbitrary SAS coverage, large-file/distributed behavior, SAS semantic
parity, Humana validation, Spark/Delta/Unity Catalog success, migration completion, production
readiness, or authorization to use a customer filesystem.
