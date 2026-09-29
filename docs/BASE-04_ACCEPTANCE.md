# BASE-04 canonical cross-provider descriptor

BASE-04 establishes one versioned physical descriptor shared by the qualified BASE-08 local
reader and SCALE-01 distributed reader. The authoritative confidence gate executes both providers
against the same Apache-2.0 licensed SAS7BDAT snapshot: `ag121a_supp_sample.sas7bdat` at upstream
revision `dad0840bd89b7581c35a41ce372c61dc42d15eab`, SHA-256
`bc7867bb33bbf238b7085a370f59e9a91a76ff1f61f6df7c74e3b66d47f5b277`.

The descriptor retains the local provider's declared labels, formats, informats and storage widths;
binds the local and distributed provider evidence identities; and compares column identity/order,
physical types, row count, per-column null counts and the complete normalized row multiset through
the same duplicate-sensitive XOR-plus-modulo-sum SHA-256 projection used by SCALE-01. Local rows
remain transient and are never persisted. Its small physical vocabulary normalization
(`str` to `string`, `float` to `double`, `int` to `long`, and `bool` to `boolean`) reconciles provider
names only. It is not a governed SAS-to-target semantic conversion rule.

Snapshot policy binds acquisition time, evaluation time, expiration, public-fixture data scope and
immutable-evidence retention. Future-dated or expired fixtures, differing source identities,
including an expiration exactly equal to evaluation time, provider conflicts, differing row values
despite equal counts/nulls, current-input drift and evidence mutation fail closed. Publication is
request-bound, no-replace and replayed from current source, provider, oracle, JAR, license and build
receipt inputs. Cancellation cannot publish a canonical result, and workload/run paths are isolated.

Run the authoritative gate with:

```bash
make base04-confidence
```

The gate builds the exact SCALE-01 provider artifact in an isolated temporary directory and uses
the existing pinned pyreadstat runtime. There are no runtime downloads in the SMF module. Final
offline intake remains PKG-QUAL-01 scope.

## Acceptance matrix

| Criterion | Executed evidence |
|---|---|
| BASE-04-AC01 | The real-provider test produces one shared eight-column descriptor from BASE-08 and SCALE-01 and requires exact schema, count, null and duplicate-sensitive row-multiset agreement. |
| BASE-04-AC02 | The immutable result binds source identity, acquisition/evaluation/expiration, data scope, retention, provider result/config/runtime identities and descriptor digest. |
| BASE-04-AC03 | Expired/future snapshots and mismatched source identities fail before comparison; evidence mutation fails replay; the fixture is identified as licensed public data, never customer data. |
| BASE-04-AC04 | The result binds workload/run/attempt and exact provider evidence, preserves conflicts, proves cancellation without canonical publication and isolates two workloads. Customer quota, tolerance and owner decisions remain absent and unclaimed. |
| HC-01 | Identity, policy, source, provider and descriptor bindings are explicit; every prohibited lifecycle claim is false. |
| HC-02 | Exact upstream revisions, runtime contracts, fixture/license digests and selection roles are recorded in `config/dependencies/base04-descriptor.json`; there is no memory/recall dependency. |
| HC-03 | BASE-08 metadata, SCALE-01 observations and the canonical projection remain separate. VS-01's provisional mapping is an integration input, not SAS authority. |
| HC-04 | Existing provider identity and metadata admission rejects protected/secret-like values; durable BASE-04 evidence contains metadata and digests, not rows. |
| HC-05 | Positive real execution, conflict, expiry, identity mismatch, cancellation, mutation, replay and isolation tests fail closed where required. |

## Bounded disposition

BASE-04 qualifies the canonical cross-provider physical descriptor contract for the selected public
fixture. BASE-02 still owns governed production type and semantic mapping. This result does not
establish arbitrary SAS coverage, Humana or SAS parity, business keys/tolerances, Databricks or
Unity Catalog validation, customer readiness, production readiness, or migration completion.
