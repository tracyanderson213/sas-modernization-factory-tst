# SAS library binding contract

BASE-06 establishes an offline, fail-closed contract for turning observable SAS
`LIBNAME` statements into source-located logical bindings. It does not connect
to SAS, resolve customer credentials, inspect Humana storage, or establish that
a referenced library exists.

## Trust boundary

Source text is untrusted evidence. The resolver accepts qualified source bytes
and records the exact artifact checksum, byte span, line, column, statement
digest, policy version, run, and attempt for every occurrence. Commented text
and `LIBNAME` tokens embedded in quoted strings are excluded lexically.

Only these static forms can be classified as literal:

- `libname REF '/literal/path';`
- `libname REF base '/literal/path';`
- `libname REF ('/literal/one' "/literal/two");`

Literal classification is not authorization and does not assert filesystem
existence. Macro triggers, expressions, environment-dependent forms, database
engines, unsupported syntax, and missing macro values remain unresolved.
Reassignment is preserved as ordered history: more than one active assignment
for a libref is ambiguous unless governed runtime evidence selects an observed
occurrence. `LIBNAME REF CLEAR` terminates the static binding and never revives
an earlier assignment.

## Runtime evidence

Runtime evidence is optional, immutable input from a separately authorized SAS
observation provider. It must bind the client, workload, source-closure digest,
policy digest, run, attempt, libref, selected source occurrence, observed paths,
provider, exact provider revision, observation time, trusted authority, key,
evidence digest, and Ed25519 signature. The resolver verifies the signature
against an offline policy trust anchor and deterministically rejects duplicate,
stale, future, malformed, cross-workload, superseded-occurrence, cleared, or
policy-mismatched evidence. A caller-computable digest is integrity metadata,
not authority. Caller-authored `resolved`, `authorized`, `exists`, credential,
or readiness assertions have no authority.

The output separates `literal`, `runtime_observed`, `dynamic`, `ambiguous`,
`cleared`, and `unresolved` states. A binding is authoritative only when there
is one supported literal assignment or matching governed runtime evidence.
Every other state carries explicit blockers and prohibited claims.

## Evidence and claims

Results are deterministic JSON-compatible values with stable identities and a
projection suitable for downstream gates. They may claim only that offline
binding analysis was generated. They always deny execution, connectivity,
credential inference, path authorization, customer readiness, validation,
parity, certification, and human approval. Downstream physical-asset work must
consume the occurrence and policy bindings rather than infer authority from a
path string.

Publication requires the authoritative request, recomputes the complete result,
validates every nested object against the closed schema, recomputes the result
identity and projection, and screens all persisted fields for protected data
before the first immutable write. Replay performs the same checks.
