# Enterprise secret provider and workload identity

SMF exposes a provider-neutral, offline security boundary in `smf.security`. The Humana adapter
selection is Microsoft Entra workload identity plus HashiCorp Vault, but vendor targets remain in a
separately supplied protected binding document. Portable requests carry opaque binding IDs only.

The implementation has no network transport and installs no provider SDK. Callers inject transports.
Before either transport is called, the adapter verifies a replay-valid readiness-derived request,
the exact policy and protected-configuration digests, active binding state, and an Ed25519 activation
record bound to client, deployment, environment, workload, subject/source, run, attempt, consumer,
policy, configuration, identity binding, secret binding, and authorization purpose.

`resolve_configured` is the fail-closed configuration admission boundary. Absent or invalid policy
or binding files produce a schema-valid typed non-success receipt and zero transport calls. Pending,
denied, expired, malformed, or mismatched activation evidence likewise produces a non-success result
before transport. Successful material is available only through `TransientMaterial` within the
provider context manager; token and secret buffers are cleared on every exit. Receipts and telemetry
contain safe bindings and lease metadata but never endpoint, tenant, issuer, audience, namespace,
role, path, token, secret, provider diagnostics, or hashes of credential values.

Receipt persistence is append-only under the isolated run/workload/attempt hierarchy. An identical
receipt is canonical; conflicts are rejected. Missing telemetry can be rebuilt from the receipt
without reacquiring a credential.

An optional protected `previous_version` records an expected version transition. Resolution still
accepts only the configured current `version`; the prior version fails closed as a binding mismatch.
`rotation_observed` is true only when this transition is configured and the current version is
returned. This is offline contract evidence, not proof that a live Vault rotation occurred.

Live activation remains blocked until authorized owners provide the exact Entra-to-Vault flow,
protected bindings, TLS/network policy, lease and rotation rules, evidence authority, retention,
real transports, and real-environment approval.
