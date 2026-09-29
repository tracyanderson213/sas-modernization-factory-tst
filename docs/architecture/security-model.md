# Security Model

## Trust Boundary

The factory is intended to run inside the enterprise-approved boundary.

## Identity

- Prefer managed identities and workload identities.
- Avoid static secrets where supported.
- Use least privilege.
- Separate development, validation, and production permissions.

Identity and secret access are provider-neutral core contracts selected by deployment
configuration. Humana's confirmed ecosystem uses Microsoft Entra ID / Active Directory
and HashiCorp Vault. The exact Entra-to-Vault authentication flow, Vault deployment,
namespace/role/path scope, leases, rotation and approval authority remain pending and
must fail closed until configured. Secret and token values, and their hashes, must not
enter durable evidence, logs, exceptions, model context or source control.

## AI

- Use only approved enterprise model endpoints.
- Avoid transmitting protected data unless explicitly approved and necessary.
- Log model, version, invocation purpose, and transformation provenance.
- Do not rely on model self-assessment as a security or correctness control.

Humana's confirmed allowed LLM provider is Anthropic. This is a deployment binding
behind the common AI provider contract, not a vendor dependency in portable factory
logic. Azure OpenAI remains an optional adapter for deployments that separately approve
it. Missing endpoint, model, data-handling or credential bindings block live invocation.

## Artifacts

Source SAS, IR, generated code, logs, validation results, and provenance records should be classified and protected according to enterprise policy.

Discovery evidence is recursively sanitized when a canonical `Workload` is
constructed. Raw credential values must not survive in workload JSON or derived
lineage, topology, scheduler, runtime, connection, or planning evidence. Source
checksums remain byte-identity proofs, while evidence identifiers are generated from
sanitized fields. Sanitization changes only copied in-memory canonical values and
does not alter acquired public corpus or private-client source bytes. Canonical
serialization repeats this same sanitization rule so post-construction mutation of a
nested metadata container cannot put raw credentials into durable output.

## Promotion

Production deployment requires explicit authorization and should not be performed by an autonomous remediation agent.
