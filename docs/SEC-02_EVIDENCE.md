# SEC-02 Acceptance Evidence

Status: offline implementation evidence for human review. This is not live Humana qualification,
submission authority, deployment approval, or a completion/merge attestation. The immutable commit
reference is assigned only by human-controlled final integration.

Source/configuration revision: current SEC-02 isolated working tree; governed Humana AI binding
remains pending in `deployments/humana/security-policy.yaml`.

## Acceptance matrix

| Criterion | Test or review artifact | Expected and actual result | Safe evidence reference |
|---|---|---|---|
| SEC-02-AC01 | Positive qualification plus missing/forged/replayed evidence, source mutation, empty/non-SAS and closure tests | Context assembles only after exact readiness, policy, signed classification and byte checks; focused suite passes | `tests/unit/test_ai_context_admission.py` |
| SEC-02-AC02 | Policy allowlist/model/endpoint binding tests and strict schemas | Only configured provider/model/endpoint, fields and artifact kinds are eligible; malformed/unknown values fail closed; focused suite passes | `tests/unit/test_ai_context_policy.py`; packaged `ai-*.schema.json` |
| SEC-02-AC03 | Plain, URL-encoded and base64 secret/SSN/email/DOB/MRN canaries, identity-field canaries, immutable qualified bytes, and categorical provider diagnostics | Canary-bearing input blocks before hashing or assembly, values are absent from result evidence, and caller mutation is impossible; focused suite passes | `tests/unit/test_ai_context_admission.py` |
| SEC-02-AC04 | Signed append-only retry recovery, forged durable qualification, conflicting retry, false-success mutation and workload-path isolation | Canonical results require a trusted Ed25519 evidence proof; missing telemetry recovers, while unsigned/self-authored, conflicting, and inflated claims fail; focused suite passes | `tests/unit/test_ai_context_manifest.py` |
| HC-01 | Request, classification and result binding inventories | Evidence binds client through decision identity plus readiness, source-closure, policy/provider/model and artifact digests; focused suite passes | `src/smf/security/ai_models.py`; `src/smf/security/ai_admission.py` |
| HC-02 | No recall input/store exists in the contract | Not applicable to this bounded non-consuming increment; durable recall remains excluded and cannot affect qualification | `docs/PHI_PII_AI_GUARDRAILS.md` |
| HC-03 | Complete canonical closure replay plus terminated SAS step/macro/include recognition | Prose and malformed DATA/PROC tokens cannot qualify; source remains distinct from context/result evidence and no generated target or parity claim exists; focused suite passes | `tests/unit/test_ai_context_admission.py` |
| HC-04 | Canary, traversal, unsafe metadata, signature, authority and categorical-error tests | Protected/secret/unsafe input is rejected before durable hashing or context assembly; focused suite passes | `tests/unit/test_ai_context_admission.py`; `tests/integration/test_ai_context_guardrails.py` |
| HC-05 | Lifecycle-claim schema mutation, pending-versus-denied, missing evidence, retry and no-network tests | Blocked/denied states remain visible; all downstream claims remain false; focused suite passes | `tests/unit/test_ai_context_manifest.py`; `tests/integration/test_ai_context_guardrails.py` |

## Reproduction commands

Focused contract and inherited security regressions:

```bash
python -m pytest -q -p no:cacheprovider \
  tests/unit/test_ai_context_policy.py \
  tests/unit/test_ai_context_admission.py \
  tests/unit/test_ai_context_manifest.py \
  tests/integration/test_ai_context_guardrails.py \
  tests/unit/test_sec01_threat_model.py \
  tests/unit/test_discovery_sanitization.py
```

Static checks and repository gates:

```bash
python -m ruff check src/smf/security tests/unit tests/integration
python -m ruff format --check src/smf/security tests/unit tests/integration
python -m mypy --strict src/smf/security
./scripts/test-discovery-confidence.sh
python scripts/corpus/verify-public-portfolio.py
make verify
```

Actual final-gate results are recorded in the developer handoff for this isolated worktree; they do
not convert offline synthetic proof into a live-environment claim.
