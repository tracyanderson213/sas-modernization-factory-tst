# SASSEM-04 Acceptance Evidence

## Scope and claim boundary

This increment implements deterministic, source-located classification for SAS formats,
informats, functions, `PROC FORMAT`, `%sysfunc`, custom catalogs, and FCMP. It generates no target
code. The executable mapping allowlist is empty. The checked-in policy records SAS runtime/version,
session options, locale, timezone, `YEARCUTOFF`, oracle authority, business tolerances, and Humana
owner decisions as pending external inputs.

Consequently, this increment makes no execution, equivalence, parity, validation, certification,
lifecycle-completion, or Humana-readiness claim. Authoritative SAS results and business approval
remain blocked external evidence.

## Acceptance matrix

| Criterion | Procedure | Expected and actual result | Immutable/reconstructable reference | Residual boundary |
|---|---|---|---|---|
| SASSEM-04-AC01 | `pytest -q tests/unit/test_sas_format_function_semantics.py` | FORMAT/INFORMAT, functions, `%sysfunc`, `PROC FORMAT`, and FCMP are separate occurrence kinds; passed locally | Exact byte spans, token SHA-256, source snapshot identity, strategy and policy in `sas-semantics.evidence.json` | Macro expansion and target templating are not performed |
| SASSEM-04-AC02 | Focused policy, location, replay, and schema tests | Strict versioned policy and byte-located occurrences; replay reclassifies exact bytes; passed locally | Public and packaged policy/evidence schemas plus example policy | Supported ranges/defaults and expected runtime outputs remain pending authoritative SAS evidence |
| SASSEM-04-AC03 | Unknown-label, custom-catalog, ambiguity, malformed enum, and caller-attestation tests | Unknown/unqualified mappings are blocked; custom/FCMP/ranged/default definitions are unsupported; passed locally | Occurrence reason codes and false success claims in immutable evidence | No label or function is treated as an executable equivalent |
| SASSEM-04-AC04 | Mutation, publication collision, retry/recovery, and two-workload tests | Source mutation and conflicting attempt reuse fail; canonical evidence survives; derived telemetry recovers idempotently; passed locally | Workload/run/attempt directory and evidence digest | No selected Humana workload, runtime, baseline, tolerance, or owner disposition was supplied |
| HC-01 | Exact identity/digest replay test | Evidence binds client, workload, subject, artifact, source snapshot/digest, policy, strategy, run, attempt, decision, and evidence identities; passed locally | `verify_classification_evidence` recomputation | This evidence is classification-only and non-authorizing |
| HC-02 | Policy/replay review | No recall or durable learned advice is consumed; passed as non-consuming behavior | Package-owned policy and deterministic source scan | Estate learning is outside this item |
| HC-03 | Separation and false-positive tests | Underlying values remain separate from formatted projections; comments/strings do not become semantics; passed locally | Occurrence flags and classification tests | No SAS oracle or target template is produced |
| HC-04 | Secret, unsafe identity, and boundary escape tests | Protected-data canaries reject before persistence/hashing; unsafe identities reject; passed locally | Negative tests in focused suite | Authorized protected client data is not introduced |
| HC-05 | Positive, negative, mutation, schema, retry, and telemetry tests | Generated/executed/validated/parity/certified/human states remain false; blocked and unsupported remain visible; passed locally | Strict evidence schema and telemetry projection | Real-runtime and business acceptance criteria remain unverified, not waived |

## Commands

Run the focused gate:

```bash
pytest -q tests/unit/test_sas_format_function_semantics.py
```

Then run `make verify`. Network-dependent audit behavior, if unavailable, must be reported as a
blocked gate rather than represented as passing.

Local verification on 2026-09-19 passed Ruff, mypy, and all 1,763 tests. The final `pip-audit`
stage was environment-blocked because the sandbox could not resolve `pypi.org`; therefore the
combined `make verify` command is not represented as fully passing.

Final commit, merge, Issue/Project lifecycle changes, and competition acceptance remain
human-controlled.
