# CV-01 acceptance evidence

Status: bounded offline implementation evidence; not Humana runtime, parity, certification, launch,
or completion approval.

## Evidence binding

- Source revision before the uncommitted CV-01 changes: `a20498dc18b8624d357515eea1cf424129c98b18`.
- Registry ID/version: `smf.deterministic.proc_sql` / `1.0.0`.
- Registry digest: `be0e98fd5285ad60de205d130641f81262b36f3abc6ce4d8b29e1031b790194f`.
- Test procedure: repository-local Python 3.12 environment; no network or client runtime invoked.
- Public-source sample digest roll-up before final gates:
  `412405e5e61207d72bfd84551df13256384b64e719916c20759880ff3d84382c`.

The immutable runtime references produced by the implementation are attempt-local
`rule-plan.json`, `rule-applications.json`, generated artifact, `conversion.manifest.json`, and
`conversion.telemetry.json`. Test references below are repository paths because ephemeral pytest
attempt directories are intentionally not committed as acceptance evidence.

## Acceptance matrix

| Criterion | Concrete proof | Expected outcome | Actual offline result |
|---|---|---|---|
| CV-01-AC01 | registry snapshot and descriptor-bound qualification tests | Rules expose construct, semantics, unsupported cases, version and package-owned qualification records | Passed |
| CV-01-AC02 | positive application-evidence and distinct-source-artifact identity tests plus unsupported-family parametrization | Exact span/input/output hashes and explicit applicability; macro/FORMAT/Jinja remain separate | Passed |
| CV-01-AC03 | active-revision/overlap, complete-statement grammar and rule-mutation tests | Ambiguity, unqualified clauses and changed rules cannot select a plausible stale rewrite | Passed |
| CV-01-AC04 | deterministic publication/recovery and existing two-workload isolation tests | Exact snapshots/policy bindings, restart and isolation remain reconstructable | Passed offline; live workload/runtime evidence remains unverified |
| HC-01 | deterministic result loader and readiness conversion guard suite | Evidence binds source/workload/run/attempt/policy/rule/artifact identities | Passed |
| HC-02 | registry API accepts no recall input and tests construct plans from admitted bytes only | No durable recall dependency or advisory authority | Passed by code review and tests |
| HC-03 | positive SQL fixture and PROC FORMAT/macro/Jinja/pass-through counterexamples | Source families stay distinct; no fixture claims semantic parity | Passed |
| HC-04 | canary, unsafe ID/path, readiness attestation and source mutation tests | Unsafe identity/protected canaries block without persisted value | Passed |
| HC-05 | empty/comment-only, malformed enum/status, generated-claim, exception, retry and concurrency tests | False success and duplicate invocation fail; outcomes remain distinct | Passed |

## Reproducible commands

Focused registry and affected integration gate:

```text
python -m ruff check src tests
python -m mypy src
python -m pytest -q tests/unit/test_conversion_rule_registry.py \
  tests/unit/test_conversion_engine.py tests/unit/test_readiness_conversion_guard.py \
  tests/integration/test_cli_conversion_validation.py \
  tests/integration/test_pilot_readiness_binding.py tests/integration/test_corpus_regression.py
```

Expected: lint and type checks pass; all selected tests pass. Actual: lint passed, mypy passed, and
the repaired focused conversion/readiness/CLI selection passed 77 tests before the final schema
negative was added. The offline corpus confidence gate passed 53 tests.

Repository-wide gate result: Ruff passed, strict mypy passed, and the final full suite passed all
1,351 tests. `make verify` then reached `pip-audit`, which was blocked because the sandbox could not
resolve `pypi.org`; no dependency-audit success is claimed. Re-run `python -m pip_audit` in an
approved networked environment before integration.

## Explicit unresolved competition evidence

- No approved Humana 1,000-script cohort manifest or distribution was provided.
- No authoritative source/output CTAS mapping is connected to this command boundary.
- No SAS baseline, Databricks runtime execution, cancellation experiment, numerical tolerance,
  business rule, cost/resource limit, owner disposition, or acceptance quota was exercised.
- Generated output therefore does not imply executed, validated, parity-passed, certified, or
  human-approved status. Those fields remain false in deterministic telemetry.
