# ART-02 acceptance evidence matrix

This matrix describes the offline increment only. It is not Humana launch evidence. Results below
were produced in the ART-02 candidate worktree at base revision `d27052e7`. No external immutable
evidence was created, so live criteria remain explicitly unverified.

Focused test command (2026-09-15):

```text
python -m pytest -q -p no:cacheprovider tests/unit/test_security_configuration.py tests/unit/test_workload_identity_provider.py tests/unit/test_secret_provider.py tests/unit/test_secret_resolution_manifest.py tests/integration/test_secret_provider_admission.py tests/integration/test_security_schema_packaging.py
```

Result: `44 passed` with the pytest cache provider disabled. The final repository and confidence
gates were then run from the candidate worktree after activating the repository virtual environment:

```text
source '/Users/tj.barry/Library/CloudStorage/OneDrive-3Cloud/Visual Studio Code/sas-modernization-factory/sas-modernization-factory/.venv/bin/activate'
make format
make verify
./scripts/test-discovery-confidence.sh
./scripts/test-corpus-confidence.sh
```

Final results: Ruff formatting/lint passed; strict mypy passed for 122 source files; pytest reported
`929 passed`; `pip-audit` found no known vulnerabilities and skipped only the unpublished local
`sas-modernization-factory` package; discovery confidence Gates A/B/C passed with 1/15/16 tests; and
corpus confidence reported `53 passed`.

| Criterion | Source/config revision | Procedure | Expected outcome | Actual outcome | Safe evidence reference |
|---|---|---|---|---|---|
| ART-02-AC01 | `d27052e7` + candidate tree | Run focused suite | Strict portable contract; absent/invalid/pending configuration makes zero calls | Passed locally | `tests/unit/test_secret_provider.py::test_configuration_admission_returns_schema_valid_non_success_without_transport`; no immutable external artifact |
| ART-02-AC02 | `d27052e7` + candidate tree | Run configuration, provider and manifest tests | Exact request binding; current version, expiry, lease and configured transition enforced | Passed locally | `tests/unit/test_secret_provider.py::test_configured_rotation_is_observed_only_for_current_version`; `tests/unit/test_secret_resolution_manifest.py`; no immutable external artifact |
| ART-02-AC03 | `d27052e7` + candidate tree | Run failure-matrix and response-boundary tests | Typed Entra/Vault/timeout/cancellation failures; response/log/exception/copy/pickle paths reveal no canary | Passed locally | `tests/unit/test_secret_provider.py::test_provider_failures_are_typed_sanitized_and_isolated`; `tests/unit/test_workload_identity_provider.py::test_credential_responses_redact_and_refuse_copy_or_serialization`; no immutable external artifact |
| ART-02-AC04 | `d27052e7` + candidate tree | Run restart and two-workload tests; review live boundary | Repeat/restart and concurrent workloads remain isolated; live evidence stays blocked | Offline tests passed; live portion unverified | `tests/unit/test_secret_provider.py::test_restart_recomputes_stable_identity_without_retained_credentials`; `tests/unit/test_secret_provider.py::test_two_workloads_resolve_without_shared_material_or_state`; `docs/SECRET_PROVIDER.md` |
| HC-01 | `d27052e7` + candidate tree | Run request, activation and manifest tests | Results bind exact identities and source/policy/configuration digests | Passed locally | `tests/integration/test_secret_provider_admission.py`; `tests/unit/test_secret_resolution_manifest.py`; no immutable external artifact |
| HC-02 | Candidate tree | Review `smf.security` imports and request model | Acceptance path has no recall dependency | Not applicable: this item consumes no recalled knowledge | `src/smf/security/`; local review only |
| HC-03 | `d27052e7` + candidate tree | Run admission source-mutation test | Source bytes are rehashed; receipts assert no conversion/parity | Passed locally | `tests/integration/test_secret_provider_admission.py::test_admission_rehashes_qualified_source_bytes`; no immutable external artifact |
| HC-04 | `d27052e7` + candidate tree | Run response-canary, failure-canary and boundary-escape tests | Credential canaries and sensitive targets do not enter receipts, logs or exceptions | Passed locally | `tests/unit/test_workload_identity_provider.py`; `tests/unit/test_security_configuration.py::test_configuration_rejects_boundary_escape`; no immutable external artifact |
| HC-05 | `d27052e7` + candidate tree | Run the exact focused and final gate commands above | Positive, negative, mutation, restart and concurrency evidence passes; blocked is never success | Focused 44 passed; full 929 passed; dependency and confidence gates passed | `.smf-agent/runs/ART-02/20260915T181500Z/gates-2.json`, SHA-256 `3131ac0970742259f9662fe57c78a1b77e34ae7194565a99d09c337d820137a9` |

Focused repair checks used `python -m ruff format --check src/smf/security tests/unit/test_security_configuration.py tests/unit/test_workload_identity_provider.py tests/unit/test_secret_provider.py tests/unit/test_secret_resolution_manifest.py tests/integration/test_secret_provider_admission.py tests/integration/test_security_schema_packaging.py`, `python -m ruff check` over those same paths, and `python -m mypy --strict src/smf/security`.
Immutable external evidence is unavailable because real-environment execution and publication were
not authorized. Mocks do not satisfy live qualification or demonstrate live rotation.
