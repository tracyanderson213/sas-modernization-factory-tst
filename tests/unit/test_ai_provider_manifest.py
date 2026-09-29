from __future__ import annotations

import base64
import contextlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.ai_provider_test_support import (
    AUTHORITY_KEY,
    TRUSTED_VERIFIER_CONFIGURATION,
    make_provider_request,
    provider_input,
    write_trusted_prerequisites,
)

from smf.ai.manifest import (
    _execute_provider_attempt,
    execute_provider_attempt,
    load_provider_result,
    provider_evidence_dir,
    recover_provider_telemetry,
    write_invocation_marker,
    write_provider_preparation,
    write_provider_result,
)
from smf.ai.mock import DeterministicMockAIProvider
from smf.ai.models import (
    AIEvidenceClass,
    AIFinishReason,
    AIProviderOutcome,
    AIProviderRequest,
    AIProviderResponse,
    AIProviderState,
    AITarget,
)
from smf.ai.prerequisites import (
    AIProviderPrerequisites,
    AIProviderVerifierConfiguration,
    PrerequisiteVerification,
    verify_provider_prerequisites,
)
from smf.ai.provider import AIProvider, _invoke_ai_provider, invoke_ai_provider
from smf.security.ai_policy import canonical_ai_json

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEYS = {"test-key": KEY.public_key()}


def _execute(root: Path, request=None):  # type: ignore[no-untyped-def]
    selected = request or make_provider_request()
    trusted_root = (
        root
        / "trusted"
        / selected.run_id
        / selected.workload_id
        / selected.workflow_attempt_id
        / selected.provider_request_id
        / selected.provider_attempt_id
    )
    return _execute_provider_attempt(
        selected,
        provider_input(),
        DeterministicMockAIProvider(),
        evidence_root=root,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
        prerequisites=write_trusted_prerequisites(trusted_root, selected),
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )


def test_signed_result_round_trip_and_tamper_rejection(tmp_path: Path) -> None:
    request = make_provider_request()
    outcome = _invoke_ai_provider(
        request,
        provider_input(),
        DeterministicMockAIProvider(),
        prerequisites=write_trusted_prerequisites(tmp_path / "trusted", request),
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )
    path = write_provider_result(tmp_path, outcome.result, signing_key=KEY, key_id="test-key")
    assert load_provider_result(path, verification_keys=KEYS)["state"] == "succeeded"
    payload = json.loads(path.read_text())
    payload["generated"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="proof is invalid"):
        load_provider_result(path, verification_keys=KEYS)


def test_identical_retry_returns_canonical_result_and_recovers_telemetry(tmp_path: Path) -> None:
    request = make_provider_request()
    first = _execute(tmp_path, request)
    result_path = provider_evidence_dir(tmp_path, request) / "result.json"
    telemetry = result_path.with_name("telemetry.json")
    telemetry.unlink()
    second = _execute(tmp_path, request)
    assert second.result == first.result
    assert second.output is None
    assert telemetry.exists()
    assert recover_provider_telemetry(result_path, verification_keys=KEYS) == telemetry


def test_restart_after_invocation_marker_is_outcome_unknown_and_never_reinvoked(
    tmp_path: Path,
) -> None:
    request = make_provider_request()
    write_provider_preparation(tmp_path, request, signing_key=KEY, key_id="test-key")
    write_invocation_marker(tmp_path, request, signing_key=KEY, key_id="test-key")
    outcome = _execute(tmp_path, request)
    assert outcome.result.state is AIProviderState.OUTCOME_UNKNOWN
    assert outcome.result.provider_invoked is True
    assert outcome.output is None


def test_attempt_identity_cannot_be_reused_for_changed_request(tmp_path: Path) -> None:
    request = make_provider_request()
    _execute(tmp_path, request)
    changed = replace(request, target=AITarget.DATABRICKS_SQL)
    with pytest.raises(ValueError, match="reused for another request"):
        _execute(tmp_path, changed)


def test_two_workloads_publish_to_isolated_paths_concurrently(tmp_path: Path) -> None:
    first = make_provider_request()
    second = make_provider_request(
        workload_id="workload-two",
        workflow_attempt_id="workflow-attempt-two",
        provider_request_id="provider-request-two",
        provider_attempt_id="provider-attempt-two",
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda request: _execute(tmp_path, request), (first, second)))
    assert [item.result.state for item in outcomes] == [
        AIProviderState.SUCCEEDED,
        AIProviderState.SUCCEEDED,
    ]
    assert provider_evidence_dir(tmp_path, first) != provider_evidence_dir(tmp_path, second)


def test_caller_cannot_persist_downstream_success_assertion(tmp_path: Path) -> None:
    request = make_provider_request()
    outcome = _invoke_ai_provider(
        request,
        provider_input(),
        DeterministicMockAIProvider(),
        prerequisites=write_trusted_prerequisites(tmp_path / "trusted", request),
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )
    forged = replace(outcome.result, generated=True, parity_passed=True)
    with pytest.raises(ValueError, match="schema validation failed"):
        write_provider_result(tmp_path, forged, signing_key=KEY, key_id="test-key")

    unbound = replace(
        outcome.result,
        evidence_refs=(
            "evidence://unrelated/one",
            "evidence://unrelated/two",
            "evidence://unrelated/three",
            "evidence://unrelated/four",
            "evidence://unrelated/five",
            "evidence://unrelated/six",
            "evidence://unrelated/seven",
        ),
    )
    with pytest.raises(ValueError, match="not request-bound"):
        write_provider_result(tmp_path, unbound, signing_key=KEY, key_id="test-key")


class RacingProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.SYNTHETIC_CONTRACT

    def __init__(self) -> None:
        self._barrier = threading.Barrier(2)
        self._lock = threading.Lock()
        self.invocations = 0

    def invoke(self, request: object, transient_input: bytes) -> AIProviderResponse:
        with self._lock:
            self.invocations += 1
        with contextlib.suppress(threading.BrokenBarrierError):
            self._barrier.wait(timeout=0.5)
        return AIProviderResponse(b"select 1", AIFinishReason.STOP, 1, 1)


class FailingProvider(AIProvider):
    provider_id = "mock"
    evidence_class = AIEvidenceClass.SYNTHETIC_CONTRACT

    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def invoke(self, request: object, transient_input: bytes) -> AIProviderResponse:
        raise self.failure


@pytest.mark.parametrize("failure", [RuntimeError("sdk detail"), OSError("socket detail")])
def test_unexpected_provider_exception_persists_sanitized_terminal_result(
    tmp_path: Path, failure: Exception
) -> None:
    request = make_provider_request()
    prerequisites = write_trusted_prerequisites(tmp_path / "trusted", request)
    outcome = _execute_provider_attempt(
        request,
        provider_input(),
        FailingProvider(failure),
        evidence_root=tmp_path,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
        prerequisites=prerequisites,
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )
    assert outcome.result.state is AIProviderState.FAILED
    result_path = provider_evidence_dir(tmp_path, request) / "result.json"
    persisted = load_provider_result(result_path, verification_keys=KEYS)
    assert persisted["blocker_codes"] == ["provider_failure"]
    assert "sdk detail" not in result_path.read_text()
    assert "socket detail" not in result_path.read_text()


def test_concurrent_identical_attempt_invokes_provider_exactly_once(tmp_path: Path) -> None:
    request = make_provider_request()
    provider = RacingProvider()
    prerequisites = write_trusted_prerequisites(tmp_path / "trusted", request)

    def execute() -> object:
        return _execute_provider_attempt(
            request,
            provider_input(),
            provider,
            evidence_root=tmp_path,
            signing_key=KEY,
            key_id="test-key",
            verification_keys=KEYS,
            prerequisites=prerequisites,
            verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: execute(), range(2)))

    assert provider.invocations == 1
    assert not any(isinstance(item, Exception) for item in outcomes)
    assert {item.result.state for item in outcomes} <= {
        AIProviderState.SUCCEEDED,
        AIProviderState.OUTCOME_UNKNOWN,
    }


def test_nonexistent_caller_asserted_prerequisites_cannot_manufacture_success(
    tmp_path: Path,
) -> None:
    request = make_provider_request()
    provider = RacingProvider()
    outcome = execute_provider_attempt(
        request,
        provider_input(),
        provider,
        evidence_root=tmp_path,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
    )
    assert outcome.result.state is AIProviderState.BLOCKED_MISSING
    assert outcome.result.blocker_codes == ("governed_verifier_unavailable",)
    assert provider.invocations == 0


def test_prerequisite_bundle_without_governed_verifiers_is_blocked(tmp_path: Path) -> None:
    request = make_provider_request()
    provider = RacingProvider()
    outcome = execute_provider_attempt(
        request,
        provider_input(),
        provider,
        evidence_root=tmp_path,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
        prerequisites=write_trusted_prerequisites(tmp_path / "untrusted-bundle", request),
    )
    assert outcome.result.state is AIProviderState.BLOCKED_MISSING
    assert outcome.result.blocker_codes == ("governed_verifier_unavailable",)
    assert provider.invocations == 0


def test_nonexistent_referenced_prerequisite_is_explicitly_blocked(tmp_path: Path) -> None:
    request = make_provider_request()
    prerequisites = write_trusted_prerequisites(tmp_path / "trusted", request)
    missing_paths = dict(prerequisites.evidence_paths)
    missing_paths["configuration"] = tmp_path / "does-not-exist.json"
    prerequisites = replace(prerequisites, evidence_paths=missing_paths)
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is AIProviderState.BLOCKED_MISSING
    assert outcome.result.blocker_codes == ("trusted_prerequisites_unavailable",)
    assert provider.invocations == 0


def _execute_with_prerequisites(
    root: Path,
    request: AIProviderRequest,
    prerequisites: AIProviderPrerequisites,
    provider: RacingProvider,
) -> AIProviderOutcome:
    return _execute_provider_attempt(
        request,
        provider_input(),
        provider,
        evidence_root=root,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
        prerequisites=prerequisites,
        verifier_configuration=TRUSTED_VERIFIER_CONFIGURATION,
    )


def test_unsigned_prerequisite_cannot_authorize_invocation(tmp_path: Path) -> None:
    request = make_provider_request()
    prerequisites = write_trusted_prerequisites(tmp_path / "trusted", request)
    path = prerequisites.evidence_paths["configuration"]
    payload = json.loads(path.read_text())
    payload.pop("proof")
    path.write_text(json.dumps(payload), encoding="utf-8")
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert provider.invocations == 0


def test_caller_signed_prerequisite_cannot_authorize_invocation(tmp_path: Path) -> None:
    request = make_provider_request()
    attacker = Ed25519PrivateKey.generate()
    prerequisites = write_trusted_prerequisites(
        tmp_path / "trusted",
        request,
        authority_key=attacker,
        authority_key_id="caller-key",
    )
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert provider.invocations == 0


def test_caller_supplied_evidence_and_trust_roots_cannot_authorize_invocation(
    tmp_path: Path,
) -> None:
    request = make_provider_request()
    attacker_sec02 = Ed25519PrivateKey.generate()
    attacker_authority = Ed25519PrivateKey.generate()
    prerequisites = write_trusted_prerequisites(
        tmp_path / "attacker-controlled",
        request,
        sec02_key=attacker_sec02,
        sec02_key_id="attacker-sec02-key",
        authority_key=attacker_authority,
        authority_key_id="attacker-authority-key",
    )
    provider = RacingProvider()

    outcome = execute_provider_attempt(
        request,
        provider_input(),
        provider,
        evidence_root=tmp_path,
        signing_key=KEY,
        key_id="test-key",
        verification_keys=KEYS,
        prerequisites=prerequisites,
        verifier_configuration=AIProviderVerifierConfiguration(
            sec02_keys={"attacker-sec02-key": attacker_sec02.public_key()},
            authority_keys={"attacker-authority-key": attacker_authority.public_key()},
        ),
    )

    assert outcome.result.state is AIProviderState.BLOCKED_MISSING
    assert outcome.result.blocker_codes == ("governed_verifier_unavailable",)
    assert provider.invocations == 0

    direct_outcome = invoke_ai_provider(
        request,
        provider_input(),
        provider,
        prerequisites=prerequisites,
        verifier_configuration=AIProviderVerifierConfiguration(
            sec02_keys={"attacker-sec02-key": attacker_sec02.public_key()},
            authority_keys={"attacker-authority-key": attacker_authority.public_key()},
        ),
    )
    assert direct_outcome.result.state is AIProviderState.BLOCKED_MISSING
    assert direct_outcome.result.blocker_codes == ("governed_verifier_unavailable",)
    assert provider.invocations == 0


def test_digest_mismatched_prerequisite_cannot_authorize_invocation(tmp_path: Path) -> None:
    request = make_provider_request()
    prerequisites = write_trusted_prerequisites(tmp_path / "trusted", request)
    path = prerequisites.evidence_paths["configuration"]
    payload = json.loads(path.read_text())
    payload["evidence_digest"] = "f" * 64
    payload.pop("proof")
    payload["proof"] = {
        "algorithm": "ed25519",
        "key_id": "provider-authority-key",
        "value": base64.b64encode(AUTHORITY_KEY.sign(canonical_ai_json(payload))).decode(),
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert provider.invocations == 0


def test_expired_prerequisite_cannot_authorize_invocation(tmp_path: Path) -> None:
    request = make_provider_request()
    prerequisites = write_trusted_prerequisites(
        tmp_path / "trusted",
        request,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert outcome.result.blocker_codes == ("trusted_prerequisite_expired",)
    assert provider.invocations == 0


@pytest.mark.parametrize(
    "changed",
    [
        {"run_id": "run-two"},
        {"workflow_attempt_id": "workflow-attempt-two"},
    ],
)
def test_cross_run_or_attempt_prerequisites_cannot_authorize_invocation(
    tmp_path: Path, changed: dict[str, str]
) -> None:
    original = make_provider_request()
    request = make_provider_request(**changed)
    prerequisites = write_trusted_prerequisites(tmp_path / "trusted", original)
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert provider.invocations == 0


@pytest.mark.parametrize(
    ("prerequisite_state", "expected"),
    [
        ("pending", AIProviderState.BLOCKED_PENDING),
        ("denied", AIProviderState.DENIED),
    ],
)
def test_trusted_pending_and_denied_prerequisites_remain_distinct(
    tmp_path: Path, prerequisite_state: str, expected: AIProviderState
) -> None:
    request = make_provider_request()
    prerequisites = write_trusted_prerequisites(
        tmp_path / "trusted",
        request,
        states={"configuration": prerequisite_state},
    )
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is expected
    assert provider.invocations == 0


def test_prerequisite_mutation_before_invocation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = make_provider_request()
    prerequisites = write_trusted_prerequisites(tmp_path / "trusted", request)
    configuration = prerequisites.evidence_paths["configuration"]
    calls = 0

    def verify_then_mutate(
        request_arg: AIProviderRequest,
        prerequisites_arg: AIProviderPrerequisites | None,
        *,
        verifier_configuration: AIProviderVerifierConfiguration | None = None,
        now: datetime | None = None,
    ) -> PrerequisiteVerification:
        nonlocal calls
        result = verify_provider_prerequisites(
            request_arg,
            prerequisites_arg,
            verifier_configuration=verifier_configuration,
            now=now,
        )
        calls += 1
        if calls == 2:
            configuration.write_bytes(configuration.read_bytes() + b" \n")
        return result

    monkeypatch.setattr("smf.ai.manifest.verify_provider_prerequisites", verify_then_mutate)
    provider = RacingProvider()
    outcome = _execute_with_prerequisites(tmp_path, request, prerequisites, provider)
    assert outcome.result.state is AIProviderState.INVALID_BINDING
    assert outcome.result.blocker_codes == ("trusted_prerequisite_changed_before_invocation",)
    assert provider.invocations == 0
