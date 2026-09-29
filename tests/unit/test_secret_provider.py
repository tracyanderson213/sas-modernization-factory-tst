import asyncio
import base64
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from test_security_configuration import write_configuration

from smf.security import (
    EntraWorkloadIdentityProvider,
    HashiCorpVaultSecretProvider,
    IdentityResponse,
    ReasonCode,
    ResolutionState,
    SecretResolutionRequest,
    SecretResponse,
    activation_digest,
    activation_payload,
)
from smf.security.identity import IdentityRejectedError, ProviderUnavailableError
from smf.security.secrets import VaultDeniedError


def request(config, evidence_digest: str = "0" * 64) -> SecretResolutionRequest:
    return SecretResolutionRequest(
        "1.0",
        "client-1",
        "deployment-1",
        "environment-1",
        "workload-1",
        "1" * 64,
        "boundary-1",
        "subject-1",
        "2" * 64,
        "run-1",
        "attempt-1",
        "consumer-1",
        "1.0",
        "identity-1",
        "secret-1",
        config.policy_id,
        config.policy_version,
        config.policy_digest,
        config.configuration_digest,
        "ready-1",
        "3" * 64,
        "evidence://snapshot/1",
        "activation-1",
        evidence_digest,
    )


def activation(req, config, key, *, state="approved"):
    now = datetime.now(UTC)
    value = {
        "evidence_id": "activation-1",
        "state": state,
        "authority": config.authority,
        "purpose": "vault-secret-read",
        "decision_id": "decision-1",
        "owner_assignment_ref": "owner-1",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    for field in (
        "client_id",
        "deployment_id",
        "environment_id",
        "workload_id",
        "workload_digest",
        "boundary_id",
        "subject_id",
        "source_sha256",
        "run_id",
        "attempt_id",
        "consumer_id",
        "consumer_contract_version",
        "identity_binding_id",
        "secret_binding_id",
        "security_policy_id",
        "security_policy_version",
        "security_policy_digest",
        "configuration_digest",
        "readiness_result_id",
        "readiness_manifest_digest",
        "qualified_snapshot_ref",
    ):
        value[field] = getattr(req, field)
    value["proof"] = {"algorithm": "ed25519", "key_id": "key-1", "value": ""}
    value["proof"]["value"] = base64.b64encode(key.sign(activation_payload(value))).decode()
    return value


class IdentityTransport:
    calls = 0
    last_response = None

    def exchange(self, *, request, binding):
        self.calls += 1
        self.last_response = IdentityResponse(
            bytearray(b"token-canary"),
            binding.issuer,
            binding.audience,
            "2099-01-01T00:00:00Z",
        )
        return self.last_response


class VaultTransport:
    calls = 0
    last_response = None

    def read(self, *, token, request, binding):
        self.calls += 1
        assert bytes(token) == b"token-canary"
        now = datetime.now(UTC)
        self.last_response = SecretResponse(
            bytearray(b"secret-canary"),
            binding.version,
            now.isoformat(),
            (now + timedelta(minutes=5)).isoformat(),
            False,
        )
        return self.last_response


def test_missing_and_self_asserted_approval_fail_before_transport(tmp_path: Path) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    identity, vault = IdentityTransport(), VaultTransport()
    provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
    req = request(config)
    with provider.resolve(req, config, None) as (material, receipt):
        assert material is None
        assert receipt.state is ResolutionState.BLOCKED_MISSING
    with provider.resolve(req, config, {"approved": True}) as (material, receipt):
        assert material is None
        assert receipt.state is ResolutionState.INVALID_BINDING
    extra = activation(req, config, key)
    extra["approved"] = True
    extra["proof"]["value"] = base64.b64encode(key.sign(activation_payload(extra))).decode()
    extra_request = replace(req, activation_evidence_digest=activation_digest(extra))
    with provider.resolve(extra_request, config, extra) as (material, receipt):
        assert material is None
        assert receipt.state is ResolutionState.INVALID_BINDING
    unsigned_denial = {
        "evidence_id": req.activation_evidence_id,
        "state": "denied",
        "authority": config.authority,
    }
    unsigned_request = replace(req, activation_evidence_digest=activation_digest(unsigned_denial))
    with provider.resolve(unsigned_request, config, unsigned_denial) as (material, receipt):
        assert material is None
        assert receipt.state is ResolutionState.INVALID_BINDING
    assert identity.calls == vault.calls == 0


def test_non_authorizing_architecture_packet_is_rejected_by_real_transport_admission(
    tmp_path: Path,
) -> None:
    config, _, _, _ = write_configuration(tmp_path)
    identity, vault = IdentityTransport(), VaultTransport()
    provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
    packet = {
        "packet_kind": "architecture_security_review_evidence",
        "authority": "non_authorizing",
    }
    with provider.resolve(request(config), config, packet) as (material, receipt):
        assert material is None
        assert receipt.state is ResolutionState.INVALID_BINDING
        assert receipt.reason_code is ReasonCode.ACTIVATION_INVALID
    assert identity.calls == vault.calls == 0


def test_identity_adapter_cannot_be_called_without_bound_activation(tmp_path: Path) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    initial = request(config)
    evidence = activation(initial, config, key)
    req = replace(initial, activation_evidence_digest=activation_digest(evidence))
    transport = IdentityTransport()
    provider = EntraWorkloadIdentityProvider(transport)

    with pytest.raises(Exception, match="not authorized"):
        provider.acquire(req, config, None)
    assert transport.calls == 0

    material = provider.acquire(req, config, evidence)
    assert bytes(material.view()) == b"token-canary"
    material.close()
    assert transport.calls == 1


def test_pending_configuration_and_explicit_denial_are_distinct(tmp_path: Path) -> None:
    pending, _, _, _ = write_configuration(tmp_path, status="pending")
    identity, vault = IdentityTransport(), VaultTransport()
    provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
    with provider.resolve(request(pending), pending, None) as (_, pending_receipt):
        assert pending_receipt.state is ResolutionState.BLOCKED_PENDING

    active, key, _, _ = write_configuration(tmp_path, status="active")
    initial = request(active)
    denied = activation(initial, active, key, state="denied")
    denied_request = replace(initial, activation_evidence_digest=activation_digest(denied))
    with provider.resolve(denied_request, active, denied) as (_, denied_receipt):
        assert denied_receipt.state is ResolutionState.DENIED
    assert pending_receipt.reason_code != denied_receipt.reason_code
    assert identity.calls == vault.calls == 0


def test_bound_signed_activation_resolves_transiently_without_persisting_canaries(
    tmp_path: Path,
) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    initial = request(config)
    evidence = activation(initial, config, key)
    req = replace(initial, activation_evidence_digest=activation_digest(evidence))
    identity, vault = IdentityTransport(), VaultTransport()
    provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
    with provider.resolve(req, config, evidence) as (material, receipt):
        assert material is not None and bytes(material.view()) == b"secret-canary"
        serialized = json.dumps(receipt.to_dict())
        assert "secret-canary" not in serialized and "token-canary" not in serialized
        assert receipt.state is ResolutionState.RESOLVED
        assert not any(
            (receipt.generated, receipt.executed, receipt.validated, receipt.parity_passed)
        )
    assert material is not None and material.closed
    assert identity.calls == vault.calls == 1
    assert identity.last_response is not None
    assert identity.last_response.token == bytearray(len(b"token-canary"))
    assert vault.last_response is not None
    assert vault.last_response.value == bytearray(len(b"secret-canary"))


def test_activation_cannot_replay_across_attempts(tmp_path: Path) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    original = request(config)
    evidence = activation(original, config, key)
    replay = replace(
        original, attempt_id="attempt-2", activation_evidence_digest=activation_digest(evidence)
    )
    identity, vault = IdentityTransport(), VaultTransport()
    provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
    with provider.resolve(replay, config, evidence) as (_, receipt):
        assert receipt.state is ResolutionState.INVALID_BINDING
    assert identity.calls == vault.calls == 0


@pytest.mark.parametrize(
    "mutation", ["forged", "stale", "expired", "environment", "boundary", "source"]
)
def test_protected_transport_rejects_invalid_exact_subject_activation_before_provider_calls(
    tmp_path: Path, mutation: str
) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    initial = request(config)
    evidence = activation(initial, config, key)
    req = initial
    if mutation == "forged":
        evidence["proof"]["value"] = base64.b64encode(b"x" * 64).decode()
    elif mutation == "stale":
        evidence["issued_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        evidence["proof"]["value"] = base64.b64encode(
            key.sign(activation_payload(evidence))
        ).decode()
    elif mutation == "expired":
        evidence["expires_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        evidence["proof"]["value"] = base64.b64encode(
            key.sign(activation_payload(evidence))
        ).decode()
    elif mutation == "environment":
        req = replace(initial, environment_id="environment-2")
    elif mutation == "boundary":
        req = replace(initial, boundary_id="boundary-2")
    else:
        req = replace(initial, source_sha256="4" * 64)
    req = replace(req, activation_evidence_digest=activation_digest(evidence))
    identity, vault = IdentityTransport(), VaultTransport()
    provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
    with provider.resolve(req, config, evidence) as (material, receipt):
        assert material is None
        assert receipt.state in {ResolutionState.INVALID_BINDING, ResolutionState.EXPIRED}
    assert identity.calls == vault.calls == 0


def test_consumer_exception_propagates_after_zeroing_secret(tmp_path: Path) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    initial = request(config)
    evidence = activation(initial, config, key)
    req = replace(initial, activation_evidence_digest=activation_digest(evidence))
    provider = HashiCorpVaultSecretProvider(
        EntraWorkloadIdentityProvider(IdentityTransport()), VaultTransport()
    )
    material = None
    try:
        with provider.resolve(req, config, evidence) as (material, _):
            raise RuntimeError("consumer-canary")
    except RuntimeError as exc:
        assert str(exc) == "consumer-canary"
    assert material is not None and material.closed


def test_two_workloads_resolve_without_shared_material_or_state(tmp_path: Path) -> None:
    config, key, _, _ = write_configuration(tmp_path)

    def run(workload_id: str, canary: bytes) -> tuple[str, bool]:
        initial = replace(request(config), workload_id=workload_id)
        evidence = activation(initial, config, key)
        req = replace(initial, activation_evidence_digest=activation_digest(evidence))

        class IsolatedVault:
            def read(self, *, token, request, binding):
                now = datetime.now(UTC)
                return SecretResponse(
                    bytearray(canary),
                    binding.version,
                    now.isoformat(),
                    (now + timedelta(minutes=5)).isoformat(),
                    False,
                )

        provider = HashiCorpVaultSecretProvider(
            EntraWorkloadIdentityProvider(IdentityTransport()), IsolatedVault()
        )
        with provider.resolve(req, config, evidence) as (material, receipt):
            assert material is not None and bytes(material.view()) == canary
            return receipt.request["workload_id"], receipt.state is ResolutionState.RESOLVED

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(run, "workload-a", b"secret-a"),
            executor.submit(run, "workload-b", b"secret-b"),
        ]
    assert {future.result() for future in futures} == {
        ("workload-a", True),
        ("workload-b", True),
    }


@pytest.mark.parametrize(
    ("stage", "failure", "expected_state", "expected_reason"),
    [
        (
            "identity",
            IdentityRejectedError("entra diagnostic canary"),
            ResolutionState.AUTHENTICATION_FAILED,
            ReasonCode.IDENTITY_REJECTED,
        ),
        (
            "vault",
            VaultDeniedError("vault diagnostic canary"),
            ResolutionState.DENIED,
            ReasonCode.VAULT_DENIED,
        ),
        (
            "vault",
            ProviderUnavailableError("provider diagnostic canary"),
            ResolutionState.PROVIDER_UNAVAILABLE,
            ReasonCode.PROVIDER_UNAVAILABLE,
        ),
        (
            "vault",
            TimeoutError("timeout diagnostic canary"),
            ResolutionState.TIMED_OUT,
            ReasonCode.TRANSPORT_TIMEOUT,
        ),
        (
            "vault",
            asyncio.CancelledError("cancel diagnostic canary"),
            ResolutionState.CANCELLED,
            ReasonCode.CANCELLED,
        ),
    ],
)
def test_provider_failures_are_typed_sanitized_and_isolated(
    tmp_path: Path,
    stage: str,
    failure: BaseException,
    expected_state: ResolutionState,
    expected_reason: ReasonCode,
) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    initial = request(config)
    evidence = activation(initial, config, key)
    req = replace(initial, activation_evidence_digest=activation_digest(evidence))

    class FailingIdentity:
        def acquire(self, request, config, activation):
            return __import__("smf.security", fromlist=["TransientMaterial"]).TransientMaterial(
                b"failure-token-canary"
            )

    class FailingEntraTransport:
        def exchange(self, *, request, binding):
            raise failure

    class FailingVault:
        calls = 0

        def read(self, *, token, request, binding):
            self.calls += 1
            raise failure

    vault = FailingVault()
    identity = (
        EntraWorkloadIdentityProvider(FailingEntraTransport())
        if stage == "identity"
        else FailingIdentity()
    )
    provider = HashiCorpVaultSecretProvider(identity, vault)
    with provider.resolve(req, config, evidence) as (material, receipt):
        assert material is None
        assert receipt.state is expected_state
        assert receipt.reason_code is expected_reason
        serialized = json.dumps(receipt.to_dict())
        assert "diagnostic canary" not in serialized
        assert "failure-token-canary" not in serialized
    assert vault.calls == (0 if stage == "identity" else 1)


@pytest.mark.parametrize(
    ("enabled", "expires_delta", "expected_state", "expected_reason"),
    [
        (False, timedelta(minutes=5), ResolutionState.DENIED, ReasonCode.CREDENTIAL_DISABLED),
        (True, timedelta(minutes=-1), ResolutionState.EXPIRED, ReasonCode.CREDENTIAL_EXPIRED),
    ],
)
def test_disabled_and_expired_secret_responses_fail_closed(
    tmp_path: Path,
    enabled: bool,
    expires_delta: timedelta,
    expected_state: ResolutionState,
    expected_reason: ReasonCode,
) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    initial = request(config)
    evidence = activation(initial, config, key)
    req = replace(initial, activation_evidence_digest=activation_digest(evidence))

    class Vault:
        def read(self, *, token, request, binding):
            now = datetime.now(UTC)
            return SecretResponse(
                bytearray(b"response-canary"),
                binding.version,
                (now - timedelta(minutes=2)).isoformat(),
                (now + expires_delta).isoformat(),
                False,
                enabled,
            )

    provider = HashiCorpVaultSecretProvider(
        EntraWorkloadIdentityProvider(IdentityTransport()), Vault()
    )
    with provider.resolve(req, config, evidence) as (material, receipt):
        assert material is None
        assert receipt.state is expected_state
        assert receipt.reason_code is expected_reason


def test_configured_rotation_is_observed_only_for_current_version(tmp_path: Path) -> None:
    config, key, _, _ = write_configuration(tmp_path, previous_version="v0")
    initial = request(config)
    evidence = activation(initial, config, key)
    req = replace(initial, activation_evidence_digest=activation_digest(evidence))
    provider = HashiCorpVaultSecretProvider(
        EntraWorkloadIdentityProvider(IdentityTransport()), VaultTransport()
    )
    with provider.resolve(req, config, evidence) as (material, receipt):
        assert material is not None
        assert receipt.state is ResolutionState.RESOLVED
        assert receipt.lease is not None and receipt.lease.rotation_observed

    class StaleVault(VaultTransport):
        def read(self, *, token, request, binding):
            response = super().read(token=token, request=request, binding=binding)
            response = SecretResponse(
                response.value,
                binding.previous_version,
                response.issued_at,
                response.expires_at,
                response.renewable,
            )
            self.last_response = response
            return response

    stale = HashiCorpVaultSecretProvider(
        EntraWorkloadIdentityProvider(IdentityTransport()), StaleVault()
    )
    with stale.resolve(req, config, evidence) as (material, receipt):
        assert material is None
        assert receipt.state is ResolutionState.INVALID_BINDING
        assert receipt.reason_code is ReasonCode.BINDING_MISMATCH


@pytest.mark.parametrize("configuration_state", ["missing", "invalid"])
def test_configuration_admission_returns_schema_valid_non_success_without_transport(
    tmp_path: Path, configuration_state: str
) -> None:
    config, _, policy, binding = write_configuration(tmp_path)
    req = request(config)
    identity, vault = IdentityTransport(), VaultTransport()
    provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
    if configuration_state == "missing":
        binding = tmp_path / "absent-binding.yaml"
    else:
        binding.write_text("not: [valid", encoding="utf-8")
    with provider.resolve_configured(req, policy, binding, None) as (material, receipt):
        assert material is None
        assert receipt.state is not ResolutionState.RESOLVED
        assert not receipt.transport_attempted
        schema = json.loads(Path("schemas/secret-resolution-result.schema.json").read_text())
        Draft202012Validator(schema).validate(receipt.to_dict())
    assert identity.calls == vault.calls == 0


def test_restart_recomputes_stable_identity_without_retained_credentials(tmp_path: Path) -> None:
    config, key, _, _ = write_configuration(tmp_path)
    initial = request(config)
    evidence = activation(initial, config, key)
    req = replace(initial, activation_evidence_digest=activation_digest(evidence))
    results = []
    for _ in range(2):
        identity, vault = IdentityTransport(), VaultTransport()
        provider = HashiCorpVaultSecretProvider(EntraWorkloadIdentityProvider(identity), vault)
        with provider.resolve(req, config, evidence) as (material, receipt):
            assert material is not None
            results.append((receipt.resolution_id, receipt.request, bytes(material.view())))
        assert identity.last_response.token == bytearray(len(b"token-canary"))
        assert vault.last_response.value == bytearray(len(b"secret-canary"))
    assert results[0] == results[1]
