import base64
import hashlib
import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from smf.deployment import load_deployment_snapshot
from smf.execution.databricks_compute import (
    VerifiedComputeAvailabilityObservation,
    availability_observation_from_dict,
    build_compute_selection_request,
    compute_policy_from_dict,
    load_compute_policy,
    verify_availability_observation,
    verify_compute_admission,
    verify_compute_result,
    verify_result_availability,
)
from smf.execution.databricks_compute import (
    select_validation_compute as _select_validation_compute,
)
from smf.execution.databricks_compute_manifest import (
    compute_evidence_dir,
    compute_telemetry,
    load_compute_result,
    recover_compute_evidence,
    write_compute_preparation,
    write_compute_result,
)
from smf.execution.databricks_compute_models import AvailabilityState, ComputeSelectionResult
from smf.readiness.policy import digest_value

SOURCE = b"proc sql; select 1; quit;"
GENERATED = b"spark.sql('select 1')"
NOW = "2026-09-18T12:00:00Z"
_POLICY_KEY: Ed25519PrivateKey
_PROVIDER_KEY: Ed25519PrivateKey
_BUNDLE_ROOT: Path
_LAST_SNAPSHOT = None


def policy_payload(state: str = "active") -> dict:
    profile = {
        "profile_id": "small-isolated",
        "priority": 10,
        "compute_type": "job_cluster",
        "access_mode": "single_user",
        "dbr_version": "16.4-lts",
        "spark_version": "3.5.2",
        "scala_version": "2.12",
        "jvm_version": "17",
        "node_type": "standard-d4ds-v5",
        "min_workers": 1,
        "max_workers": 2,
        "max_concurrent_workloads": 1,
        "max_cost_usd": 25.0,
        "max_runtime_seconds": 900,
        "max_retries": 1,
        "cancellation_deadline_seconds": 30,
        "forced_termination_deadline_seconds": 90,
        "network_policy_id": "private-egress",
        "source_scope_id": "source-read",
        "output_scope_id": "isolated-output",
        "target": "pyspark",
        "workload_class": "standard",
        "single_workload_isolation": True,
    }
    value = {
        "schema_version": "1.0",
        "policy_id": "policy-1",
        "policy_version": "1.0.0",
        "policy_state": state,
        "client_id": "client-1",
        "deployment_id": "deployment-1",
        "environment_id": "environment-1",
        "workspace_binding_id": "workspace-1",
        "authority_ref": "policy-owner-1" if state == "active" else None,
        "authority_key_id": "policy-key-1" if state == "active" else None,
        "authority_signature": None,
        "valid_from": "2026-01-01T00:00:00Z" if state == "active" else None,
        "valid_until": "2027-01-01T00:00:00Z" if state == "active" else None,
        "supersedes_policy_digest": None,
        "owner_requirement_refs": ["HC-REQ-04", "HC-REQ-05", "HC-REQ-07"],
        "max_availability_age_seconds": 7200 if state == "active" else None,
        "profiles": [profile] if state == "active" else [],
        "policy_digest": "",
    }
    if state == "active":
        authority = dict(value)
        authority.pop("policy_digest")
        authority.pop("authority_signature")
        value["authority_signature"] = base64.b64encode(
            _POLICY_KEY.sign(
                json.dumps(
                    {
                        "contract": "smf-validation-compute-policy-authority-v1",
                        **authority,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
        ).decode()
    unsigned = dict(value)
    unsigned.pop("policy_digest")
    value["policy_digest"] = digest_value(
        {"contract": "smf-validation-compute-policy-v1", **unsigned}
    )
    return value


def observation_payload(state: str = "available") -> dict:
    value = {
        "schema_version": "1.0",
        "observation_id": "observation-1",
        "authority_ref": "availability-key-1",
        "observed_at": "2026-09-18T11:00:00Z",
        "expires_at": "2026-09-18T13:00:00Z",
        "provider_version": "provider-1.0",
        "workspace_binding_id": "workspace-1",
        "profile_id": "small-isolated",
        "state": state,
        "quota_limit": 2,
        "quota_used": 0,
        "observation_digest": "",
    }
    unsigned = dict(value)
    unsigned.pop("observation_digest")
    value["observation_digest"] = digest_value(
        {"contract": "smf-compute-availability-v1", **unsigned}
    )
    return value


def verified_observation(state: str = "available", *, key=None):
    global _PROVIDER_KEY
    observation = availability_observation_from_dict(observation_payload(state))
    key = key or _PROVIDER_KEY
    _PROVIDER_KEY = key
    signature = base64.b64encode(
        key.sign(
            __import__("json")
            .dumps(observation.bindings(), sort_keys=True, separators=(",", ":"))
            .encode()
        )
    ).decode()
    return verify_availability_observation(
        observation,
        key_id="availability-key-1",
        signature=signature,
        authority_keys={"availability-key-1": key.public_key()},
    )


_DEFAULT_OBSERVATION = object()


def readiness_payload() -> dict:
    configuration_digest = (
        _LAST_SNAPSHOT.configuration_digest if _LAST_SNAPSHOT is not None else "3" * 64
    )
    value = {
        "result_id": "readiness-1",
        "content_digest": "",
        "classification": "READY",
        "workload_id": "workload-1",
        "workload_digest": "1" * 64,
        "boundary_id": "boundary-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "policy_id": "readiness-policy-1",
        "policy_version": "1.0",
        "policy_digest": "6" * 64,
        "policy_snapshot": {
            "prerequisite_binding": {
                "client_id": "client-1",
                "deployment_id": "deployment-1",
                "environment_id": "environment-1",
                "configuration_digest": configuration_digest,
            }
        },
        "qualification_input": {
            "workload": {
                "artifacts": [
                    {
                        "artifact_id": "subject-1",
                        "checksum": __import__("hashlib").sha256(SOURCE).hexdigest(),
                    }
                ]
            }
        },
        "evidence_references": [
            {
                "kind": "discovery_snapshot",
                "snapshot_uri": "evidence://snapshots/snapshot-1",
            }
        ],
    }
    unsigned = dict(value)
    unsigned.pop("content_digest")
    value["content_digest"] = digest_value(unsigned)
    return value


def _write_yaml(path: Path, payload: dict) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _snapshot_for(policy_value: dict):
    global _LAST_SNAPSHOT
    _write_yaml(_BUNDLE_ROOT / "compute-policy.yaml", policy_value)
    names = [
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
    ]
    configuration_digest = digest_value(
        {
            "files": [
                {
                    "path": name,
                    "sha256": hashlib.sha256((_BUNDLE_ROOT / name).read_bytes()).hexdigest(),
                }
                for name in names
            ]
        }
    )
    readiness = yaml.safe_load((_BUNDLE_ROOT / "readiness-policy.yaml").read_text())
    readiness["prerequisite_binding"] = {
        "client_id": "client-1",
        "deployment_id": "deployment-1",
        "environment_id": "environment-1",
        "configuration_digest": configuration_digest,
    }
    readiness["evidence_provenance"]["approval"] = {
        "authorities": ["policy-owner-1"],
        "acquisition_sources": ["governed-policy-store"],
        "key_ids": ["policy-key-1"],
    }
    readiness["evidence_provenance"]["environment"] = {
        "authorities": ["availability-key-1"],
        "acquisition_sources": ["governed-provider-observation-store"],
        "key_ids": ["availability-key-1"],
    }
    readiness["verification_keys"] = {
        "policy-key-1": base64.b64encode(
            _POLICY_KEY.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode(),
        "availability-key-1": base64.b64encode(
            _PROVIDER_KEY.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode(),
    }
    _write_yaml(_BUNDLE_ROOT / "readiness-policy.yaml", readiness)
    _LAST_SNAPSHOT = load_deployment_snapshot(_BUNDLE_ROOT / "factory.yaml")
    return _LAST_SNAPSHOT


@pytest.fixture(autouse=True)
def _governed_readiness_loader(monkeypatch, tmp_path: Path) -> None:
    global _POLICY_KEY, _PROVIDER_KEY, _BUNDLE_ROOT
    _POLICY_KEY = Ed25519PrivateKey.generate()
    _PROVIDER_KEY = Ed25519PrivateKey.generate()
    _BUNDLE_ROOT = tmp_path / "deployment"
    shutil.copytree("deployments/humana", _BUNDLE_ROOT)
    factory = yaml.safe_load((_BUNDLE_ROOT / "factory.yaml").read_text())
    factory["template_status"] = "active"
    factory["deployment_identity"] = {
        "client_id": "client-1",
        "deployment_id": "deployment-1",
        "environment_id": "environment-1",
    }
    _write_yaml(_BUNDLE_ROOT / "factory.yaml", factory)
    databricks = yaml.safe_load((_BUNDLE_ROOT / "databricks.yaml").read_text())
    databricks["deployment_identity"] = dict(factory["deployment_identity"])
    for index, binding in enumerate(databricks["bindings"], start=1):
        binding.update(state="active", value=f"binding-{index}")
        if binding["role"] == "workspace":
            binding["binding_id"] = "workspace-1"
        if binding["role"] == "compute_policy":
            binding["value"] = "compute-policy.yaml"
    _write_yaml(_BUNDLE_ROOT / "databricks.yaml", databricks)
    for name in ("security-policy.yaml", "validation-policy.yaml"):
        payload = yaml.safe_load((_BUNDLE_ROOT / name).read_text())
        payload["deployment_identity"] = dict(factory["deployment_identity"])
        _write_yaml(_BUNDLE_ROOT / name, payload)
    monkeypatch.setattr(
        "smf.execution.databricks_compute.load_readiness_manifest",
        lambda _path: readiness_payload(),
    )


def request_for(policy=None, observation=_DEFAULT_OBSERVATION, **changes):
    if policy is None:
        policy_value = policy_payload()
    elif hasattr(policy, "bindings"):
        policy_value = policy.bindings()
    else:
        policy_value = policy
    if observation is _DEFAULT_OBSERVATION:
        observation = verified_observation()
    snapshot = _snapshot_for(policy_value)
    policy = compute_policy_from_dict(policy_value)
    values = {
        "source_bytes": SOURCE,
        "generated_bytes": GENERATED,
        "deployment_snapshot": snapshot,
        "observation": observation,
        "readiness_manifest_path": Path("governed-readiness.json"),
        "workload_id": "workload-1",
        "workload_digest": "1" * 64,
        "boundary_id": "boundary-1",
        "subject_id": "subject-1",
        "executable_entrypoint_id": "entrypoint-1",
        "qualified_snapshot_ref": "evidence://snapshots/snapshot-1",
        "source_closure_digest": "2" * 64,
        "target": "pyspark",
        "workload_class": "standard",
        "run_id": "run-1",
        "workflow_attempt_id": "attempt-1",
        "selection_attempt_id": "selection-1",
        "evaluated_at": NOW,
    }
    values.update(changes)
    return build_compute_selection_request(**values), policy, observation


def select_validation_compute(request, policy, observation):
    return _select_validation_compute(
        request,
        observation,
        deployment_snapshot=_LAST_SNAPSHOT,
        readiness_manifest_path=Path("governed-readiness.json"),
    )


def replay_inputs(root: Path) -> dict:
    source = root / "source.sas"
    generated = root / "generated.py"
    readiness = root / "readiness.json"
    source.write_bytes(SOURCE)
    generated.write_bytes(GENERATED)
    readiness.write_text("{}\n", encoding="utf-8")
    return {
        "authorized_root": root,
        "source_path": source,
        "generated_path": generated,
        "deployment_factory_path": _BUNDLE_ROOT / "factory.yaml",
        "readiness_manifest_path": readiness,
    }


def test_exact_policy_selects_offline_without_downstream_claims() -> None:
    request, policy, observation = request_for()
    result = select_validation_compute(request, policy, observation)
    assert result.state.value == "selected_offline"
    assert result.selected_profile_id == "small-isolated"
    assert result.effective_profile["max_runtime_seconds"] == 900
    assert not any(
        (
            result.allocated,
            result.submitted,
            result.executed,
            result.validated,
            result.parity_passed,
            result.certified,
            result.human_approved,
        )
    )


def test_caller_authored_availability_and_pending_denied_quota_remain_distinct() -> None:
    request, policy, trusted = request_for()
    untrusted = availability_observation_from_dict(observation_payload())
    assert select_validation_compute(request, policy, untrusted).state.value == "invalid_binding"

    for availability, expected in (
        ("pending", "blocked_pending"),
        ("denied", "denied"),
        ("quota_exhausted", "quota_exhausted"),
        ("allocation_unavailable", "allocation_unavailable"),
        ("incompatible_runtime", "incompatible_runtime"),
    ):
        observation = verified_observation(availability)
        request, _, _ = request_for(policy=policy, observation=observation)
        assert select_validation_compute(request, policy, observation).state.value == expected
    assert trusted.state.value == "available"


def test_verified_availability_marker_cannot_be_caller_constructed() -> None:
    observation = availability_observation_from_dict(observation_payload())
    with pytest.raises(ValueError, match="verified authority proof"):
        VerifiedComputeAvailabilityObservation(_verification_token=object(), **observation.__dict__)


def test_signed_denied_observation_mutated_to_available_cannot_select() -> None:
    observation = verified_observation("denied")
    request, policy, _ = request_for(observation=observation)

    object.__setattr__(observation, "state", AvailabilityState.AVAILABLE)

    result = select_validation_compute(request, policy, observation)

    assert result.state.value == "invalid_binding"
    assert result.reason_code == "availability_untrusted"

    verify_compute_result(
        result,
        request=request,
        source_bytes=SOURCE,
        generated_bytes=GENERATED,
        deployment_snapshot=_LAST_SNAPSHOT,
        readiness_manifest_path=Path("governed-readiness.json"),
    )


def test_untrusted_provider_terminal_result_survives_durable_replay(tmp_path: Path) -> None:
    observation = verified_observation("denied")
    request, _, _ = request_for(observation=observation)
    object.__setattr__(observation, "state", AvailabilityState.AVAILABLE)
    result = select_validation_compute(request, None, observation)
    evidence_key = Ed25519PrivateKey.generate()
    write_compute_preparation(tmp_path, request, signing_key=evidence_key, key_id="key-1")
    write_compute_result(tmp_path, request, result, signing_key=evidence_key, key_id="key-1")

    assert (
        recover_compute_evidence(
            tmp_path,
            request,
            verification_keys={"key-1": evidence_key.public_key()},
            **replay_inputs(tmp_path),
        )
        == result
    )


def test_unsigned_provider_terminal_result_replays_as_untrusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = availability_observation_from_dict(observation_payload())
    request, _, _ = request_for(observation=observation)
    result = select_validation_compute(request, None, observation)

    verify_compute_result(
        result,
        request=request,
        source_bytes=SOURCE,
        generated_bytes=GENERATED,
        deployment_snapshot=_LAST_SNAPSHOT,
        readiness_manifest_path=Path("governed-readiness.json"),
    )

    assert result.state.value == "invalid_binding"
    assert result.reason_code == "availability_untrusted"
    assert result.availability_proof is None
    evidence_key = Ed25519PrivateKey.generate()
    write_compute_preparation(tmp_path, request, signing_key=evidence_key, key_id="key-1")
    write_compute_result(tmp_path, request, result, signing_key=evidence_key, key_id="key-1")
    assert (
        recover_compute_evidence(
            tmp_path,
            request,
            verification_keys={"key-1": evidence_key.public_key()},
            **replay_inputs(tmp_path),
        )
        == result
    )

    changed_readiness = readiness_payload()
    changed_readiness["classification"] = "BLOCKED"
    unsigned = dict(changed_readiness)
    unsigned.pop("content_digest")
    changed_readiness["content_digest"] = digest_value(unsigned)
    monkeypatch.setattr(
        "smf.execution.databricks_compute.load_readiness_manifest",
        lambda _path: changed_readiness,
    )
    with pytest.raises(ValueError, match="stale or invalid"):
        verify_compute_result(
            result,
            request=request,
            source_bytes=SOURCE,
            generated_bytes=GENERATED,
            deployment_snapshot=_LAST_SNAPSHOT,
            readiness_manifest_path=Path("governed-readiness.json"),
        )


def test_mutated_observation_digest_cannot_select() -> None:
    observation = verified_observation()
    request, policy, _ = request_for(observation=observation)
    object.__setattr__(observation, "observation_digest", "0" * 64)

    result = select_validation_compute(request, policy, observation)

    assert result.state.value == "invalid_binding"
    assert result.reason_code == "availability_untrusted"


def test_missing_availability_is_an_explicit_blocker() -> None:
    policy = compute_policy_from_dict(policy_payload())
    request, _, _ = request_for(policy=policy, observation=None)
    result = select_validation_compute(request, policy, None)
    assert result.state.value == "blocked_missing"
    assert result.reason_code == "availability_missing"


@pytest.mark.parametrize("state", ["approved", "availble", True])
def test_unknown_policy_or_availability_enum_fails_closed(state) -> None:
    policy = policy_payload()
    policy["policy_state"] = state
    with pytest.raises(ValueError):
        compute_policy_from_dict(policy)
    observation = observation_payload()
    observation["state"] = state
    with pytest.raises(ValueError):
        availability_observation_from_dict(observation)


@pytest.mark.parametrize("source", [b"", b"/* proc sql; select 1; quit; */", b"%let x=data y;"])
def test_empty_or_nonconvertible_source_cannot_select(source: bytes) -> None:
    with pytest.raises(ValueError, match="executable SAS entry point"):
        request_for(source_bytes=source)


def test_replay_and_mutable_inputs_are_rejected() -> None:
    request, policy, observation = request_for()
    result = select_validation_compute(request, policy, observation)
    admission = {
        "source_bytes": SOURCE,
        "generated_bytes": GENERATED,
        "deployment_snapshot": _LAST_SNAPSHOT,
        "readiness_manifest_path": Path("governed-readiness.json"),
    }
    for field, changed in (
        ("source_bytes", SOURCE + b" "),
        ("generated_bytes", GENERATED + b" "),
        (
            "deployment_snapshot",
            replace(_LAST_SNAPSHOT, configuration_digest="7" * 64),
        ),
        ("deployment_snapshot", replace(_LAST_SNAPSHOT, bundle_digest="8" * 64)),
    ):
        with pytest.raises(ValueError, match="stale or invalid"):
            verify_compute_admission(result, request=request, **{**admission, field: changed})
    other = replace(request, workload_id="workload-2")
    with pytest.raises(ValueError, match="stale or invalid"):
        verify_compute_admission(
            result,
            request=other,
            **admission,
        )


def test_provider_evidence_mutation_before_admission_is_rejected() -> None:
    observation = verified_observation()
    request, _, _ = request_for(observation=observation)
    result = select_validation_compute(request, None, observation)
    changed_observation = dict(result.availability_observation or {})
    changed_observation["state"] = "denied"
    unsigned_observation = dict(changed_observation)
    unsigned_observation.pop("observation_digest")
    changed_observation["observation_digest"] = digest_value(
        {"contract": "smf-compute-availability-v1", **unsigned_observation}
    )
    changed_payload = result.to_dict()
    changed_payload["availability_observation"] = changed_observation
    changed_payload["content_digest"] = ""
    tampered = replace(
        result,
        availability_observation=changed_observation,
        content_digest=digest_value(changed_payload),
    )

    with pytest.raises(ValueError, match="availability proof is invalid"):
        verify_compute_admission(
            tampered,
            request=request,
            source_bytes=SOURCE,
            generated_bytes=GENERATED,
            deployment_snapshot=_LAST_SNAPSHOT,
            readiness_manifest_path=Path("governed-readiness.json"),
        )


def test_provider_proof_substitution_before_admission_is_rejected() -> None:
    provider_key = Ed25519PrivateKey.generate()
    observation = verified_observation(key=provider_key)
    request, _, _ = request_for(observation=observation)
    result = select_validation_compute(request, None, observation)
    denied = verified_observation("denied", key=provider_key)
    substituted_proof = {
        "key_id": denied.verification_key_id or "",
        "signature": denied.verification_signature or "",
    }
    changed_payload = result.to_dict()
    changed_payload["availability_proof"] = substituted_proof
    changed_payload["content_digest"] = ""
    tampered = replace(
        result,
        availability_proof=substituted_proof,
        content_digest=digest_value(changed_payload),
    )

    with pytest.raises(ValueError, match="availability proof is invalid"):
        verify_compute_admission(
            tampered,
            request=request,
            source_bytes=SOURCE,
            generated_bytes=GENERATED,
            deployment_snapshot=_LAST_SNAPSHOT,
            readiness_manifest_path=Path("governed-readiness.json"),
        )


@pytest.mark.parametrize(
    ("availability", "expected"),
    (("available", "selected_offline"), ("denied", "denied"), ("pending", "blocked_pending")),
)
def test_legitimate_signed_selected_denied_and_pending_results_reverify(
    availability: str, expected: str
) -> None:
    observation = verified_observation(availability)
    request, _, _ = request_for(observation=observation)
    result = select_validation_compute(request, None, observation)

    verify_compute_result(
        result,
        request=request,
        source_bytes=SOURCE,
        generated_bytes=GENERATED,
        deployment_snapshot=_LAST_SNAPSHOT,
        readiness_manifest_path=Path("governed-readiness.json"),
    )

    assert result.state.value == expected


def test_lifecycle_claim_mutation_is_rejected() -> None:
    request, policy, observation = request_for()
    result = select_validation_compute(request, policy, observation)
    with pytest.raises(ValueError, match="downstream success"):
        ComputeSelectionResult(**{**result.__dict__, "parity_passed": True})


def test_append_only_recovery_and_two_workload_isolation(tmp_path: Path) -> None:
    provider_key = Ed25519PrivateKey.generate()
    observation = verified_observation(key=provider_key)
    request, policy, _ = request_for(observation=observation)
    result = select_validation_compute(request, policy, observation)
    key = Ed25519PrivateKey.generate()
    write_compute_preparation(tmp_path, request, signing_key=key, key_id="key-1")
    path = write_compute_result(tmp_path, request, result, signing_key=key, key_id="key-1")
    telemetry = path.with_name("telemetry.json")
    telemetry.unlink()
    assert (
        recover_compute_evidence(
            tmp_path,
            request,
            verification_keys={"key-1": key.public_key()},
            **replay_inputs(tmp_path),
        )
        == result
    )
    assert telemetry.exists()

    other = replace(request, workload_id="workload-2")
    assert compute_evidence_dir(tmp_path, other) != compute_evidence_dir(tmp_path, request)
    with pytest.raises(FileExistsError, match="Conflicting immutable"):
        write_compute_result(
            tmp_path,
            request,
            replace(result, reason_code="edited"),
            signing_key=key,
            key_id="key-1",
        )


def test_checked_in_policy_is_explicitly_pending_and_schema_copies_match() -> None:
    policy, _ = load_compute_policy(Path("deployments/humana/compute-policy.yaml"))
    assert policy.policy_state.value == "pending"
    assert policy.profiles == ()
    assert policy.max_availability_age_seconds is None
    assert policy.authority_ref is None
    assert policy.authority_key_id is None
    assert policy.authority_signature is None
    assert policy.valid_from is None
    assert policy.valid_until is None
    for name in (
        "databricks-compute-availability.schema.json",
        "databricks-compute-policy.schema.json",
        "databricks-compute-request.schema.json",
        "databricks-compute-result.schema.json",
    ):
        assert (Path("schemas") / name).read_bytes() == (
            Path("src/smf/schemas") / name
        ).read_bytes()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authority_ref", "fabricated-owner"),
        ("authority_key_id", "fabricated-key"),
        ("authority_signature", "ZmFrZQ=="),
        ("valid_from", "2026-01-01T00:00:00Z"),
        ("valid_until", "2027-01-01T00:00:00Z"),
        ("max_availability_age_seconds", 300),
    ],
)
def test_pending_policy_rejects_fabricated_values(field: str, value: object) -> None:
    payload = policy_payload("pending")
    payload[field] = value
    unsigned = dict(payload)
    unsigned.pop("policy_digest")
    payload["policy_digest"] = digest_value(
        {"contract": "smf-validation-compute-policy-v1", **unsigned}
    )

    with pytest.raises(ValueError, match="schema validation|cannot assert"):
        compute_policy_from_dict(payload)


def test_caller_forged_configuration_digest_cannot_construct_request() -> None:
    snapshot = _snapshot_for(policy_payload())
    with pytest.raises(ValueError, match="validation seal|governed digest binding"):
        build_compute_selection_request(
            source_bytes=SOURCE,
            generated_bytes=GENERATED,
            deployment_snapshot=replace(snapshot, configuration_digest="f" * 64),
            observation=verified_observation(),
            readiness_manifest_path=Path("governed-readiness.json"),
            workload_id="workload-1",
            workload_digest="1" * 64,
            boundary_id="boundary-1",
            subject_id="subject-1",
            executable_entrypoint_id="entrypoint-1",
            qualified_snapshot_ref="evidence://snapshots/snapshot-1",
            source_closure_digest="2" * 64,
            target="pyspark",
            workload_class="standard",
            run_id="run-1",
            workflow_attempt_id="attempt-1",
            selection_attempt_id="selection-1",
            evaluated_at=NOW,
        )


def test_issue_153_readback_receipt_is_exact_and_local_body_is_cross_checked() -> None:
    receipt_path = Path("docs/architecture/DBX-03_ISSUE_153_READBACK.json")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    schema = json.loads(
        Path("schemas/github-issue-readback-receipt.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(receipt)
    local = Path(receipt["local_body"]["path"]).read_bytes()
    assert hashlib.sha256(local).hexdigest() == receipt["local_body"]["sha256"]
    assert receipt["local_body"]["matches_live_body"] is (
        receipt["local_body"]["sha256"] == receipt["body_sha256"]
    )
    assert (
        Path("schemas/github-issue-readback-receipt.schema.json").read_bytes()
        == Path("src/smf/schemas/github-issue-readback-receipt.schema.json").read_bytes()
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [("issue_number", 154), ("body_sha256", "0" * 64), ("title", "Mutated")],
)
def test_issue_153_readback_identity_or_body_mutation_fails_schema(
    field: str, value: object
) -> None:
    receipt = json.loads(
        Path("docs/architecture/DBX-03_ISSUE_153_READBACK.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        Path("schemas/github-issue-readback-receipt.schema.json").read_text(encoding="utf-8")
    )
    receipt[field] = value
    assert list(Draft202012Validator(schema).iter_errors(receipt))


def test_active_policy_without_availability_maximum_age_fails_closed() -> None:
    payload = policy_payload()
    payload["max_availability_age_seconds"] = None
    unsigned = dict(payload)
    unsigned.pop("policy_digest")
    payload["policy_digest"] = digest_value(
        {"contract": "smf-validation-compute-policy-v1", **unsigned}
    )

    with pytest.raises(ValueError, match="max_availability_age_seconds"):
        compute_policy_from_dict(payload)

    payload = policy_payload()
    payload.pop("max_availability_age_seconds")
    with pytest.raises(ValueError, match="unknown or missing fields"):
        compute_policy_from_dict(payload)


def test_policy_decision_is_bound_to_exact_recorded_policy_bytes() -> None:
    request, active, observation = request_for()
    forged = replace(_LAST_SNAPSHOT, compute_policy_digest="0" * 64)

    result = _select_validation_compute(
        request,
        observation,
        deployment_snapshot=forged,
        readiness_manifest_path=Path("governed-readiness.json"),
    )

    assert result.state.value == "invalid_binding"
    assert result.reason_code == "governed_evidence_invalid"


def test_readiness_assertions_cannot_be_mutated_without_governed_evidence() -> None:
    request, policy, observation = request_for()
    mutated = replace(request, readiness_manifest_digest="9" * 64)

    result = select_validation_compute(mutated, policy, observation)

    assert result.state.value == "invalid_binding"
    assert result.reason_code == "readiness_evidence_mismatch"


def test_availability_maximum_age_is_independent_of_signed_expiry() -> None:
    global _PROVIDER_KEY
    payload = observation_payload()
    payload["observed_at"] = "2000-01-01T00:00:00Z"
    payload["expires_at"] = "2027-01-01T00:00:00Z"
    unsigned = dict(payload)
    unsigned.pop("observation_digest")
    payload["observation_digest"] = digest_value(
        {"contract": "smf-compute-availability-v1", **unsigned}
    )
    observation = availability_observation_from_dict(payload)
    key = Ed25519PrivateKey.generate()
    _PROVIDER_KEY = key
    signature = base64.b64encode(
        key.sign(
            __import__("json")
            .dumps(observation.bindings(), sort_keys=True, separators=(",", ":"))
            .encode()
        )
    ).decode()
    trusted = verify_availability_observation(
        observation,
        key_id="availability-key-1",
        signature=signature,
        authority_keys={"availability-key-1": key.public_key()},
    )
    request, policy, _ = request_for(observation=trusted)

    result = select_validation_compute(request, policy, trusted)

    assert result.state.value == "expired"
    assert result.reason_code == "availability_stale"


def test_result_persists_reconstructable_provider_observation() -> None:
    provider_key = Ed25519PrivateKey.generate()
    observation = verified_observation(key=provider_key)
    request, policy, _ = request_for(observation=observation)
    result = select_validation_compute(request, policy, observation)

    assert result.evaluated_at == NOW
    assert result.availability_observation == observation.bindings()
    assert result.availability_proof["key_id"] == observation.authority_ref
    assert result.availability_proof["signature"]


def test_persisted_result_reverifies_exact_provider_evidence(tmp_path: Path) -> None:
    provider_key = Ed25519PrivateKey.generate()
    observation = verified_observation(key=provider_key)
    request, policy, _ = request_for(observation=observation)
    result = select_validation_compute(request, policy, observation)
    evidence_key = Ed25519PrivateKey.generate()
    write_compute_preparation(tmp_path, request, signing_key=evidence_key, key_id="key-1")
    path = write_compute_result(tmp_path, request, result, signing_key=evidence_key, key_id="key-1")

    reloaded = load_compute_result(path, verification_keys={"key-1": evidence_key.public_key()})
    reverified = verify_result_availability(
        reloaded,
        authority_keys={"availability-key-1": provider_key.public_key()},
    )

    assert reverified.bindings() == observation.bindings()
    assert reloaded.evaluated_at == NOW
    assert reverified.provider_version == "provider-1.0"
    assert reverified.quota_limit == 2
    assert reverified.quota_used == 0
    telemetry = compute_telemetry(reloaded)
    assert telemetry["policy_digest"] == policy.policy_digest
    assert telemetry["observation_authority_ref"] == "availability-key-1"
    assert telemetry["observation_provider_version"] == "provider-1.0"
    assert telemetry["evaluated_at"] == NOW


@pytest.mark.parametrize("kind", ["symlink", "nonregular", "traversal", "outside"])
def test_evidence_loader_rejects_unsafe_filesystem_objects(tmp_path: Path, kind: str) -> None:
    authorized = tmp_path / "authorized"
    authorized.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    if kind == "symlink":
        candidate = authorized / "result.json"
        candidate.symlink_to(outside)
    elif kind == "nonregular":
        candidate = authorized / "result.json"
        os.mkfifo(candidate)
    elif kind == "traversal":
        candidate = authorized / ".." / "outside.json"
    else:
        candidate = outside

    with pytest.raises(ValueError, match="Invalid Databricks compute result evidence"):
        load_compute_result(
            candidate,
            verification_keys={},
            authorized_root=authorized,
        )


def test_replay_reverifies_provider_proof_and_all_governed_bindings(tmp_path: Path) -> None:
    provider_key = Ed25519PrivateKey.generate()
    observation = verified_observation(key=provider_key)
    request, policy, _ = request_for(observation=observation)
    result = select_validation_compute(request, policy, observation)
    invalid_proof = {
        "key_id": "availability-key-1",
        "signature": base64.b64encode(b"tampered-provider-proof").decode(),
    }
    payload = result.to_dict()
    payload["availability_proof"] = invalid_proof
    payload["content_digest"] = ""
    tampered = replace(
        result,
        availability_proof=invalid_proof,
        content_digest=digest_value(payload),
    )
    evidence_key = Ed25519PrivateKey.generate()
    write_compute_preparation(tmp_path, request, signing_key=evidence_key, key_id="key-1")
    write_compute_result(
        tmp_path,
        request,
        tampered,
        signing_key=evidence_key,
        key_id="key-1",
    )

    with pytest.raises(ValueError, match="availability proof is invalid"):
        recover_compute_evidence(
            tmp_path,
            request,
            verification_keys={"key-1": evidence_key.public_key()},
            **replay_inputs(tmp_path),
        )


@pytest.mark.parametrize("availability", ["denied", "pending"])
@pytest.mark.parametrize("changed", ["policy", "configuration", "readiness", "provider"])
def test_nonselected_replay_rejects_governed_evidence_drift(
    tmp_path: Path, monkeypatch, availability: str, changed: str
) -> None:
    provider_key = Ed25519PrivateKey.generate()
    observation = verified_observation(availability, key=provider_key)
    request, _, _ = request_for(observation=observation)
    result = select_validation_compute(request, None, observation)
    evidence_key = Ed25519PrivateKey.generate()
    write_compute_preparation(tmp_path, request, signing_key=evidence_key, key_id="key-1")

    if changed == "provider":
        changed_observation = dict(result.availability_observation or {})
        changed_observation["quota_used"] = 1
        unsigned_observation = dict(changed_observation)
        unsigned_observation.pop("observation_digest")
        changed_observation["observation_digest"] = digest_value(
            {"contract": "smf-compute-availability-v1", **unsigned_observation}
        )
        changed_payload = result.to_dict()
        changed_payload["availability_observation"] = changed_observation
        changed_payload["content_digest"] = ""
        result = replace(
            result,
            availability_observation=changed_observation,
            content_digest=digest_value(changed_payload),
        )
    write_compute_result(tmp_path, request, result, signing_key=evidence_key, key_id="key-1")

    if changed == "policy":
        _snapshot_for(policy_payload("pending"))
    elif changed == "configuration":
        configuration = _BUNDLE_ROOT / "validation-policy.yaml"
        configuration.write_text(configuration.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    elif changed == "readiness":
        readiness = readiness_payload()
        readiness["classification"] = "BLOCKED"
        unsigned_readiness = dict(readiness)
        unsigned_readiness.pop("content_digest")
        readiness["content_digest"] = digest_value(unsigned_readiness)
        monkeypatch.setattr(
            "smf.execution.databricks_compute.load_readiness_manifest", lambda _path: readiness
        )

    with pytest.raises(ValueError):
        recover_compute_evidence(
            tmp_path,
            request,
            verification_keys={"key-1": evidence_key.public_key()},
            **replay_inputs(tmp_path),
        )


def test_restart_replays_prepared_request_and_rejects_t2_identity(tmp_path: Path) -> None:
    observation = verified_observation()
    request_t1, policy, _ = request_for(observation=observation)
    request_t2, _, _ = request_for(
        policy=policy,
        observation=observation,
        evaluated_at="2026-09-18T12:30:00Z",
    )
    evidence_key = Ed25519PrivateKey.generate()
    preparation = write_compute_preparation(
        tmp_path, request_t1, signing_key=evidence_key, key_id="key-1"
    )
    assert compute_evidence_dir(tmp_path, request_t1) == compute_evidence_dir(tmp_path, request_t2)

    captured = recover_compute_evidence(
        tmp_path,
        request_t2,
        verification_keys={"key-1": evidence_key.public_key()},
        authorized_root=tmp_path,
    )

    assert captured == request_t1
    assert captured.evaluated_at == NOW
    assert captured.decision_id != request_t2.decision_id
    with pytest.raises(FileExistsError, match="Conflicting immutable"):
        write_compute_preparation(tmp_path, request_t2, signing_key=evidence_key, key_id="key-1")
    competing = select_validation_compute(request_t2, policy, observation)
    with pytest.raises(ValueError, match="preparation binding mismatch"):
        write_compute_result(
            tmp_path,
            request_t2,
            competing,
            signing_key=evidence_key,
            key_id="key-1",
        )

    resumed = select_validation_compute(captured, policy, observation)
    original = select_validation_compute(request_t1, policy, observation)
    result_path = write_compute_result(
        tmp_path, captured, resumed, signing_key=evidence_key, key_id="key-1"
    )

    assert resumed == original
    assert resumed.state.value == "selected_offline"
    assert resumed.evaluated_at == NOW
    assert result_path.parent == preparation.parent
    assert len(list(tmp_path.rglob("preparation.json"))) == 1
    assert len(list(tmp_path.rglob("result.json"))) == 1


def test_competing_preparation_race_publishes_one_attempt_identity(tmp_path: Path) -> None:
    request_t1, _, observation = request_for()
    request_t2, _, _ = request_for(
        observation=observation,
        evaluated_at="2026-09-18T12:30:00Z",
    )
    evidence_key = Ed25519PrivateKey.generate()

    def publish(request):
        try:
            return write_compute_preparation(
                tmp_path, request, signing_key=evidence_key, key_id="key-1"
            )
        except FileExistsError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(publish, (request_t1, request_t2)))

    assert sum(isinstance(outcome, Path) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, FileExistsError) for outcome in outcomes) == 1
    assert len(list(tmp_path.rglob("preparation.json"))) == 1
    captured = recover_compute_evidence(
        tmp_path,
        request_t2,
        verification_keys={"key-1": evidence_key.public_key()},
        authorized_root=tmp_path,
    )
    assert captured in (request_t1, request_t2)


def test_tampered_signed_preparation_is_rejected(tmp_path: Path) -> None:
    request, _, _ = request_for()
    evidence_key = Ed25519PrivateKey.generate()
    path = write_compute_preparation(tmp_path, request, signing_key=evidence_key, key_id="key-1")
    payload = json.loads(path.read_text(encoding="utf-8"))
    unsigned = {key: value for key, value in payload.items() if key != "proof"}
    unsigned["decision_id"] = "dcd-" + "0" * 64
    unsigned["content_digest"] = digest_value(
        {key: value for key, value in unsigned.items() if key != "content_digest"}
    )
    signature = evidence_key.sign(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    )
    payload = {
        **unsigned,
        "proof": {
            "algorithm": "ed25519",
            "key_id": "key-1",
            "value": base64.b64encode(signature).decode(),
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="preparation integrity mismatch"):
        recover_compute_evidence(
            tmp_path,
            request,
            verification_keys={"key-1": evidence_key.public_key()},
            authorized_root=tmp_path,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", "run-2"),
        ("workload_id", "workload-2"),
        ("workflow_attempt_id", "attempt-2"),
        ("selection_attempt_id", "selection-2"),
    ),
)
def test_cross_attempt_preparation_substitution_is_rejected(
    tmp_path: Path, field: str, value: str
) -> None:
    request, _, _ = request_for()
    evidence_key = Ed25519PrivateKey.generate()
    source = write_compute_preparation(
        tmp_path / "source", request, signing_key=evidence_key, key_id="key-1"
    )
    substituted = replace(request, **{field: value})
    target = compute_evidence_dir(tmp_path / "target", substituted) / "preparation.json"
    target.parent.mkdir(parents=True)
    shutil.copyfile(source, target)

    with pytest.raises(ValueError, match="attempt binding mismatch"):
        recover_compute_evidence(
            tmp_path / "target",
            substituted,
            verification_keys={"key-1": evidence_key.public_key()},
            authorized_root=tmp_path,
        )


def test_duplicate_attempt_evidence_is_ambiguous_even_when_identical(tmp_path: Path) -> None:
    request, _, _ = request_for()
    evidence_key = Ed25519PrivateKey.generate()
    stable = write_compute_preparation(
        tmp_path, request, signing_key=evidence_key, key_id="key-1"
    ).parent
    legacy = stable.parent / request.selection_request_id / request.selection_attempt_id
    shutil.copytree(stable, legacy)

    with pytest.raises(ValueError, match="Ambiguous Databricks compute attempt evidence"):
        recover_compute_evidence(
            tmp_path,
            request,
            verification_keys={"key-1": evidence_key.public_key()},
            authorized_root=tmp_path,
        )


def test_evaluation_time_changes_decision_identity() -> None:
    request, policy, observation = request_for()
    first = select_validation_compute(request, policy, observation)
    later_request, _, _ = request_for(
        policy=policy,
        observation=observation,
        evaluated_at="2026-09-18T14:00:00Z",
    )
    later = select_validation_compute(later_request, policy, observation)

    assert first.decision_id != later.decision_id
