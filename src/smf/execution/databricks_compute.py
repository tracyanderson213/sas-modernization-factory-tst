"""Offline, fail-closed validation-compute policy selection."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.deployment.configuration import (
    DeploymentSnapshot,
    require_validated_deployment_snapshot,
)
from smf.execution.databricks_compute_models import (
    AccessMode,
    AvailabilityState,
    ComputeAvailabilityObservation,
    ComputePolicyState,
    ComputeSelectionRequest,
    ComputeSelectionResult,
    ComputeSelectionState,
    ComputeType,
    ValidationComputePolicy,
    ValidationComputeProfile,
)
from smf.execution.databricks_compute_schema import validate_databricks_compute_schema
from smf.readiness.manifest import load_manifest as load_readiness_manifest
from smf.readiness.policy import digest_value
from smf.security.admission import has_executable_sas_entrypoint
from smf.strict_yaml import load_unique_yaml

_VERIFIED_OBSERVATION_TOKEN = object()


class VerifiedComputeAvailabilityObservation(ComputeAvailabilityObservation):
    """Marker for an observation verified against deployment-owned authority keys."""

    __slots__ = ()

    def __init__(self, *, _verification_token: object, **values: Any) -> None:
        if _verification_token is not _VERIFIED_OBSERVATION_TOKEN:
            raise ValueError("Compute availability observation lacks verified authority proof")
        super().__init__(**values)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def profile_from_dict(value: Mapping[str, Any]) -> ValidationComputeProfile:
    expected = {
        "profile_id",
        "priority",
        "compute_type",
        "access_mode",
        "dbr_version",
        "spark_version",
        "scala_version",
        "jvm_version",
        "node_type",
        "min_workers",
        "max_workers",
        "max_concurrent_workloads",
        "max_cost_usd",
        "max_runtime_seconds",
        "max_retries",
        "cancellation_deadline_seconds",
        "forced_termination_deadline_seconds",
        "network_policy_id",
        "source_scope_id",
        "output_scope_id",
        "target",
        "workload_class",
        "single_workload_isolation",
    }
    if set(value) != expected:
        raise ValueError("Compute profile has unknown or missing fields")
    try:
        return ValidationComputeProfile(
            **{
                **dict(value),
                "compute_type": ComputeType(value["compute_type"]),
                "access_mode": AccessMode(value["access_mode"]),
            }
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid validation compute profile") from exc


def compute_policy_from_dict(value: Mapping[str, Any]) -> ValidationComputePolicy:
    expected = {
        "schema_version",
        "policy_id",
        "policy_version",
        "policy_state",
        "client_id",
        "deployment_id",
        "environment_id",
        "workspace_binding_id",
        "authority_ref",
        "authority_key_id",
        "authority_signature",
        "valid_from",
        "valid_until",
        "supersedes_policy_digest",
        "owner_requirement_refs",
        "max_availability_age_seconds",
        "profiles",
        "policy_digest",
    }
    if set(value) != expected or not isinstance(value.get("profiles"), list):
        raise ValueError("Compute policy has unknown or missing fields")
    validate_databricks_compute_schema("databricks-compute-policy.schema.json", dict(value))
    owner_refs = value.get("owner_requirement_refs")
    if not isinstance(owner_refs, list):
        raise ValueError("Compute policy owner requirements must be an array")
    try:
        return ValidationComputePolicy(
            **{
                **dict(value),
                "policy_state": ComputePolicyState(value["policy_state"]),
                "owner_requirement_refs": tuple(owner_refs),
                "profiles": tuple(profile_from_dict(item) for item in value["profiles"]),
            }
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid validation compute policy") from exc


def verify_compute_policy_authority(
    policy: ValidationComputePolicy,
    *,
    authority_keys: Mapping[str, Ed25519PublicKey],
    allowed_authorities: tuple[str, ...],
    allowed_key_ids: tuple[str, ...],
) -> None:
    """Verify an active policy against independently governed approval trust roots."""

    if policy.policy_state is not ComputePolicyState.ACTIVE:
        return
    if (
        policy.authority_ref not in allowed_authorities
        or policy.authority_key_id not in allowed_key_ids
        or policy.authority_key_id not in authority_keys
        or policy.authority_signature is None
    ):
        raise ValueError("Active compute policy authority is untrusted")
    try:
        signature = base64.b64decode(policy.authority_signature, validate=True)
        authority_keys[policy.authority_key_id].verify(
            signature, _canonical(policy.authority_bindings())
        )
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("Active compute policy authority proof is invalid") from exc


def load_compute_policy(path: Path) -> tuple[ValidationComputePolicy, bytes]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Compute policy must be a regular deployment file")
    raw = path.read_bytes()
    try:
        value = load_unique_yaml(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid validation compute policy YAML") from exc
    if not isinstance(value, dict):
        raise ValueError("Validation compute policy must be an object")
    return compute_policy_from_dict(value), raw


def _policy_from_snapshot(
    snapshot: DeploymentSnapshot,
) -> tuple[ValidationComputePolicy, bytes]:
    require_validated_deployment_snapshot(snapshot)
    entries = [
        (item, raw)
        for item, raw in zip(snapshot.file_inventory, snapshot.snapshot_bytes, strict=True)
        if item["path"] == "compute-policy.yaml"
    ]
    if len(entries) != 1:
        raise ValueError("Deployment snapshot lacks one governed compute policy")
    item, raw = entries[0]
    try:
        payload = load_unique_yaml(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Deployment snapshot compute policy is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("Deployment snapshot compute policy is invalid")
    policy = compute_policy_from_dict(payload)
    if (
        hashlib.sha256(raw).hexdigest() != item["sha256"]
        or policy.policy_digest != snapshot.compute_policy_digest
        or policy.policy_state.value != snapshot.compute_policy_state
    ):
        raise ValueError("Deployment snapshot compute policy binding is invalid")
    return policy, raw


def availability_observation_from_dict(
    value: Mapping[str, Any],
) -> ComputeAvailabilityObservation:
    expected = {
        "schema_version",
        "observation_id",
        "authority_ref",
        "observed_at",
        "expires_at",
        "provider_version",
        "workspace_binding_id",
        "profile_id",
        "state",
        "quota_limit",
        "quota_used",
        "observation_digest",
    }
    if set(value) != expected:
        raise ValueError("Availability observation has unknown or missing fields")
    validate_databricks_compute_schema("databricks-compute-availability.schema.json", dict(value))
    try:
        return ComputeAvailabilityObservation(
            **{**dict(value), "state": AvailabilityState(value["state"])}
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid compute availability observation") from exc


def verify_availability_observation(
    observation: ComputeAvailabilityObservation,
    *,
    key_id: str,
    signature: str,
    authority_keys: Mapping[str, Ed25519PublicKey],
    allowed_authorities: tuple[str, ...] | None = None,
    allowed_key_ids: tuple[str, ...] | None = None,
) -> VerifiedComputeAvailabilityObservation:
    """Verify provider evidence; an observation object or `available` boolean is not authority."""

    key = authority_keys.get(key_id)
    if (
        key is None
        or (
            allowed_authorities is not None and observation.authority_ref not in allowed_authorities
        )
        or (allowed_key_ids is not None and key_id not in allowed_key_ids)
    ):
        raise ValueError("Compute availability authority is untrusted")
    try:
        key.verify(base64.b64decode(signature, validate=True), _canonical(observation.bindings()))
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("Compute availability proof is invalid") from exc
    verified_values = dict(observation.__dict__)
    verified_values.update(
        verification_key_id=key_id,
        verification_signature=signature,
    )
    return VerifiedComputeAvailabilityObservation(
        _verification_token=_VERIFIED_OBSERVATION_TOKEN,
        **verified_values,
    )


def _availability_authority_roots(
    snapshot: DeploymentSnapshot,
) -> tuple[dict[str, Ed25519PublicKey], tuple[str, ...], tuple[str, ...]]:
    """Load provider-observation trust roots only from the sealed deployment snapshot."""

    require_validated_deployment_snapshot(snapshot)
    policy = snapshot.readiness.policy
    authorities = policy.evidence_authorities.get("environment", ())
    key_ids = policy.evidence_key_ids.get("environment", ())
    if not authorities or not key_ids:
        raise ValueError("Deployment lacks governed compute availability authority roots")
    try:
        keys = {
            key_id: Ed25519PublicKey.from_public_bytes(
                base64.b64decode(policy.verification_keys[key_id], validate=True)
            )
            for key_id in key_ids
        }
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("Deployment compute availability authority roots are invalid") from exc
    return keys, authorities, key_ids


def _reverify_selection_observation(
    observation: ComputeAvailabilityObservation,
    *,
    deployment_snapshot: DeploymentSnapshot,
) -> VerifiedComputeAvailabilityObservation:
    """Detach, reconstruct, digest-check, and authorize exact provider evidence."""

    # The JSON round trip is the durable boundary. No marker, subclass, or live
    # dataclass field is trusted after this point.
    serialized = json.loads(_canonical(observation.bindings()))
    if not isinstance(serialized, dict):
        raise ValueError("Compute availability observation is not serializable")
    reconstructed = availability_observation_from_dict(serialized)
    key_id = observation.verification_key_id
    signature = observation.verification_signature
    if not isinstance(key_id, str) or not isinstance(signature, str):
        raise ValueError("Compute availability observation lacks provider proof")
    keys, authorities, key_ids = _availability_authority_roots(deployment_snapshot)
    return verify_availability_observation(
        reconstructed,
        key_id=key_id,
        signature=signature,
        authority_keys=keys,
        allowed_authorities=authorities,
        allowed_key_ids=key_ids,
    )


def build_compute_selection_request(
    *,
    source_bytes: bytes,
    generated_bytes: bytes,
    deployment_snapshot: DeploymentSnapshot,
    observation: ComputeAvailabilityObservation | None,
    readiness_manifest_path: Path,
    workload_id: str,
    workload_digest: str,
    boundary_id: str,
    subject_id: str,
    executable_entrypoint_id: str,
    qualified_snapshot_ref: str,
    source_closure_digest: str,
    target: str,
    workload_class: str,
    run_id: str,
    workflow_attempt_id: str,
    selection_attempt_id: str,
    evaluated_at: str,
    requested_profile_id: str | None = None,
) -> ComputeSelectionRequest:
    if not has_executable_sas_entrypoint(source_bytes):
        raise ValueError("Qualified source has no executable SAS entry point")
    if not generated_bytes.strip():
        raise ValueError("Generated target must contain meaningful bytes")
    recorded_policy, policy_bytes = _policy_from_snapshot(deployment_snapshot)
    binding_by_role = {item["role"]: item for item in deployment_snapshot.bindings}
    workspace_binding_id = binding_by_role["workspace"]["binding_id"]
    client_id = deployment_snapshot.client_id
    deployment_id = deployment_snapshot.deployment_id
    environment_id = deployment_snapshot.environment_id
    configuration_digest = deployment_snapshot.configuration_digest
    bundle_digest = deployment_snapshot.bundle_digest
    readiness = load_readiness_manifest(readiness_manifest_path)
    artifacts = readiness["qualification_input"]["workload"].get("artifacts", [])
    matches = [item for item in artifacts if item.get("artifact_id") == subject_id]
    snapshots = [
        item.get("snapshot_uri")
        for item in readiness["evidence_references"]
        if item.get("kind") == "discovery_snapshot" and item.get("snapshot_uri")
    ]
    binding = readiness["policy_snapshot"].get("prerequisite_binding")
    readiness_matches = (
        readiness["classification"] == "READY"
        and readiness["workload_id"] == workload_id
        and readiness["run_id"] == run_id
        and readiness["attempt_id"] == workflow_attempt_id
        and readiness["boundary_id"] == boundary_id
        and readiness["workload_digest"] == workload_digest
        and isinstance(binding, dict)
        and binding.get("client_id") == client_id
        and binding.get("deployment_id") == deployment_id
        and binding.get("environment_id") == environment_id
        and binding.get("configuration_digest") == configuration_digest
        and len(matches) == 1
        and matches[0].get("checksum") == hashlib.sha256(source_bytes).hexdigest()
        and snapshots == [qualified_snapshot_ref]
    )
    if not readiness_matches:
        raise ValueError("Governed readiness manifest does not match compute subject")
    return ComputeSelectionRequest(
        schema_version="1.0",
        client_id=client_id,
        deployment_id=deployment_id,
        environment_id=environment_id,
        workspace_binding_id=workspace_binding_id,
        workload_id=workload_id,
        workload_digest=workload_digest,
        boundary_id=boundary_id,
        subject_id=subject_id,
        executable_entrypoint_id=executable_entrypoint_id,
        qualified_snapshot_ref=qualified_snapshot_ref,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        source_closure_digest=source_closure_digest,
        generated_sha256=hashlib.sha256(generated_bytes).hexdigest(),
        configuration_digest=configuration_digest,
        bundle_digest=bundle_digest,
        readiness_result_id=readiness["result_id"],
        readiness_manifest_digest=readiness["content_digest"],
        readiness_policy_id=readiness["policy_id"],
        readiness_policy_version=readiness["policy_version"],
        readiness_policy_digest=readiness["policy_digest"],
        readiness_activation_authority_ref=recorded_policy.authority_ref or "unresolved",
        readiness_manifest=readiness,
        target=target,
        workload_class=workload_class,
        run_id=run_id,
        workflow_attempt_id=workflow_attempt_id,
        selection_attempt_id=selection_attempt_id,
        policy_id=recorded_policy.policy_id,
        policy_version=recorded_policy.policy_version,
        policy_digest=recorded_policy.policy_digest,
        policy_bytes_sha256=hashlib.sha256(policy_bytes).hexdigest(),
        policy_snapshot=recorded_policy.bindings(),
        observation_id=observation.observation_id if observation else None,
        observation_digest=observation.observation_digest if observation else None,
        requested_profile_id=requested_profile_id,
        evaluated_at=evaluated_at,
    )


def _result(
    request: ComputeSelectionRequest,
    state: ComputeSelectionState,
    reason: str,
    profile: ValidationComputeProfile | None = None,
    observation: ComputeAvailabilityObservation | None = None,
    *,
    observation_payload: dict[str, Any] | None = None,
    observation_proof: dict[str, str] | None = None,
) -> ComputeSelectionResult:
    if observation is not None and (
        observation_payload is not None or observation_proof is not None
    ):
        raise ValueError("Compute result observation has multiple sources")
    if observation_payload is None and observation_proof is not None:
        raise ValueError("Compute result observation and proof must be recorded together")
    recorded_observation = observation.bindings() if observation else observation_payload
    recorded_proof = (
        None
        if observation
        and observation.verification_key_id is None
        and observation.verification_signature is None
        else {
            "key_id": observation.verification_key_id or "",
            "signature": observation.verification_signature or "",
        }
        if observation
        else observation_proof
    )
    effective = profile.bindings() if profile else None
    unsigned = ComputeSelectionResult(
        schema_version="1.0",
        request=request.bindings(),
        request_digest=request.request_digest,
        selection_request_id=request.selection_request_id,
        selection_attempt_id=request.selection_attempt_id,
        decision_id=request.decision_id,
        state=state,
        reason_code=reason,
        selected_profile_id=profile.profile_id if profile else None,
        effective_profile=effective,
        effective_profile_digest=profile.profile_digest if profile else None,
        evaluated_at=request.evaluated_at,
        availability_observation=recorded_observation,
        availability_proof=recorded_proof,
        evidence_refs=(
            request.qualified_snapshot_ref,
            request.readiness_result_id,
            request.policy_digest,
            request.observation_digest or "missing:availability",
        ),
        retryable=state
        in {
            ComputeSelectionState.QUOTA_EXHAUSTED,
            ComputeSelectionState.ALLOCATION_UNAVAILABLE,
        },
        blocked=state is not ComputeSelectionState.SELECTED_OFFLINE,
    )
    payload = unsigned.to_dict()
    payload["content_digest"] = ""
    return ComputeSelectionResult(**{**unsigned.__dict__, "content_digest": digest_value(payload)})


def _governed_readiness_matches(
    request: ComputeSelectionRequest, readiness: dict[str, Any]
) -> bool:
    """Apply the complete governed-readiness binding for selection and durable replay."""

    readiness_unsigned = dict(readiness)
    readiness_content_digest = readiness_unsigned.pop("content_digest", None)
    readiness_binding = readiness.get("policy_snapshot", {}).get("prerequisite_binding")
    return bool(
        readiness_content_digest == digest_value(readiness_unsigned)
        and readiness_content_digest == request.readiness_manifest_digest
        and readiness.get("result_id") == request.readiness_result_id
        and readiness.get("policy_id") == request.readiness_policy_id
        and readiness.get("policy_version") == request.readiness_policy_version
        and readiness.get("policy_digest") == request.readiness_policy_digest
        and readiness.get("classification") == "READY"
        and readiness.get("workload_id") == request.workload_id
        and readiness.get("workload_digest") == request.workload_digest
        and readiness.get("boundary_id") == request.boundary_id
        and readiness.get("run_id") == request.run_id
        and readiness.get("attempt_id") == request.workflow_attempt_id
        and isinstance(readiness_binding, dict)
        and readiness_binding.get("client_id") == request.client_id
        and readiness_binding.get("deployment_id") == request.deployment_id
        and readiness_binding.get("environment_id") == request.environment_id
        and readiness_binding.get("configuration_digest") == request.configuration_digest
    )


def select_validation_compute(
    request: ComputeSelectionRequest,
    observation: ComputeAvailabilityObservation | None,
    *,
    deployment_snapshot: DeploymentSnapshot,
    readiness_manifest_path: Path,
) -> ComputeSelectionResult:
    """Select one bounded profile without allocation or provider submission."""

    try:
        recorded_policy, policy_bytes = _policy_from_snapshot(deployment_snapshot)
        governed_readiness = load_readiness_manifest(readiness_manifest_path)
    except (UnicodeDecodeError, ValueError):
        return _result(request, ComputeSelectionState.INVALID_BINDING, "governed_evidence_invalid")
    verified_observation: VerifiedComputeAvailabilityObservation | None = None
    if observation is not None:
        try:
            verified_observation = _reverify_selection_observation(
                observation, deployment_snapshot=deployment_snapshot
            )
        except (TypeError, ValueError):
            return _result(
                request,
                ComputeSelectionState.INVALID_BINDING,
                "availability_untrusted",
                observation_payload=observation.bindings(),
                observation_proof=(
                    None
                    if observation.verification_key_id is None
                    and observation.verification_signature is None
                    else {
                        "key_id": observation.verification_key_id or "",
                        "signature": observation.verification_signature or "",
                    }
                ),
            )
    if (
        hashlib.sha256(policy_bytes).hexdigest() != request.policy_bytes_sha256
        or recorded_policy.bindings() != request.policy_snapshot
        or governed_readiness != request.readiness_manifest
    ):
        return _result(request, ComputeSelectionState.INVALID_BINDING, "governed_evidence_mismatch")
    try:
        now = datetime.fromisoformat(request.evaluated_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return _result(request, ComputeSelectionState.INVALID_BINDING, "evaluation_time_invalid")
    if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
        return _result(request, ComputeSelectionState.INVALID_BINDING, "evaluation_time_invalid")
    if not _governed_readiness_matches(request, request.readiness_manifest):
        return _result(
            request, ComputeSelectionState.INVALID_BINDING, "readiness_evidence_mismatch"
        )
    policy = recorded_policy
    bindings_match = (
        request.policy_id == policy.policy_id
        and request.policy_version == policy.policy_version
        and request.policy_digest == policy.policy_digest
        and request.client_id == policy.client_id
        and request.deployment_id == policy.deployment_id
        and request.environment_id == policy.environment_id
        and request.workspace_binding_id == policy.workspace_binding_id
        and (
            verified_observation is None
            or (
                request.observation_id == verified_observation.observation_id
                and request.observation_digest == verified_observation.observation_digest
                and verified_observation.workspace_binding_id == policy.workspace_binding_id
            )
        )
    )
    if not bindings_match:
        return _result(request, ComputeSelectionState.INVALID_BINDING, "compute_evidence_mismatch")
    if policy.policy_state is ComputePolicyState.PENDING:
        return _result(request, ComputeSelectionState.BLOCKED_PENDING, "policy_pending")
    if policy.policy_state is ComputePolicyState.DENIED:
        return _result(request, ComputeSelectionState.DENIED, "policy_denied")
    if policy.policy_state is not ComputePolicyState.ACTIVE:
        return _result(request, ComputeSelectionState.EXPIRED, "policy_superseded")
    if policy.max_availability_age_seconds is None:
        return _result(request, ComputeSelectionState.INVALID_BINDING, "freshness_policy_missing")
    if policy.valid_from is None or policy.valid_until is None:
        return _result(request, ComputeSelectionState.INVALID_BINDING, "validity_policy_missing")
    if now < datetime.fromisoformat(
        policy.valid_from.replace("Z", "+00:00")
    ) or now >= datetime.fromisoformat(policy.valid_until.replace("Z", "+00:00")):
        return _result(request, ComputeSelectionState.EXPIRED, "policy_expired")
    if verified_observation is None:
        return _result(request, ComputeSelectionState.BLOCKED_MISSING, "availability_missing")
    observation = verified_observation
    if now < datetime.fromisoformat(
        observation.observed_at.replace("Z", "+00:00")
    ) or now >= datetime.fromisoformat(observation.expires_at.replace("Z", "+00:00")):
        return _result(
            request,
            ComputeSelectionState.EXPIRED,
            "availability_expired",
            observation=observation,
        )
    observed_at = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
    if (now - observed_at).total_seconds() > policy.max_availability_age_seconds:
        return _result(
            request,
            ComputeSelectionState.EXPIRED,
            "availability_stale",
            observation=observation,
        )
    state_map = {
        AvailabilityState.PENDING: (ComputeSelectionState.BLOCKED_PENDING, "availability_pending"),
        AvailabilityState.DENIED: (ComputeSelectionState.DENIED, "compute_denied"),
        AvailabilityState.QUOTA_EXHAUSTED: (
            ComputeSelectionState.QUOTA_EXHAUSTED,
            "quota_exhausted",
        ),
        AvailabilityState.ALLOCATION_UNAVAILABLE: (
            ComputeSelectionState.ALLOCATION_UNAVAILABLE,
            "allocation_unavailable",
        ),
        AvailabilityState.INCOMPATIBLE_RUNTIME: (
            ComputeSelectionState.INCOMPATIBLE_RUNTIME,
            "incompatible_runtime",
        ),
        AvailabilityState.PROVIDER_UNAVAILABLE: (
            ComputeSelectionState.ALLOCATION_UNAVAILABLE,
            "provider_unavailable",
        ),
    }
    if observation.state is not AvailabilityState.AVAILABLE:
        state, reason = state_map[observation.state]
        return _result(request, state, reason, observation=observation)
    matches = [
        item
        for item in policy.profiles
        if item.target == request.target
        and item.workload_class == request.workload_class
        and (
            request.requested_profile_id is None or item.profile_id == request.requested_profile_id
        )
    ]
    if not matches:
        return _result(
            request,
            ComputeSelectionState.INCOMPATIBLE_RUNTIME,
            "no_compatible_profile",
            observation=observation,
        )
    matches.sort(key=lambda item: item.priority)
    profile = matches[0]
    if observation.profile_id != profile.profile_id:
        return _result(
            request,
            ComputeSelectionState.INVALID_BINDING,
            "availability_profile_mismatch",
            observation=observation,
        )
    if observation.quota_used >= observation.quota_limit:
        return _result(
            request,
            ComputeSelectionState.QUOTA_EXHAUSTED,
            "quota_exhausted",
            observation=observation,
        )
    return _result(
        request,
        ComputeSelectionState.SELECTED_OFFLINE,
        "selected_offline",
        profile,
        observation,
    )


def verify_compute_admission(
    result: ComputeSelectionResult,
    *,
    request: ComputeSelectionRequest,
    source_bytes: bytes,
    generated_bytes: bytes,
    deployment_snapshot: DeploymentSnapshot,
    readiness_manifest_path: Path,
) -> None:
    """Reverify qualified identities and immutable bytes immediately before downstream use."""

    verify_compute_result(
        result,
        request=request,
        source_bytes=source_bytes,
        generated_bytes=generated_bytes,
        deployment_snapshot=deployment_snapshot,
        readiness_manifest_path=readiness_manifest_path,
    )
    if result.state is not ComputeSelectionState.SELECTED_OFFLINE:
        raise ValueError("Databricks compute admission evidence is stale or invalid")


def verify_compute_result(
    result: ComputeSelectionResult,
    *,
    request: ComputeSelectionRequest,
    source_bytes: bytes,
    generated_bytes: bytes,
    deployment_snapshot: DeploymentSnapshot,
    readiness_manifest_path: Path,
) -> None:
    """Independently reverify and reproduce any durable compute result."""

    payload = result.to_dict()
    content_digest = payload.pop("content_digest")
    payload["content_digest"] = ""
    try:
        policy, policy_bytes = _policy_from_snapshot(deployment_snapshot)
        governed_readiness = load_readiness_manifest(readiness_manifest_path)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Databricks compute admission evidence is stale or invalid") from exc
    if (
        content_digest != digest_value(payload)
        or result.request != request.bindings()
        or result.request_digest != request.request_digest
        or result.decision_id != request.decision_id
        or hashlib.sha256(source_bytes).hexdigest() != request.source_sha256
        or hashlib.sha256(generated_bytes).hexdigest() != request.generated_sha256
        or hashlib.sha256(policy_bytes).hexdigest() != request.policy_bytes_sha256
        or policy.bindings() != request.policy_snapshot
        or deployment_snapshot.configuration_digest != request.configuration_digest
        or deployment_snapshot.bundle_digest != request.bundle_digest
        or governed_readiness != request.readiness_manifest
    ):
        raise ValueError("Databricks compute admission evidence is stale or invalid")
    untrusted_result = (
        result.state is ComputeSelectionState.INVALID_BINDING
        and result.reason_code == "availability_untrusted"
    )
    if (result.availability_observation is None) != (result.availability_proof is None) and not (
        untrusted_result
        and result.availability_observation is not None
        and result.availability_proof is None
    ):
        raise ValueError("Databricks compute admission evidence is stale or invalid")
    if untrusted_result:
        if result.availability_observation is None:
            raise ValueError("Databricks compute admission evidence is stale or invalid")
        if not _governed_readiness_matches(request, governed_readiness):
            raise ValueError("Databricks compute admission evidence is stale or invalid")
        raw_observation = result.availability_observation
        raw_proof = result.availability_proof
        if (
            raw_observation.get("observation_id") != request.observation_id
            or raw_observation.get("observation_digest") != request.observation_digest
        ):
            raise ValueError("Databricks compute admission evidence is stale or invalid")
        if raw_proof is not None:
            try:
                reconstructed = availability_observation_from_dict(raw_observation)
                reconstructed = replace(
                    reconstructed,
                    verification_key_id=raw_proof.get("key_id"),
                    verification_signature=raw_proof.get("signature"),
                )
                _reverify_selection_observation(
                    reconstructed, deployment_snapshot=deployment_snapshot
                )
            except (TypeError, ValueError):
                pass
            else:
                raise ValueError("Databricks compute admission evidence is stale or invalid")
        reproduced_untrusted = _result(
            request,
            ComputeSelectionState.INVALID_BINDING,
            "availability_untrusted",
            observation_payload=raw_observation,
            observation_proof=raw_proof,
        )
        if reproduced_untrusted != result:
            raise ValueError("Databricks compute admission evidence is stale or invalid")
        return
    observation = (
        verify_result_availability(result, deployment_snapshot=deployment_snapshot)
        if result.availability_observation is not None
        else None
    )
    reproduced = select_validation_compute(
        request,
        observation,
        deployment_snapshot=deployment_snapshot,
        readiness_manifest_path=readiness_manifest_path,
    )
    if reproduced != result:
        raise ValueError("Databricks compute admission evidence is stale or invalid")


def verify_result_availability(
    result: ComputeSelectionResult,
    *,
    authority_keys: Mapping[str, Ed25519PublicKey] | None = None,
    deployment_snapshot: DeploymentSnapshot | None = None,
) -> VerifiedComputeAvailabilityObservation:
    """Reverify the exact provider observation retained in durable result evidence."""

    if result.availability_observation is None or result.availability_proof is None:
        raise ValueError("Compute result lacks provider availability evidence")
    observation = availability_observation_from_dict(result.availability_observation)
    allowed_authorities: tuple[str, ...] | None = None
    allowed_key_ids: tuple[str, ...] | None = None
    if deployment_snapshot is not None:
        if authority_keys is not None:
            raise ValueError("Compute availability roots must have one governed source")
        authority_keys, allowed_authorities, allowed_key_ids = _availability_authority_roots(
            deployment_snapshot
        )
    if authority_keys is None:
        raise ValueError("Compute availability authority roots are missing")
    return verify_availability_observation(
        observation,
        key_id=result.availability_proof.get("key_id", ""),
        signature=result.availability_proof.get("signature", ""),
        authority_keys=authority_keys,
        allowed_authorities=allowed_authorities,
        allowed_key_ids=allowed_key_ids,
    )
