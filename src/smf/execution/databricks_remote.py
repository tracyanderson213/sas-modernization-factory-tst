"""Governed DBX-01 remote-execution boundary.

The production path is deliberately default-deny: it fully reverifies CV-04,
DBPKG-01, DBX-02 and DBX-03 evidence and emits an immutable blocked plan until a
separate live-execution authority is available.  A synthetic transport exerciser
proves submit/poll/cancel semantics without creating live-execution evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from smf.conversion.provider_package import ProviderPackageRequest, verify_provider_package
from smf.deployment.configuration import DeploymentSnapshot
from smf.execution.databricks_auth_manifest import load_authentication_result
from smf.execution.databricks_auth_models import (
    DatabricksAuthenticationRequest,
    DatabricksAuthenticationState,
)
from smf.execution.databricks_compute import verify_compute_admission
from smf.execution.databricks_compute_models import ComputeSelectionRequest, ComputeSelectionResult
from smf.immutable_files import publish_json, published_file_exists, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.unity_catalog_validation import (
    CurrentIngestionEvidence,
    CurrentTargetMappingEvidence,
    UnityCatalogValidationPolicy,
    UnityCatalogValidationRequest,
    verify_unity_catalog_validation_against_inputs,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _safe(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or contains_protected_data(value):
        raise ValueError(f"Unsafe DBX-01 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"DBX-01 {label} is not a SHA-256 digest")
    return value


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"DBX-01 {label} is not canonical RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"DBX-01 {label} is not canonical RFC3339 UTC")
    return parsed


@dataclass(frozen=True)
class RemoteExecutionRequest:
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    source_artifact_id: str
    source_sha256: str
    generated_sha256: str
    package_id: str
    package_digest: str
    catalog_plan_id: str
    catalog_plan_digest: str
    authentication_result_id: str
    authentication_content_digest: str
    compute_result_id: str
    compute_content_digest: str
    evaluation_time: str
    timeout_seconds: int = 900
    max_poll_attempts: int = 30

    def binding(self) -> dict[str, Any]:
        for name in (
            "client_id",
            "deployment_id",
            "environment_id",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "source_artifact_id",
            "package_id",
            "catalog_plan_id",
            "authentication_result_id",
            "compute_result_id",
        ):
            _safe(getattr(self, name), name)
        for name in (
            "source_sha256",
            "generated_sha256",
            "package_digest",
            "catalog_plan_digest",
            "authentication_content_digest",
            "compute_content_digest",
        ):
            _sha(getattr(self, name), name)
        _time(self.evaluation_time, "evaluation_time")
        if not 1 <= self.timeout_seconds <= 86_400 or not 1 <= self.max_poll_attempts <= 1_000:
            raise ValueError("DBX-01 timeout or poll bound is invalid")
        return asdict(self)


@dataclass(frozen=True)
class CurrentRemoteEvidence:
    package_manifest_path: Path
    package_request: ProviderPackageRequest
    catalog_result_path: Path
    catalog_request: UnityCatalogValidationRequest
    catalog_policy: UnityCatalogValidationPolicy
    target_mapping_evidence: CurrentTargetMappingEvidence
    ingestion_evidence: CurrentIngestionEvidence
    catalog_output_root: Path
    authentication_result_path: Path
    authentication_request: DatabricksAuthenticationRequest
    authentication_verification_keys: Mapping[str, Ed25519PublicKey]
    compute_result: ComputeSelectionResult
    compute_request: ComputeSelectionRequest
    compute_source_bytes: bytes
    compute_generated_bytes: bytes
    deployment_snapshot: DeploymentSnapshot
    readiness_manifest_path: Path


@dataclass(frozen=True)
class SyntheticScenario:
    """Internally evaluated, non-network scenario for adapter state-machine tests."""

    submission_outcome: Literal["accepted", "lost_response"]
    poll_states: tuple[str, ...] = ()
    poll_elapsed_seconds: tuple[int, ...] = ()
    cancellation_outcome: Literal["cancelled", "unknown"] = "cancelled"

    def validate(self) -> None:
        if self.submission_outcome not in {"accepted", "lost_response"}:
            raise ValueError("DBX-01 synthetic submission outcome is invalid")
        if len(self.poll_states) != len(self.poll_elapsed_seconds):
            raise ValueError("DBX-01 synthetic poll state/time cardinality mismatch")
        if any(
            state not in {"queued", "running", "succeeded", "failed", "cancelled", "unknown"}
            for state in self.poll_states
        ):
            raise ValueError("DBX-01 synthetic poll state is invalid")
        if any(not isinstance(value, int) or value < 0 for value in self.poll_elapsed_seconds):
            raise ValueError("DBX-01 synthetic poll time is invalid")
        if tuple(sorted(self.poll_elapsed_seconds)) != self.poll_elapsed_seconds:
            raise ValueError("DBX-01 synthetic poll times must be monotonic")
        if self.cancellation_outcome not in {"cancelled", "unknown"}:
            raise ValueError("DBX-01 synthetic cancellation outcome is invalid")


def _schema() -> dict[str, Any]:
    value = json.loads(
        files("smf.schemas").joinpath("databricks-remote-plan.schema.json").read_text()
    )
    if not isinstance(value, dict):
        raise ValueError("DBX-01 packaged schema is invalid")
    return value


def _manifest() -> list[dict[str, str]]:
    resources = (
        (
            "smf/execution/databricks_remote.py",
            files("smf.execution").joinpath("databricks_remote.py"),
        ),
        (
            "smf/conversion/provider_package.py",
            files("smf.conversion").joinpath("provider_package.py"),
        ),
        ("smf/unity_catalog_validation.py", files("smf").joinpath("unity_catalog_validation.py")),
        (
            "smf/execution/databricks_auth_manifest.py",
            files("smf.execution").joinpath("databricks_auth_manifest.py"),
        ),
        (
            "smf/execution/databricks_compute.py",
            files("smf.execution").joinpath("databricks_compute.py"),
        ),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/databricks-remote-plan.schema.json",
            files("smf.schemas").joinpath("databricks-remote-plan.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _verify_current_inputs(
    request: RemoteExecutionRequest, evidence: CurrentRemoteEvidence
) -> tuple[dict[str, Any], dict[str, Any], Any, ComputeSelectionResult]:
    package = verify_provider_package(evidence.package_manifest_path, evidence.package_request)
    catalog = verify_unity_catalog_validation_against_inputs(
        evidence.catalog_result_path,
        evidence.catalog_request,
        evidence.catalog_policy,
        target_mapping_evidence=evidence.target_mapping_evidence,
        ingestion_evidence=evidence.ingestion_evidence,
        output_root=evidence.catalog_output_root,
    )
    authentication = load_authentication_result(
        evidence.authentication_result_path,
        verification_keys=evidence.authentication_verification_keys,
    )
    if authentication.request != evidence.authentication_request.bindings():
        raise ValueError("DBX-01 authentication evidence is not current-request bound")
    verify_compute_admission(
        evidence.compute_result,
        request=evidence.compute_request,
        source_bytes=evidence.compute_source_bytes,
        generated_bytes=evidence.compute_generated_bytes,
        deployment_snapshot=evidence.deployment_snapshot,
        readiness_manifest_path=evidence.readiness_manifest_path,
    )
    binding = request.binding()
    expected = {
        "client_id": binding["client_id"],
        "deployment_id": binding["deployment_id"],
        "environment_id": binding["environment_id"],
        "workload_id": binding["workload_id"],
        "run_id": binding["run_id"],
        "attempt_id": binding["attempt_id"],
    }
    package_identity = package.get("identity", {})
    package_expected = {
        "client_id": request.client_id,
        "deployment_id": request.deployment_id,
        "environment_id": request.environment_id,
        "workload_id": request.workload_id,
        "source_artifact_id": request.source_artifact_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
    }
    if any(package_identity.get(key) != value for key, value in package_expected.items()):
        raise ValueError("DBX-01 package identity mismatch")
    catalog_expected = {**expected, "source_id": binding["source_id"]}
    if any(catalog["request"].get(k) != v for k, v in catalog_expected.items()):
        raise ValueError("DBX-01 catalog-plan identity mismatch")
    if any(
        catalog["request"].get(key) != binding[key]
        for key in (
            "authentication_result_id",
            "authentication_content_digest",
            "compute_result_id",
            "compute_content_digest",
        )
    ):
        raise ValueError("DBX-01 catalog-plan authority references are stale")
    auth_request = authentication.request
    compute_request = evidence.compute_result.request
    translated = {"attempt_id": "workflow_attempt_id"}
    for key, value in expected.items():
        upstream = translated.get(key, key)
        if auth_request.get(upstream) != value or compute_request.get(upstream) != value:
            raise ValueError(f"DBX-01 upstream {key} mismatch")
    if (
        package.get("source", {}).get("sha256") != request.source_sha256
        or auth_request.get("source_sha256") != request.source_sha256
        or compute_request.get("source_sha256") != request.source_sha256
        or auth_request.get("generated_sha256") != request.generated_sha256
        or compute_request.get("generated_sha256") != request.generated_sha256
        or evidence.catalog_request.evaluation_time != request.evaluation_time
        or evidence.compute_request.evaluated_at != request.evaluation_time
    ):
        raise ValueError("DBX-01 source, generated, or evaluation-time authority mismatch")
    observed = {
        "package_id": package.get("package_id"),
        "package_digest": package.get("content_digest"),
        "catalog_plan_id": catalog.get("result_id"),
        "catalog_plan_digest": catalog.get("content_digest"),
        "authentication_result_id": authentication.authentication_request_id,
        "authentication_content_digest": authentication.content_digest,
        "compute_result_id": evidence.compute_result.selection_request_id,
        "compute_content_digest": evidence.compute_result.content_digest,
    }
    if any(binding[key] != value for key, value in observed.items()):
        raise ValueError("DBX-01 upstream result identity or digest drift")
    if (
        package.get("status") != "packaged"
        or package.get("generated_sha256") != request.generated_sha256
    ):
        raise ValueError("DBX-01 deterministic package is not executable")
    if authentication.state is not DatabricksAuthenticationState.VERIFIED:
        raise ValueError("DBX-01 authentication is not verified")
    return package, catalog, authentication, evidence.compute_result


def prepare_remote_execution_plan(
    request: RemoteExecutionRequest, evidence: CurrentRemoteEvidence
) -> dict[str, Any]:
    package, catalog, authentication, compute = _verify_current_inputs(request, evidence)
    binding = request.binding()
    blockers = [
        "live_remote_execution_authority_required",
        "live_unity_catalog_readback_required",
        "target_specific_submission_details_required",
    ]
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "dbx-01.1.0",
        "result_id": "pending",
        "content_digest": "",
        "request": binding,
        "request_digest": digest_value(binding),
        "upstream": {
            "package_id": package["package_id"],
            "package_digest": package["content_digest"],
            "catalog_plan_id": catalog["result_id"],
            "catalog_plan_digest": catalog["content_digest"],
            "authentication_result_id": authentication.authentication_request_id,
            "authentication_content_digest": authentication.content_digest,
            "compute_result_id": compute.selection_request_id,
            "compute_content_digest": compute.content_digest,
        },
        "submission": {
            "enabled": False,
            "idempotency_key": stable_id("DBXSUB", binding),
            "remote_run_id": None,
            "remote_task_id": None,
        },
        "state": "blocked_external_authority",
        "retry_disposition": "do_not_submit",
        "blockers": blockers,
        "implementation_manifest": _manifest(),
        "claims": {
            "generated": True,
            "submitted": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "human_assisted": False,
            "humana_ready": False,
            "production_ready": False,
            "migration_complete": False,
        },
    }
    result["result_id"] = stable_id(
        "DBX01", {k: v for k, v in result.items() if k not in {"result_id", "content_digest"}}
    )
    result["content_digest"] = digest_value({**result, "content_digest": ""})
    _verify_remote_execution_plan_structure(result)
    return result


def _verify_remote_execution_plan_structure(result: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema()).iter_errors(result), key=lambda item: list(item.path)
    )
    if errors:
        raise ValueError("DBX-01 schema validation failed: " + errors[0].message)
    if result["request_digest"] != digest_value(result["request"]):
        raise ValueError("DBX-01 request digest mismatch")
    decision = {k: v for k, v in result.items() if k not in {"result_id", "content_digest"}}
    if result["result_id"] != stable_id("DBX01", decision) or result[
        "content_digest"
    ] != digest_value({**result, "content_digest": ""}):
        raise ValueError("DBX-01 result integrity mismatch")
    if result["implementation_manifest"] != _manifest() or result["submission"]["enabled"]:
        raise ValueError("DBX-01 implementation or submission boundary mismatch")
    if any(value for key, value in result["claims"].items() if key != "generated"):
        raise ValueError("DBX-01 unauthorized execution claim")


def verify_remote_execution_plan(
    result: dict[str, Any], request: RemoteExecutionRequest, evidence: CurrentRemoteEvidence
) -> None:
    """Replay current governed inputs; structural integrity alone is never authority."""
    _verify_remote_execution_plan_structure(result)
    if result != prepare_remote_execution_plan(request, evidence):
        raise ValueError("DBX-01 result differs from current governed inputs")


def publish_remote_execution_plan(
    result: dict[str, Any],
    request: RemoteExecutionRequest,
    evidence: CurrentRemoteEvidence,
    *,
    output_root: Path,
) -> Path:
    verify_remote_execution_plan(result, request, evidence)
    path = (
        output_root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "dbx01"
        / "result.json"
    )
    if published_file_exists(path, root=output_root, label="DBX-01 plan"):
        raise FileExistsError("DBX-01 plan is already published for this attempt")
    publish_json(path, result, "DBX-01 plan", root=output_root)
    observed = read_published_json(path, root=output_root, label="DBX-01 plan")
    if observed != result:
        raise ValueError("DBX-01 publication replay mismatch")
    return path


SyntheticState = Literal["succeeded", "failed", "cancelled", "outcome_unknown"]


def exercise_synthetic_transport(
    request: RemoteExecutionRequest, scenario: SyntheticScenario
) -> dict[str, Any]:
    """Exercise adapter semantics; returned evidence is never live authority."""
    if not isinstance(scenario, SyntheticScenario):
        raise ValueError("DBX-01 accepts only an internally owned synthetic scenario")
    scenario.validate()
    binding = request.binding()
    key = stable_id("DBXSUB", binding)
    if scenario.submission_outcome == "lost_response":
        return {
            "evidence_class": "synthetic_contract",
            "state": "outcome_unknown",
            "retry_allowed": False,
            "remote_run_id": None,
            "remote_task_id": None,
            "polls": 0,
            "cancel_attempted": False,
            "claims": {"submitted": False, "executed": False},
        }
    remote_run_id = stable_id("DBXRUN", {"idempotency_key": key})
    remote_task_id = stable_id("DBXTASK", {"idempotency_key": key, "ordinal": 1})
    terminal: SyntheticState | None = None
    polls = 0
    for poll_ordinal, (state, elapsed) in enumerate(
        zip(scenario.poll_states, scenario.poll_elapsed_seconds, strict=True), start=1
    ):
        if poll_ordinal > request.max_poll_attempts:
            break
        polls = poll_ordinal
        if elapsed >= request.timeout_seconds:
            break
        if state in {"succeeded", "failed", "cancelled"}:
            terminal = cast(SyntheticState, state)
            break
        if state == "unknown":
            terminal = "outcome_unknown"
            break
    cancelled = False
    if terminal is None:
        cancelled = True
        terminal = (
            "cancelled" if scenario.cancellation_outcome == "cancelled" else "outcome_unknown"
        )
    return {
        "evidence_class": "synthetic_contract",
        "state": terminal,
        "retry_allowed": terminal in {"failed", "cancelled"},
        "remote_run_id": remote_run_id,
        "remote_task_id": remote_task_id,
        "polls": polls,
        "cancel_attempted": cancelled,
        "claims": {"submitted": False, "executed": False},
    }


__all__ = [
    "CurrentRemoteEvidence",
    "RemoteExecutionRequest",
    "SyntheticScenario",
    "exercise_synthetic_transport",
    "prepare_remote_execution_plan",
    "publish_remote_execution_plan",
    "verify_remote_execution_plan",
]
