"""Offline evaluator for the migration CLI contract scaffold."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from smf.migration_contract.configuration import (
    acquire_configuration_manifest,
    acquire_request_artifacts,
)
from smf.migration_contract.models import (
    MigrationCommand,
    MigrationContractRequest,
    PreparedMigrationResult,
)
from smf.migration_contract.schema import validate_schema
from smf.migration_contract.source import acquire_source_snapshot
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PROTECTED_ID = re.compile(r"(?i)(secret-canary|phi-canary|pii-canary|password|bearer|token)")


def _safe_id(value: str | None, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value) or _PROTECTED_ID.search(value):
        raise ValueError(f"{label} is missing or unsafe")
    return value


def _content_digest(payload: dict[str, Any]) -> str:
    material = {key: value for key, value in payload.items() if key != "content_digest"}
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def evaluate_migration_contract(request: MigrationContractRequest) -> PreparedMigrationResult:
    run_id = _safe_id(request.run_id, "run_id")
    attempt_id = _safe_id(request.attempt_id, "attempt_id", nullable=True)
    workload_id = _safe_id(request.workload_id, "workload_id", nullable=True)
    action_target = _safe_id(request.action_target, "action target", nullable=True)
    validate_schema(
        "migration-cli-request.schema.json",
        {
            "schema_version": "1.0",
            "command": request.command.value,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "workload_id": workload_id,
        },
    )

    source: dict[str, Any] | None = None
    configuration: dict[str, Any] | None = None
    deployment_identity: dict[str, str] | None = None
    request_artifacts: list[dict[str, Any]] = []
    request_artifact_bundle_digest: str | None = None
    blockers: list[dict[str, str]] = []
    source_commands = {MigrationCommand.CONVERT, MigrationCommand.MODERNIZE}
    configuration_commands = source_commands | {
        MigrationCommand.RESUME,
        MigrationCommand.AI_GATEWAY_PREFLIGHT,
    }
    required_roles = {
        MigrationCommand.CONVERT: {
            "gateway_configuration",
            "asset_policy",
            "type_policy",
            "validation_policy",
        },
        MigrationCommand.MODERNIZE: {
            "gateway_configuration",
            "asset_policy",
            "type_policy",
            "validation_policy",
            "modernization_policy",
        },
        MigrationCommand.EXCEPTIONS_SUBMIT: {"exception_request"},
        MigrationCommand.EXCEPTIONS_DECIDE: {"exception_decision"},
        MigrationCommand.APPROVE: {"approval_evidence"},
        MigrationCommand.PROMOTE: {"promotion_approval"},
        MigrationCommand.AI_GATEWAY_PREFLIGHT: {"gateway_configuration"},
    }.get(request.command, set())
    observed_roles = {role for role, _ in request.role_paths}
    if observed_roles != required_roles or len(observed_roles) != len(request.role_paths):
        raise ValueError("Command configuration roles are missing, extra, or duplicate")

    if request.command in source_commands:
        if request.source_root is None or request.workload_config is None or workload_id is None:
            raise ValueError(
                "Migration admission requires source, workload configuration, and workload"
            )
        source = acquire_source_snapshot(request.source_root, request.workload_config, workload_id)
        if source["workload_id"].casefold() != workload_id.casefold():
            raise ValueError("Qualified workload identity does not match the request")
    if request.command in configuration_commands:
        if request.factory_config is None:
            raise ValueError("Command requires factory configuration")
        configuration, deployment_identity = acquire_configuration_manifest(
            request.factory_config, request.role_paths
        )
        blockers.append({"code": "upstream_qualification_not_bound", "state": "missing"})
    else:
        request_artifacts, request_artifact_bundle_digest = acquire_request_artifacts(
            request.role_paths
        )
    if request.command not in source_commands | {MigrationCommand.AI_GATEWAY_PREFLIGHT}:
        blockers.append({"code": "run_manifest_unavailable", "state": "missing"})

    blockers.append({"code": "backend_not_implemented", "state": "not_implemented"})
    invocation_id = attempt_id or stable_id(
        "INV",
        {
            "contract_version": "1.0",
            "command": request.command.value,
            "run_id": run_id,
            "workload_id": workload_id,
            "action_target": action_target,
            "source_closure_digest": source["source_closure_digest"] if source else None,
            "configuration_bundle_digest": (
                configuration["configuration_bundle_digest"] if configuration else None
            ),
            "request_artifact_bundle_digest": request_artifact_bundle_digest,
        },
    )
    identity: dict[str, Any] = {
        "contract_version": "1.0",
        "command": request.command.value,
        "client_id": deployment_identity["client_id"] if deployment_identity else None,
        "deployment_id": deployment_identity["deployment_id"] if deployment_identity else None,
        "environment_id": deployment_identity["environment_id"] if deployment_identity else None,
        "workload_id": source["workload_id"] if source else workload_id,
        "subject_id": source["subject_id"] if source else None,
        "source_closure_digest": source["source_closure_digest"] if source else None,
        "workload_configuration_digest": (
            source["workload_configuration_digest"] if source else None
        ),
        "configuration_bundle_digest": (
            configuration["configuration_bundle_digest"] if configuration else None
        ),
        "request_artifact_bundle_digest": request_artifact_bundle_digest,
        "upstream_qualification_id": None,
        "upstream_revision": None,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "invocation_id": invocation_id,
        "action_target": action_target,
    }
    request_id = stable_id("MREQ", identity)
    decision_id = stable_id("MDEC", {**identity, "request_id": request_id})
    result_id = stable_id("MRES", {"decision_id": decision_id, "blockers": blockers})
    artifact_id = stable_id("MART", {"result_id": result_id, "kind": "migration-cli-result"})
    segments = ["runs", str(run_id)]
    if identity["workload_id"] is not None:
        segments.extend(["workloads", str(identity["workload_id"])])
    segments.extend(["contract-attempts", str(invocation_id), "migration-cli.result.json"])
    evidence_reference = "/".join(segments)

    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "1.0",
        "command": request.command.value,
        "request_id": request_id,
        "decision_id": decision_id,
        "result_id": result_id,
        "artifact_id": artifact_id,
        "content_digest": "0" * 64,
        "canonical_evidence_reference": evidence_reference,
        "identity": identity,
        "source_snapshot": source,
        "configuration_manifest": configuration,
        "request_artifacts": request_artifacts,
        "status": "blocked",
        "terminal_disposition": "not_implemented",
        "backend_state": "not_implemented",
        "evidence_class": "offline_contract_scaffold",
        "blockers": blockers,
        "next_permitted_action": "resolve_prerequisites_or_implement_owned_backend",
        "lifecycle": {
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "human_approved": False,
            "promoted": False,
            "provider_invoked": False,
        },
    }
    result["content_digest"] = _content_digest(result)
    telemetry = telemetry_from_result(result)
    validate_schema("migration-cli-result.schema.json", result)
    validate_schema("migration-cli-telemetry.schema.json", telemetry)
    return PreparedMigrationResult(result=result, telemetry=telemetry)


def telemetry_from_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "result_id": result["result_id"],
        "decision_id": result["decision_id"],
        "command": result["command"],
        "status": result["status"],
        "terminal_disposition": result["terminal_disposition"],
        "blocker_states": [item["state"] for item in result["blockers"]],
        "lifecycle": dict(result["lifecycle"]),
    }


def verify_result(result: dict[str, Any]) -> None:
    validate_schema("migration-cli-result.schema.json", result)
    if result["content_digest"] != _content_digest(result):
        raise ValueError("Migration result content digest is invalid")
    identity = result["identity"]
    request_id = stable_id("MREQ", identity)
    decision_id = stable_id("MDEC", {**identity, "request_id": request_id})
    result_id = stable_id("MRES", {"decision_id": decision_id, "blockers": result["blockers"]})
    artifact_id = stable_id("MART", {"result_id": result_id, "kind": "migration-cli-result"})
    expected = (request_id, decision_id, result_id, artifact_id)
    observed = tuple(
        result[key] for key in ("request_id", "decision_id", "result_id", "artifact_id")
    )
    segments = ["runs", str(identity["run_id"])]
    if identity["workload_id"] is not None:
        segments.extend(["workloads", str(identity["workload_id"])])
    segments.extend(
        [
            "contract-attempts",
            str(identity["invocation_id"]),
            "migration-cli.result.json",
        ]
    )
    expected_reference = "/".join(segments)
    source = result["source_snapshot"]
    if source is not None:
        source_inventory = source["source_inventory"]
        expected_closure = hashlib.sha256(
            json.dumps(source_inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        source_bindings = {
            "workload_id": source["workload_id"],
            "subject_id": source["subject_id"],
            "source_closure_digest": expected_closure,
            "workload_configuration_digest": source["workload_configuration_digest"],
        }
        if any(identity[key] != value for key, value in source_bindings.items()):
            raise ValueError("Migration source snapshot is not bound to result identity")
    configuration = result["configuration_manifest"]
    if configuration is not None:
        configuration_material = {
            "files": configuration["files"],
            "factory_bundle_digest": configuration["factory_bundle_digest"],
        }
        expected_configuration_digest = hashlib.sha256(
            json.dumps(configuration_material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        configuration_bindings = {
            "client_id": configuration["client_id"],
            "deployment_id": configuration["deployment_id"],
            "environment_id": configuration["environment_id"],
            "configuration_bundle_digest": expected_configuration_digest,
        }
        if any(identity[key] != value for key, value in configuration_bindings.items()):
            raise ValueError("Migration configuration is not bound to result identity")
    request_artifacts = result["request_artifacts"]
    expected_request_artifact_digest = (
        hashlib.sha256(
            json.dumps(request_artifacts, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if request_artifacts
        else None
    )
    blocker_codes = [item["code"] for item in result["blockers"]]
    if (
        observed != expected
        or result["command"] != identity["command"]
        or result["canonical_evidence_reference"] != expected_reference
        or identity["request_artifact_bundle_digest"] != expected_request_artifact_digest
        or len(blocker_codes) != len(set(blocker_codes))
        or "backend_not_implemented" not in blocker_codes
        or any(result["lifecycle"].values())
    ):
        raise ValueError("Migration result identity or lifecycle claims are invalid")
