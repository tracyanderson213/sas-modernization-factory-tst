"""Bounded deterministic-first repair orchestration with an offline gateway boundary."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from smf.ai_gateway import (
    DeterministicMockGatewayTransport,
    GatewayPreflightRequest,
    MockGatewayScenario,
    evaluate_gateway_preflight,
    evaluate_synthetic_probe,
    verify_gateway_result,
)
from smf.conversion.provider_package import ProviderPackageRequest, verify_provider_package
from smf.immutable_files import (
    ensure_directory,
    publish_json,
    published_file_exists,
    read_published_json,
)
from smf.workload.identity import stable_id

MAX_GATEWAY_ATTEMPTS = 3


@dataclass(frozen=True)
class RepairControllerRequest:
    deterministic_manifest_path: Path
    deterministic_request: ProviderPackageRequest
    gateway_request: GatewayPreflightRequest
    output_root: Path
    controller_attempt_id: str
    max_gateway_attempts: int = 2
    synthetic_scenarios: tuple[MockGatewayScenario, ...] = ()


@dataclass(frozen=True)
class PreparedRepairResult:
    result: dict[str, Any]
    telemetry: dict[str, Any]


def _digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(value: object) -> str:
    return _digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _schema(name: str) -> dict[str, Any]:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Packaged {name} is not an object")
    return payload


def _validate(name: str, payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(payload), key=lambda e: list(e.path)
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"AI repair schema validation failed: {detail}")


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/ai_repair.py", files("smf").joinpath("ai_repair.py")),
        ("smf/ai_gateway.py", files("smf").joinpath("ai_gateway.py")),
        (
            "smf/conversion/provider_package.py",
            files("smf.conversion").joinpath("provider_package.py"),
        ),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/ai-repair-result.schema.json",
            files("smf.schemas").joinpath("ai-repair-result.schema.json"),
        ),
        (
            "smf/schemas/ai-repair-telemetry.schema.json",
            files("smf.schemas").joinpath("ai-repair-telemetry.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": _digest_bytes(resource.read_bytes())}
        for name, resource in resources
    ]


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _identity_alignment(
    deterministic: dict[str, Any], gateway: dict[str, Any], request: RepairControllerRequest
) -> dict[str, str]:
    deterministic_identity = deterministic["identity"]
    gateway_identity = gateway["identity"]
    keys = ("client_id", "deployment_id", "environment_id", "workload_id", "run_id")
    if any(deterministic_identity[key] != gateway_identity[key] for key in keys):
        raise ValueError("AIREP-01 blocked: deterministic and gateway identities differ")
    if deterministic_identity["attempt_id"] != request.controller_attempt_id:
        raise ValueError("AIREP-01 blocked: controller attempt does not bind deterministic attempt")
    if gateway_identity["attempt_id"] != request.controller_attempt_id:
        raise ValueError("AIREP-01 blocked: controller attempt does not bind gateway attempt")
    return {key: deterministic_identity[key] for key in (*keys, "attempt_id", "source_artifact_id")}


def _claims(status: str) -> dict[str, bool]:
    return {
        "deterministic_conversion_selected": status == "deterministic_complete",
        "gateway_invoked": False,
        "provider_invoked": False,
        "repair_generated": False,
        "repair_accepted": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "migration_ready": False,
        "production_ready": False,
        "migration_complete": False,
    }


def prepare_repair_result(request: RepairControllerRequest) -> PreparedRepairResult:
    """Select deterministic output first, then exercise the offline fallback contract."""

    if not 1 <= request.max_gateway_attempts <= MAX_GATEWAY_ATTEMPTS:
        raise ValueError("AIREP-01 blocked: max_gateway_attempts must be between 1 and 3")
    if len(request.synthetic_scenarios) > request.max_gateway_attempts:
        raise ValueError("AIREP-01 blocked: synthetic scenarios exceed the bounded attempt policy")
    if any(not isinstance(item, MockGatewayScenario) for item in request.synthetic_scenarios):
        raise ValueError("AIREP-01 blocked: scenarios must use the strict gateway enum")
    if _absolute(request.output_root) != _absolute(request.deterministic_request.output_root):
        raise ValueError("AIREP-01 blocked: deterministic evidence root differs")
    if _absolute(request.output_root) != _absolute(request.gateway_request.output_root):
        raise ValueError("AIREP-01 blocked: gateway evidence root differs")

    deterministic = verify_provider_package(
        request.deterministic_manifest_path, request.deterministic_request
    )
    implementation = _implementation_manifest()
    status = "deterministic_complete" if deterministic["status"] == "packaged" else "blocked"
    gateway: dict[str, Any] | None = None
    synthetic_exercises: list[dict[str, Any]] = []
    if status == "deterministic_complete":
        identity = deterministic["identity"]
        if identity["attempt_id"] != request.controller_attempt_id:
            raise ValueError(
                "AIREP-01 blocked: controller attempt does not bind deterministic attempt"
            )
        bound_identity = {key: identity[key] for key in identity}
        terminal_disposition = "deterministic_output_selected"
        blockers: list[dict[str, str]] = []
    else:
        prepared_gateway = evaluate_gateway_preflight(request.gateway_request)
        verify_gateway_result(prepared_gateway.result)
        gateway = prepared_gateway.result
        bound_identity = _identity_alignment(deterministic, gateway, request)
        terminal_disposition = "external_gateway_authority_required"
        blockers = [
            {"code": "deterministic_conversion_incomplete", "state": deterministic["status"]},
            *[{"code": item["code"], "state": item["state"]} for item in gateway["blockers"]],
        ]
        for ordinal, scenario in enumerate(request.synthetic_scenarios, start=1):
            outcome = evaluate_synthetic_probe(DeterministicMockGatewayTransport(scenario))
            previous_digest = (
                synthetic_exercises[-1]["attempt_digest"] if synthetic_exercises else None
            )
            attempt = {
                "ordinal": ordinal,
                "scenario": scenario.value,
                "disposition": outcome.disposition,
                "retryable": outcome.retryable,
                "outcome_certain": outcome.outcome_certain,
                "evidence_class": outcome.evidence_class,
                "provider_invoked": outcome.provider_invoked,
                "previous_attempt_digest": previous_digest,
                "repair_artifact_state": "not_generated",
                "revalidation_state": "not_run",
            }
            attempt["attempt_digest"] = _digest(attempt)
            synthetic_exercises.append(attempt)
            if not outcome.retryable:
                break

    identity = {
        **bound_identity,
        "controller_attempt_id": request.controller_attempt_id,
        "policy_version": "1.0",
        "max_gateway_attempts": request.max_gateway_attempts,
        "synthetic_scenario_plan_digest": _digest(
            [scenario.value for scenario in request.synthetic_scenarios]
        ),
        "deterministic_manifest_digest": deterministic["content_digest"],
        "gateway_preflight_digest": gateway["content_digest"] if gateway is not None else None,
        "implementation_digest": _digest(implementation),
    }
    result_id = stable_id("AIREPRES", identity)
    reference = (
        f"runs/{identity['run_id']}/workloads/{identity['workload_id']}/attempts/"
        f"{request.controller_attempt_id}/ai-repair/controller.result.json"
    )
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": result_id,
        "content_digest": "0" * 64,
        "canonical_evidence_reference": reference,
        "identity": identity,
        "status": status,
        "terminal_disposition": terminal_disposition,
        "deterministic": {
            "status": deterministic["status"],
            "manifest_digest": deterministic["content_digest"],
            "source_artifact_id": deterministic["source"]["artifact_id"],
            "source_sha256": deterministic["source"]["sha256"],
            "generated_sha256": deterministic["generated_sha256"],
            "entrypoint": deterministic["entrypoint"],
            "candidate_artifact": deterministic["candidate_artifact"],
            "provider_revision": deterministic["provider"]["evaluated_revision"],
            "provider_license_sha256": deterministic["provider"]["license"]["sha256"],
        },
        "gateway": None
        if gateway is None
        else {
            "status": gateway["status"],
            "result_id": gateway["result_id"],
            "content_digest": gateway["content_digest"],
            "evidence_class": gateway["evidence_class"],
        },
        "synthetic_exercises": synthetic_exercises,
        "blockers": blockers,
        "implementation_manifest": implementation,
        "claims": _claims(status),
    }
    result["content_digest"] = _digest({k: v for k, v in result.items() if k != "content_digest"})
    telemetry = telemetry_from_result(result)
    _validate("ai-repair-result.schema.json", result)
    _validate("ai-repair-telemetry.schema.json", telemetry)
    return PreparedRepairResult(result, telemetry)


def telemetry_from_result(result: dict[str, Any]) -> dict[str, Any]:
    telemetry = {
        "schema_version": "1.0",
        "result_id": result["result_id"],
        "status": result["status"],
        "terminal_disposition": result["terminal_disposition"],
        "synthetic_exercise_count": len(result["synthetic_exercises"]),
        "blocker_codes": [item["code"] for item in result["blockers"]],
        "last_attempt_digest": (
            result["synthetic_exercises"][-1]["attempt_digest"]
            if result["synthetic_exercises"]
            else None
        ),
        "claims": dict(result["claims"]),
    }
    _validate("ai-repair-telemetry.schema.json", telemetry)
    return telemetry


def verify_repair_result(result: dict[str, Any], request: RepairControllerRequest) -> None:
    _validate("ai-repair-result.schema.json", result)
    if result["content_digest"] != _digest(
        {key: value for key, value in result.items() if key != "content_digest"}
    ):
        raise ValueError("AIREP-01 result content digest is invalid")
    if result["result_id"] != stable_id("AIREPRES", result["identity"]):
        raise ValueError("AIREP-01 result identity is invalid")
    if result["implementation_manifest"] != _implementation_manifest():
        raise ValueError("AIREP-01 implementation manifest differs from the current runtime")
    replayed = prepare_repair_result(request)
    if result != replayed.result:
        raise ValueError("AIREP-01 result differs from current governed inputs")


def publish_repair_result(
    request: RepairControllerRequest, prepared: PreparedRepairResult
) -> tuple[Path, Path]:
    replayed = prepare_repair_result(request)
    if replayed != prepared:
        raise ValueError("AIREP-01 prepared result differs from current governed inputs")
    verify_repair_result(prepared.result, request)
    root = _absolute(request.output_root)
    reference = Path(prepared.result["canonical_evidence_reference"])
    if reference.is_absolute() or ".." in reference.parts:
        raise ValueError("AIREP-01 evidence reference escapes output root")
    result_path = root / reference
    ensure_directory(result_path.parent, root=root)
    publish_json(result_path, prepared.result, "AIREP-01 result", root=root)
    canonical = read_published_json(result_path, root=root, label="AIREP-01 result")
    if not isinstance(canonical, dict):
        raise ValueError("AIREP-01 canonical result is not an object")
    verify_repair_result(canonical, request)
    telemetry = telemetry_from_result(canonical)
    if telemetry != prepared.telemetry:
        raise ValueError("AIREP-01 telemetry is not derived from the canonical result")
    telemetry_path = result_path.with_name("controller.telemetry.json")
    publish_json(telemetry_path, telemetry, "AIREP-01 telemetry", root=root)
    return result_path, telemetry_path


def recover_repair_result(request: RepairControllerRequest) -> PreparedRepairResult | None:
    """Recover only a missing telemetry projection after current-input replay."""

    replayed = prepare_repair_result(request)
    root = _absolute(request.output_root)
    reference = Path(replayed.result["canonical_evidence_reference"])
    if reference.is_absolute() or ".." in reference.parts:
        raise ValueError("AIREP-01 evidence reference escapes output root")
    result_path = root / reference
    telemetry_path = result_path.with_name("controller.telemetry.json")
    if not published_file_exists(result_path, root=root, label="AIREP-01 result"):
        return None
    if published_file_exists(telemetry_path, root=root, label="AIREP-01 telemetry"):
        return None
    canonical = read_published_json(result_path, root=root, label="AIREP-01 result")
    if not isinstance(canonical, dict):
        raise ValueError("AIREP-01 canonical result is not an object")
    verify_repair_result(canonical, request)
    if canonical != replayed.result:
        raise ValueError("AIREP-01 canonical result differs from current governed inputs")
    return PreparedRepairResult(canonical, telemetry_from_result(canonical))
