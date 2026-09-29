"""Offline prompt and model governance qualification for AIP-05."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.ai.models import AIProviderRequest
from smf.immutable_files import publish_json, read_published_bytes, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
_HOSTILE_TEMPLATE = re.compile(
    r"(?i)(ignore|override|bypass|disable)\s+(?:all\s+)?(?:previous|system|security|policy)"
)
_SOURCE_SLOT = "{{SOURCE_CONTEXT}}"


@dataclass(frozen=True)
class GovernanceEvidenceReference:
    kind: str
    evidence_ref: str
    evidence_digest: str
    origin_id: str
    applicability_id: str
    version: str
    selection_reason_id: str
    client_id: str
    source_digest: str
    conflict_disposition: str


@dataclass(frozen=True)
class PromptGovernanceRequest:
    input_root: Path
    policy_relative_path: str
    template_relative_path: str
    evaluation_relative_path: str
    output_root: Path
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    source_digest: str
    run_id: str
    attempt_id: str
    evaluation_time: str
    selected_evidence: tuple[GovernanceEvidenceReference, ...]


@dataclass(frozen=True)
class PreparedPromptGovernance:
    result: dict[str, Any]
    telemetry: dict[str, Any]


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object) -> str:
    return _digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Packaged {name} is not an object")
    return value


def _validate(name: str, value: dict[str, Any]) -> None:
    names = (
        "prompt-model-governance-policy.schema.json",
        "prompt-model-evaluation.schema.json",
        "prompt-model-governance-result.schema.json",
        "prompt-model-governance-telemetry.schema.json",
    )
    resources = [(_schema(item)["$id"], Resource.from_contents(_schema(item))) for item in names]
    registry = Registry().with_resources(resources)
    errors = sorted(
        Draft202012Validator(_schema(name), registry=registry).iter_errors(value),
        key=lambda e: list(e.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"AIP-05 schema validation failed: {detail}")


def _safe_id(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."} or contains_protected_data(value):
        raise ValueError(f"AIP-05 {label} is unsafe")
    return value


def _time(value: str, label: str) -> datetime:
    if not _RFC3339.fullmatch(value):
        raise ValueError(f"AIP-05 {label} must be canonical RFC 3339")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"AIP-05 {label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"AIP-05 {label} requires a timezone")
    return parsed


def _relative(value: str, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"AIP-05 {label} must be a safe relative path")
    return path


def _read(root: Path, relative: str, label: str) -> bytes:
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    path = lexical_root.joinpath(*_relative(relative, label).parts)
    return read_published_bytes(path, root=lexical_root, label=label)


def _load_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"AIP-05 {label} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"AIP-05 {label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"AIP-05 {label} must be an object")
    return value


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/ai_governance.py", files("smf").joinpath("ai_governance.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        *(
            (f"smf/schemas/{name}", files("smf.schemas").joinpath(name))
            for name in (
                "prompt-model-governance-policy.schema.json",
                "prompt-model-evaluation.schema.json",
                "prompt-model-governance-result.schema.json",
                "prompt-model-governance-telemetry.schema.json",
            )
        ),
    )
    return [
        {"path": name, "sha256": _digest_bytes(resource.read_bytes())}
        for name, resource in resources
    ]


def _reject_protected(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_protected(key)
            _reject_protected(item)
    elif isinstance(value, list):
        for item in value:
            _reject_protected(item)
    elif isinstance(value, str) and contains_protected_data(value):
        raise ValueError("AIP-05 governed input contains protected material")


def _selected_evidence(
    request: PromptGovernanceRequest, policy: dict[str, Any]
) -> list[dict[str, str]]:
    if not request.selected_evidence:
        raise ValueError("AIP-05 requires at least one selected evidence reference")
    if len(request.selected_evidence) > policy["context_budget"]["max_evidence_items"]:
        raise ValueError("AIP-05 selected evidence exceeds the governed context budget")
    permitted = set(policy["evidence_selection"]["allowed_kinds"])
    values: list[dict[str, str]] = []
    for item in request.selected_evidence:
        if item.kind not in permitted:
            raise ValueError("AIP-05 selected evidence kind is not permitted")
        if not item.evidence_ref.startswith("evidence://") or ".." in item.evidence_ref:
            raise ValueError("AIP-05 selected evidence reference is unsafe")
        if not _DIGEST.fullmatch(item.evidence_digest) or not _DIGEST.fullmatch(item.source_digest):
            raise ValueError("AIP-05 selected evidence digest is invalid")
        for name in ("origin_id", "applicability_id", "version", "selection_reason_id"):
            _safe_id(cast(str, getattr(item, name)), f"evidence {name}")
        if item.client_id != request.client_id or item.source_digest != request.source_digest:
            raise ValueError("AIP-05 selected evidence crosses the request boundary")
        if item.conflict_disposition not in {"none", "resolved"}:
            raise ValueError("AIP-05 selected evidence has an unresolved conflict")
        value = {
            "kind": item.kind,
            "evidence_ref": item.evidence_ref,
            "evidence_digest": item.evidence_digest,
            "origin_id": item.origin_id,
            "applicability_id": item.applicability_id,
            "version": item.version,
            "selection_reason_id": item.selection_reason_id,
            "client_id": item.client_id,
            "source_digest": item.source_digest,
            "conflict_disposition": item.conflict_disposition,
        }
        _reject_protected(value)
        values.append(value)
    keys = [item["evidence_ref"].casefold() for item in values]
    if len(keys) != len(set(keys)):
        raise ValueError("AIP-05 selected evidence references are ambiguous")
    return values


def _claims() -> dict[str, bool]:
    return {
        "live_model_authorized": False,
        "gateway_invoked": False,
        "provider_invoked": False,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "humana_ready": False,
        "production_ready": False,
        "migration_complete": False,
    }


def prepare_prompt_governance(request: PromptGovernanceRequest) -> PreparedPromptGovernance:
    """Validate and bind an offline prompt/model contract without granting live authority."""

    identity = {
        name: _safe_id(cast(str, getattr(request, name)), name)
        for name in (
            "client_id",
            "deployment_id",
            "environment_id",
            "workload_id",
            "run_id",
            "attempt_id",
        )
    }
    if not _DIGEST.fullmatch(request.source_digest):
        raise ValueError("AIP-05 source_digest must be a canonical SHA-256 digest")
    evaluated_at = _time(request.evaluation_time, "evaluation_time")
    policy_raw = _read(request.input_root, request.policy_relative_path, "policy")
    template_raw = _read(request.input_root, request.template_relative_path, "template")
    evaluation_raw = _read(request.input_root, request.evaluation_relative_path, "evaluation")
    policy = _load_json(policy_raw, "policy")
    evaluation = _load_json(evaluation_raw, "evaluation")
    _reject_protected(policy)
    _reject_protected(evaluation)
    _validate("prompt-model-governance-policy.schema.json", policy)
    _validate("prompt-model-evaluation.schema.json", evaluation)
    try:
        template = template_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("AIP-05 template must be UTF-8") from exc
    if len(template_raw) > policy["prompt_template"]["max_bytes"]:
        raise ValueError("AIP-05 template exceeds the governed context budget")
    if template.count(_SOURCE_SLOT) != 1:
        raise ValueError("AIP-05 template must contain exactly one untrusted source slot")
    if contains_protected_data(template) or _HOSTILE_TEMPLATE.search(template):
        raise ValueError("AIP-05 template contains protected or hostile instructions")
    template_digest = _digest_bytes(template_raw)
    if template_digest != policy["prompt_template"]["sha256"]:
        raise ValueError("AIP-05 template bytes do not match policy")
    if policy["prompt_template"]["max_bytes"] > policy["context_budget"]["max_input_bytes"]:
        raise ValueError("AIP-05 template budget exceeds the governed input budget")
    provider_id = cast(str, policy["model_binding"]["provider_id"]).casefold()
    if any(name in provider_id for name in ("anthropic", "openai", "direct")):
        raise ValueError("AIP-05 direct model-provider bindings are prohibited")
    context_budget_digest = _digest(policy["context_budget"])
    expected_evaluation = {
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "model_binding_id": policy["model_binding"]["binding_id"],
        "prompt_template_sha256": template_digest,
        "context_budget_digest": context_budget_digest,
    }
    if any(evaluation[key] != value for key, value in expected_evaluation.items()):
        raise ValueError("AIP-05 evaluation evidence crosses the governed policy boundary")
    if evaluation["evaluation_ref"] != policy["evaluation"]["evidence_ref"]:
        raise ValueError("AIP-05 evaluation reference does not match policy")
    if (
        evaluation["suite_id"] != policy["evaluation"]["suite_id"]
        or evaluation["suite_version"] != policy["evaluation"]["suite_version"]
    ):
        raise ValueError("AIP-05 evaluation suite does not match policy")
    if _digest_bytes(evaluation_raw) != policy["evaluation"]["evidence_sha256"]:
        raise ValueError("AIP-05 evaluation bytes do not match policy")
    issued_at = _time(policy["authority"]["issued_at"], "authority issued_at")
    valid_until = _time(policy["authority"]["valid_until"], "authority valid_until")
    if issued_at > evaluated_at or valid_until <= evaluated_at:
        raise ValueError("AIP-05 policy authority is not current at evaluation_time")
    # Caller-authored local files can prove contract mechanics, never operational authority.
    if policy["authority"]["state"] != "pending" or evaluation["state"] != "pending":
        raise ValueError("AIP-05 operational authority requires an external trusted verifier")

    implementation = _implementation_manifest()
    selected_evidence = _selected_evidence(request, policy)
    identity.update(
        {
            "source_digest": request.source_digest,
            "evaluation_time": evaluated_at.isoformat(),
            "policy_sha256": _digest_bytes(policy_raw),
            "template_sha256": template_digest,
            "evaluation_sha256": _digest_bytes(evaluation_raw),
            "implementation_digest": _digest(implementation),
        }
    )
    result_id = stable_id("AIP05RES", identity)
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": result_id,
        "content_digest": "0" * 64,
        "canonical_evidence_reference": (
            f"runs/{identity['run_id']}/workloads/{identity['workload_id']}/attempts/"
            f"{identity['attempt_id']}/ai-governance/result.json"
        ),
        "identity": identity,
        "status": "blocked_external_authority",
        "terminal_disposition": "live_model_and_evaluation_authority_required",
        "evidence_class": "synthetic_contract",
        "policy": policy,
        "prompt_template": {
            "template_id": policy["prompt_template"]["template_id"],
            "version": policy["prompt_template"]["version"],
            "evidence_ref": policy["prompt_template"]["evidence_ref"],
            "sha256": template_digest,
            "byte_count": len(template_raw),
            "raw_prompt_persisted": False,
        },
        "evaluation": {
            "suite_id": evaluation["suite_id"],
            "suite_version": evaluation["suite_version"],
            "evidence_ref": evaluation["evaluation_ref"],
            "sha256": _digest_bytes(evaluation_raw),
            "state": evaluation["state"],
            "case_count": len(evaluation["cases"]),
        },
        "instruction_boundary": {
            "system_policy_immutable": True,
            "source_role": "untrusted_data",
            "source_can_authorize_tools": False,
            "source_can_change_endpoint_or_model": False,
        },
        "selected_evidence": selected_evidence,
        "blockers": [
            "trusted_model_binding_authority_required",
            "trusted_evaluation_authority_required",
        ],
        "implementation_manifest": implementation,
        "claims": _claims(),
    }
    result["content_digest"] = _digest({k: v for k, v in result.items() if k != "content_digest"})
    telemetry = telemetry_from_governance(result)
    _validate("prompt-model-governance-result.schema.json", result)
    _validate("prompt-model-governance-telemetry.schema.json", telemetry)
    return PreparedPromptGovernance(result, telemetry)


def telemetry_from_governance(result: dict[str, Any]) -> dict[str, Any]:
    telemetry = {
        "schema_version": "1.0",
        "result_id": result["result_id"],
        "status": result["status"],
        "terminal_disposition": result["terminal_disposition"],
        "policy_id": result["policy"]["policy_id"],
        "policy_version": result["policy"]["policy_version"],
        "model_binding_id": result["policy"]["model_binding"]["binding_id"],
        "blockers": list(result["blockers"]),
        "claims": dict(result["claims"]),
    }
    _validate("prompt-model-governance-telemetry.schema.json", telemetry)
    return telemetry


def verify_prompt_governance(result: dict[str, Any], request: PromptGovernanceRequest) -> None:
    _validate("prompt-model-governance-result.schema.json", result)
    current = prepare_prompt_governance(request)
    if current.result != result:
        raise ValueError("AIP-05 result does not match current governed inputs")


def assert_provider_request_governed(result: dict[str, Any], provider: AIProviderRequest) -> None:
    """Require exact AIP-01 prompt/model bindings; this grants no invocation authority."""

    _validate("prompt-model-governance-result.schema.json", result)
    if result["content_digest"] != _digest(
        {key: value for key, value in result.items() if key != "content_digest"}
    ) or result["result_id"] != stable_id("AIP05RES", result["identity"]):
        raise ValueError("AIP-05 governance evidence integrity is invalid")
    policy = result["policy"]
    model = policy["model_binding"]
    template = result["prompt_template"]
    if (
        result["identity"]["client_id"] != provider.client_id
        or result["identity"]["deployment_id"] != provider.deployment_id
        or result["identity"]["environment_id"] != provider.environment_id
        or result["identity"]["workload_id"] != provider.workload_id
        or result["identity"]["source_digest"] != provider.source_closure_digest
        or result["identity"]["run_id"] != provider.run_id
        or result["identity"]["attempt_id"] != provider.workflow_attempt_id
        or model["provider_id"] != provider.provider_id
        or model["model_alias"] != provider.model_id
        or model["endpoint_binding_id"] != provider.endpoint_binding_id
        or template["evidence_ref"] != provider.prompt_template_ref
        or template["sha256"] != provider.prompt_template_digest
        or policy["evidence_ref"] != provider.prompt_policy_ref
        or result["identity"]["policy_sha256"] != provider.prompt_policy_digest
    ):
        raise ValueError("AIP-05 governance evidence does not bind the provider request")
    if result["status"] != "blocked_external_authority":
        raise ValueError("AIP-05 local evidence cannot authorize a live provider")


def publish_prompt_governance(
    request: PromptGovernanceRequest, prepared: PreparedPromptGovernance
) -> tuple[Path, Path]:
    verify_prompt_governance(prepared.result, request)
    relative = PurePosixPath(prepared.result["canonical_evidence_reference"])
    result_path = request.output_root.joinpath(*relative.parts)
    telemetry_path = result_path.with_name("telemetry.json")
    publish_json(result_path, prepared.result, "AIP-05 result", root=request.output_root)
    publish_json(telemetry_path, prepared.telemetry, "AIP-05 telemetry", root=request.output_root)
    replay = read_published_json(result_path, root=request.output_root, label="AIP-05 result")
    if replay != prepared.result:
        raise ValueError("AIP-05 published result replay failed")
    return result_path, telemetry_path
