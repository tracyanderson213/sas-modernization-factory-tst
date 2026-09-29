"""Offline, provider-neutral Humana AI Gateway configuration contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from importlib.resources import files
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.deployment import load_deployment_snapshot
from smf.immutable_files import ensure_directory, publish_json, read_published_json
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REFERENCE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^\s]+$")
_DIRECT_PROVIDER = re.compile(r"(?i)(^|\.)(anthropic\.com|openai\.com|openai\.azure\.com)$")
_SECRET_FIELD = re.compile(r"(?i)(api[_-]?key|client[_-]?secret|password|access[_-]?token|bearer)")
_SECRET_VALUE = re.compile(r"(?i)(secret-canary|phi-canary|pii-canary|sk-[a-z0-9])")
_RFC3339 = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T"
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    value: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in value:
            raise ValueError("Duplicate AI Gateway configuration key")
        value[key] = loader.construct_object(value_node, deep=deep)
    return value


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


class MockGatewayScenario(StrEnum):
    SUCCESS = "success"
    AUTHENTICATION_DENIED = "authentication_denied"
    THROTTLED = "throttled"
    CONTENT_FILTERED = "content_filtered"
    MALFORMED = "malformed"
    CORRELATION_MISSING = "correlation_missing"
    DISCONNECTED = "disconnected"
    UNCERTAIN_TIMEOUT = "uncertain_timeout"


@dataclass(frozen=True)
class GatewayProbeOutcome:
    disposition: str
    retryable: bool
    outcome_certain: bool
    provider_invoked: bool = False
    evidence_class: str = "synthetic_contract"


class GatewayTransport(Protocol):
    """Transport boundary; AIGW-01 ships no operational implementation."""

    evidence_class: str

    def probe(self) -> GatewayProbeOutcome: ...


class DeterministicMockGatewayTransport:
    """In-process mock that cannot produce operational gateway evidence."""

    evidence_class = "synthetic_contract"

    def __init__(self, scenario: MockGatewayScenario) -> None:
        if not isinstance(scenario, MockGatewayScenario):
            raise ValueError("Mock gateway scenario must use a strict enum")
        self.scenario = scenario

    def probe(self) -> GatewayProbeOutcome:
        values = {
            MockGatewayScenario.SUCCESS: ("synthetic_success", False, True),
            MockGatewayScenario.AUTHENTICATION_DENIED: ("authentication_denied", False, True),
            MockGatewayScenario.THROTTLED: ("quota_throttled", True, True),
            MockGatewayScenario.CONTENT_FILTERED: ("content_filtered", False, True),
            MockGatewayScenario.MALFORMED: ("response_contract_invalid", False, True),
            MockGatewayScenario.CORRELATION_MISSING: ("correlation_missing", False, True),
            MockGatewayScenario.DISCONNECTED: ("transport_disconnected", True, True),
            MockGatewayScenario.UNCERTAIN_TIMEOUT: ("outcome_unknown", False, False),
        }
        disposition, retryable, certain = values[self.scenario]
        return GatewayProbeOutcome(disposition, retryable, certain)


def evaluate_synthetic_probe(transport: GatewayTransport) -> GatewayProbeOutcome:
    """Exercise only the explicit synthetic boundary, never an arbitrary transport."""

    if not isinstance(transport, DeterministicMockGatewayTransport):
        raise ValueError("Operational AI Gateway transport is unavailable")
    outcome = transport.probe()
    if outcome.evidence_class != "synthetic_contract" or outcome.provider_invoked:
        raise ValueError("Mock evidence cannot claim provider invocation")
    return outcome


@dataclass(frozen=True)
class GatewayPreflightRequest:
    factory_config_path: Path
    gateway_config_path: Path
    output_root: Path
    run_id: str
    attempt_id: str | None
    workload_id: str
    evaluation_time: str


@dataclass(frozen=True)
class PreparedGatewayPreflight:
    result: dict[str, Any]
    telemetry: dict[str, Any]


def _schema(name: str) -> dict[str, Any]:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Packaged {name} is not an object")
    return payload


def _validate(name: str, payload: dict[str, Any]) -> None:
    related = (
        "ai-gateway-config.schema.json",
        "ai-gateway-preflight-result.schema.json",
        "ai-gateway-preflight-telemetry.schema.json",
    )
    resources = []
    for related_name in related:
        schema = _schema(related_name)
        resources.append((schema["$id"], Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    errors = sorted(
        Draft202012Validator(_schema(name), registry=registry).iter_errors(payload),
        key=lambda e: list(e.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"AI Gateway schema validation failed: {detail}")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe AI Gateway {label}")
    if _SECRET_VALUE.search(value):
        raise ValueError(f"AI Gateway {label} contains protected material")
    return value


def _parse_rfc3339(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValueError(f"AI Gateway {label} must use canonical RFC 3339 syntax")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"AI Gateway {label} is not a valid RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"AI Gateway {label} requires a timezone offset")
    return parsed


def _read_regular(path: Path, label: str) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if any(item.is_symlink() for item in (absolute, *absolute.parents)):
        raise ValueError(f"{label} has a symlink ancestor")
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise ValueError(f"{label} is missing or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"{label} changed while being acquired")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _reject_secrets(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_FIELD.search(key):
                raise ValueError("AI Gateway configuration contains a credential field")
            _reject_secrets(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secrets(item)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ValueError("AI Gateway configuration contains protected material")


def load_gateway_config(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, "AI Gateway configuration")
    try:
        payload = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("AI Gateway configuration is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError("AI Gateway configuration must be an object")
    _reject_secrets(payload)
    _validate("ai-gateway-config.schema.json", payload)
    gateway = cast(dict[str, Any], payload["gateway"])
    parsed = urlparse(cast(str, gateway["endpoint"]))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("AI Gateway endpoint must be an HTTPS origin without credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("AI Gateway endpoint must not contain route, query, or fragment")
    hostname = parsed.hostname.casefold()
    if hostname.endswith(".."):
        raise ValueError("AI Gateway endpoint hostname is not canonical")
    try:
        canonical_hostname = hostname.removesuffix(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("AI Gateway endpoint hostname is invalid") from exc
    if _DIRECT_PROVIDER.search(canonical_hostname):
        raise ValueError("Direct model-provider endpoints are prohibited")
    if cast(str, gateway["route"]).startswith(("http://", "https://")):
        raise ValueError("AI Gateway route must be a relative absolute-path")
    for reference in _references(payload):
        if reference is not None and not _REFERENCE.fullmatch(reference):
            raise ValueError("AI Gateway opaque references must be URI references")
    header_names = [cast(str, item["name"]).casefold() for item in payload["headers"]]
    if len(header_names) != len(set(header_names)):
        raise ValueError("AI Gateway headers contain duplicate names")
    authentication = cast(dict[str, Any], payload["authentication"])
    if authentication["mode"] == "pending" and any(
        authentication[key] is not None for key in ("credential_reference", "audience_reference")
    ):
        raise ValueError("Pending AI Gateway authentication cannot claim configured references")
    if authentication["mode"] != "pending" and authentication["credential_reference"] is None:
        raise ValueError("Active AI Gateway authentication requires a credential reference")
    if (
        authentication["mode"] == "entra_workload_identity"
        and authentication["audience_reference"] is None
    ):
        raise ValueError("Entra workload identity requires an audience reference")
    tls = cast(dict[str, Any], payload["tls"])
    if (tls["client_certificate_reference"] is None) != (tls["client_key_reference"] is None):
        raise ValueError("AI Gateway mTLS certificate and key references must be paired")
    retry = cast(dict[str, Any], payload["retry"])
    if retry["max_delay_ms"] < retry["base_delay_ms"]:
        raise ValueError("AI Gateway retry maximum delay cannot be below base delay")
    timeout = cast(dict[str, Any], payload["timeout"])
    if timeout["request_seconds"] < timeout["connect_seconds"]:
        raise ValueError("AI Gateway request timeout cannot be below connect timeout")
    if timeout["uncertain_outcome_seconds"] < timeout["request_seconds"]:
        raise ValueError("AI Gateway uncertain-outcome timeout cannot be below request timeout")
    authority = cast(dict[str, Any], payload["authority"])
    qualified_at = _parse_rfc3339(authority["qualification_time"], "qualification_time")
    valid_until = _parse_rfc3339(authority["valid_until"], "valid_until")
    if valid_until <= qualified_at:
        raise ValueError("AI Gateway configuration authority is stale")
    if gateway["state"] == "active" and (
        authentication["mode"] == "pending"
        or authority["state"] != "active"
        or authority["configuration_authority_reference"] is None
    ):
        raise ValueError(
            "Active AI Gateway configuration requires governed configuration authority"
        )
    return payload, raw


def _references(value: object, key: str = "") -> list[str | None]:
    found: list[str | None] = []
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key.endswith("_reference"):
                found.append(cast(str | None, child))
            else:
                found.extend(_references(child, child_key))
    elif isinstance(value, list):
        for child in value:
            found.extend(_references(child, key))
    return found


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/ai_gateway.py", files("smf").joinpath("ai_gateway.py")),
        ("smf/cli/main.py", files("smf.cli").joinpath("main.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        *(
            (f"smf/schemas/{name}", files("smf.schemas").joinpath(name))
            for name in (
                "ai-gateway-config.schema.json",
                "ai-gateway-preflight-result.schema.json",
                "ai-gateway-preflight-telemetry.schema.json",
            )
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def evaluate_gateway_preflight(request: GatewayPreflightRequest) -> PreparedGatewayPreflight:
    run_id = _safe_id(request.run_id, "run_id")
    workload_id = _safe_id(request.workload_id, "workload_id")
    attempt_id = _safe_id(
        request.attempt_id or stable_id("AIGWATT", {"run_id": run_id, "workload_id": workload_id}),
        "attempt_id",
    )
    evaluation_time = _parse_rfc3339(request.evaluation_time, "evaluation_time")
    config, raw = load_gateway_config(request.gateway_config_path)
    authority = cast(dict[str, Any], config["authority"])
    qualification_time = _parse_rfc3339(authority["qualification_time"], "qualification_time")
    valid_until = _parse_rfc3339(authority["valid_until"], "valid_until")
    if qualification_time > evaluation_time:
        raise ValueError("AI Gateway authority qualification is in the future")
    if valid_until <= evaluation_time:
        raise ValueError("AI Gateway configuration authority is stale at evaluation_time")
    snapshot = load_deployment_snapshot(request.factory_config_path)
    config_digest = hashlib.sha256(raw).hexdigest()
    implementation = _implementation_manifest()
    identity = {
        "client_id": snapshot.client_id,
        "deployment_id": snapshot.deployment_id,
        "environment_id": snapshot.environment_id,
        "workload_id": workload_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "evaluation_time": evaluation_time.isoformat(),
        "configuration_digest": config_digest,
        "factory_bundle_digest": snapshot.bundle_digest,
        "implementation_digest": _digest(implementation),
        "source_state": "not_applicable_to_configuration_preflight",
        "source_digest": None,
        "upstream_revision": _digest(implementation),
    }
    result_id = stable_id("AIGWRES", identity)
    reference = (
        f"runs/{run_id}/workloads/{workload_id}/gateway-preflight-attempts/"
        f"{attempt_id}/ai-gateway-preflight.result.json"
    )
    blockers = [{"code": "live_gateway_authority_missing", "state": "pending"}]
    if config["gateway"]["state"] == "pending":
        blockers.append({"code": "gateway_configuration_pending", "state": "pending"})
    authority = cast(dict[str, Any], config["authority"])
    if authority["state"] == "pending":
        blockers.append({"code": "configuration_authority_pending", "state": "pending"})
    elif authority["state"] == "denied":
        blockers.append({"code": "configuration_authority_denied", "state": "denied"})
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "1.0",
        "command": "ai-gateway.preflight",
        "result_id": result_id,
        "content_digest": "0" * 64,
        "canonical_evidence_reference": reference,
        "identity": identity,
        "configuration": config,
        "implementation_manifest": implementation,
        "status": "blocked",
        "terminal_disposition": "external_authority_required",
        "evidence_class": "offline_configuration_contract",
        "blockers": blockers,
        "claims": {
            "dns_verified": False,
            "tls_verified": False,
            "authenticated": False,
            "protocol_verified": False,
            "content_filter_verified": False,
            "quota_verified": False,
            "provider_invoked": False,
            "repair_generated": False,
            "migration_ready": False,
        },
    }
    result["content_digest"] = _digest({k: v for k, v in result.items() if k != "content_digest"})
    telemetry = telemetry_from_result(result)
    _validate("ai-gateway-preflight-result.schema.json", result)
    _validate("ai-gateway-preflight-telemetry.schema.json", telemetry)
    return PreparedGatewayPreflight(result, telemetry)


def telemetry_from_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "result_id": result["result_id"],
        "status": result["status"],
        "terminal_disposition": result["terminal_disposition"],
        "blocker_states": [item["state"] for item in result["blockers"]],
        "claims": dict(result["claims"]),
    }


def verify_gateway_result(result: dict[str, Any]) -> None:
    _validate("ai-gateway-preflight-result.schema.json", result)
    expected_digest = _digest({k: v for k, v in result.items() if k != "content_digest"})
    if result["content_digest"] != expected_digest:
        raise ValueError("AI Gateway result content digest is invalid")
    if result["result_id"] != stable_id("AIGWRES", result["identity"]):
        raise ValueError("AI Gateway result identity is invalid")
    if any(result["claims"].values()):
        raise ValueError("Offline AI Gateway result contains an operational claim")
    if result["implementation_manifest"] != _implementation_manifest():
        raise ValueError("AI Gateway implementation manifest does not match the current runtime")


def publish_gateway_preflight(
    request: GatewayPreflightRequest, prepared: PreparedGatewayPreflight
) -> tuple[Path, Path]:
    replayed = evaluate_gateway_preflight(request)
    if replayed != prepared:
        raise ValueError("AI Gateway prepared result does not match current qualified inputs")
    verify_gateway_result(prepared.result)
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    reference = Path(prepared.result["canonical_evidence_reference"])
    if reference.is_absolute() or ".." in reference.parts:
        raise ValueError("AI Gateway evidence reference escapes output root")
    result_path = root / reference
    ensure_directory(result_path.parent, root=root)
    publish_json(result_path, prepared.result, "AI Gateway preflight result", root=root)
    canonical = read_published_json(result_path, root=root, label="AI Gateway preflight result")
    if not isinstance(canonical, dict):
        raise ValueError("Canonical AI Gateway result is not an object")
    verify_gateway_result(canonical)
    telemetry = telemetry_from_result(canonical)
    if telemetry != prepared.telemetry:
        raise ValueError("AI Gateway telemetry is not derived from canonical result")
    telemetry_path = result_path.with_name("ai-gateway-preflight.telemetry.json")
    publish_json(telemetry_path, telemetry, "AI Gateway preflight telemetry", root=root)
    return result_path, telemetry_path


def recover_gateway_preflight(request: GatewayPreflightRequest) -> PreparedGatewayPreflight | None:
    """Recover only a missing telemetry projection from an immutable bound result."""

    replayed = evaluate_gateway_preflight(request)
    run_id = _safe_id(request.run_id, "run_id")
    workload_id = _safe_id(request.workload_id, "workload_id")
    attempt_id = _safe_id(
        request.attempt_id or stable_id("AIGWATT", {"run_id": run_id, "workload_id": workload_id}),
        "attempt_id",
    )
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    result_path = (
        root
        / "runs"
        / run_id
        / "workloads"
        / workload_id
        / "gateway-preflight-attempts"
        / attempt_id
        / "ai-gateway-preflight.result.json"
    )
    telemetry_path = result_path.with_name("ai-gateway-preflight.telemetry.json")
    if not result_path.exists() or telemetry_path.exists():
        return None
    payload = read_published_json(result_path, root=root, label="AI Gateway preflight result")
    if not isinstance(payload, dict):
        raise ValueError("Canonical AI Gateway result is not an object")
    verify_gateway_result(payload)
    identity = payload["identity"]
    if any(
        identity[key] != expected
        for key, expected in (
            ("run_id", run_id),
            ("workload_id", workload_id),
            ("attempt_id", attempt_id),
        )
    ):
        raise ValueError("Canonical AI Gateway result does not match recovery request")
    if payload != replayed.result:
        raise ValueError("Canonical AI Gateway result does not match current qualified inputs")
    return PreparedGatewayPreflight(payload, telemetry_from_result(payload))
