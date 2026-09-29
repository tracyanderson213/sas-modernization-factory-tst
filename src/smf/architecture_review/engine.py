"""Deterministic assembly of an offline architecture/security review packet."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.architecture_review.models import ArchitectureReviewRequest
from smf.architecture_review.schema import validate
from smf.deployment.configuration import load_deployment_snapshot
from smf.discovery import discover_source
from smf.readiness.manifest import load_manifest as load_readiness_manifest
from smf.readiness.policy import digest_value
from smf.security.configuration import canonical_json, load_security_configuration
from smf.security.threat_model import load_security_threat_model
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SENSITIVE_TEXT = re.compile(
    r"(?i)(secret-canary|password\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=]|"
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b)"
)


class _UniqueLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueLoader, node: yaml.Node, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate competition requirement key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _identity(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or sanitize_discovery_value(value) != value:
        raise ValueError(f"Unsafe {label}")
    return value


def _safe_file(root: Path, path: Path, label: str) -> Path:
    root = root.resolve()
    raw = path.as_posix()
    decoded = raw
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    candidate = Path(decoded)
    lexical = candidate if candidate.is_absolute() else root / candidate
    try:
        lexical_parts = lexical.relative_to(root).parts
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository scope or is not a regular file") from exc
    current = root
    for part in lexical_parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} escapes repository scope or is not a regular file")
    if lexical.is_symlink():
        raise ValueError(f"{label} escapes repository scope or is not a regular file")
    target = lexical.resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError(f"{label} escapes repository scope or is not a regular file")
    return target


def _safe_directory(root: Path, path: Path, label: str) -> Path:
    root = root.resolve()
    lexical = path if path.is_absolute() else root / path
    try:
        lexical_parts = lexical.relative_to(root).parts
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository scope or is not a directory") from exc
    current = root
    for part in lexical_parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} escapes repository scope or is not a directory")
    if lexical.is_symlink():
        raise ValueError(f"{label} escapes repository scope or is not a directory")
    target = lexical.resolve()
    if not target.is_relative_to(root) or not target.is_dir():
        raise ValueError(f"{label} escapes repository scope or is not a directory")
    return target


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    return value


def _reject_sensitive(value: Any, label: str) -> None:
    """Reject unsafe durable text before any packet digest or persistence."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_sensitive(key, label)
            _reject_sensitive(item, label)
        return
    if isinstance(value, tuple | list):
        for item in value:
            _reject_sensitive(item, label)
        return
    if isinstance(value, str) and (
        _SENSITIVE_TEXT.search(value) or sanitize_discovery_value(value) != value
    ):
        raise ValueError(f"{label} contains sensitive durable content")


def _meaningful_sas(source_bytes: bytes) -> None:
    try:
        text = source_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Architecture review requires one meaningful SAS entry point") from exc
    without_comments = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    without_comments = re.sub(r"(?m)^\s*\*[^;]*;", " ", without_comments)
    if not re.search(r"(?i)(?:\bdata\s+[A-Za-z_]|\bproc\s+[A-Za-z_])", without_comments):
        raise ValueError("Architecture review requires one meaningful SAS entry point")
    _reject_sensitive(text, "Qualified source")


def _canonical_source(
    root: Path, request: ArchitectureReviewRequest, source: Path
) -> dict[str, Any]:
    manifest_path = _safe_file(root, request.discovery_manifest, "Discovery manifest")
    try:
        recorded = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Canonical discovery evidence is malformed") from exc
    if not isinstance(recorded, dict) or set(recorded) != {"provider", "source", "workloads"}:
        raise ValueError("Canonical discovery evidence is malformed")
    provider = recorded.get("provider")
    if not isinstance(provider, str) or provider == "auto":
        raise ValueError("Canonical discovery provider must be explicit")
    discovery_root = _safe_directory(
        root, Path(str(recorded.get("source", ""))), "Discovery source"
    )
    replayed = json.loads(
        json.dumps(
            discover_source(
                discovery_root, provider=provider, namespace=request.discovery_namespace
            ).to_dict()
        )
    )
    if replayed != recorded:
        raise ValueError("Canonical discovery evidence does not match deterministic replay")
    workloads = [
        item
        for item in recorded["workloads"]
        if isinstance(item, dict) and item.get("workload_id") == request.workload_id
    ]
    if len(workloads) != 1:
        raise ValueError("Canonical workload identity is missing or ambiguous")
    workload = workloads[0]
    boundaries = [
        item
        for item in workload.get("boundaries", [])
        if isinstance(item, dict) and item.get("boundary_id") == request.boundary_id
    ]
    artifacts = {
        item.get("artifact_id"): item
        for item in workload.get("artifacts", [])
        if isinstance(item, dict) and isinstance(item.get("artifact_id"), str)
    }
    if len(boundaries) != 1 or request.subject_id not in artifacts:
        raise ValueError("Canonical boundary or entry point is missing")
    boundary_ids = boundaries[0].get("artifact_ids")
    if not isinstance(boundary_ids, list) or request.subject_id not in boundary_ids:
        raise ValueError("Canonical entry point is outside the selected boundary")
    if len(boundary_ids) != len(set(boundary_ids)) or any(
        item not in artifacts for item in boundary_ids
    ):
        raise ValueError("Canonical source closure is malformed")
    entry = artifacts[request.subject_id]
    if entry.get("kind") not in {"sas_program", "sas_macro", "sas_include"}:
        raise ValueError("Canonical entry point is not SAS source")
    expected_entry = _safe_file(
        discovery_root, Path(str(entry.get("logical_path", ""))), "Entry point"
    )
    if expected_entry != source:
        raise ValueError("Caller source does not match the canonical entry point")
    closure: list[dict[str, str]] = []
    for artifact_id in sorted(boundary_ids):
        artifact = artifacts[artifact_id]
        artifact_path = _safe_file(
            discovery_root, Path(str(artifact.get("logical_path", ""))), "Source closure artifact"
        )
        try:
            closure_text = artifact_path.read_bytes().decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("Source closure artifact is not valid UTF-8 text") from exc
        _reject_sensitive(closure_text, "Source closure artifact")
        checksum = _sha(artifact_path)
        if checksum != artifact.get("checksum"):
            raise ValueError("Canonical source closure checksum mismatch")
        closure.append(
            {
                "artifact_id": artifact_id,
                "logical_path": str(artifact["logical_path"]),
                "locator": str(artifact_path),
                "sha256": checksum,
            }
        )
    graph = workload.get("dependency_graph")
    if not isinstance(graph, dict):
        raise ValueError("Canonical dependency graph is missing")
    artifact_nodes = {
        item.get("node_id"): item.get("entity_id")
        for item in graph.get("nodes", [])
        if isinstance(item, dict) and item.get("kind") == "artifact"
    }
    if request.subject_id not in artifact_nodes or not set(boundary_ids).issubset(
        set(artifact_nodes.values())
    ):
        raise ValueError("Canonical dependency closure is incomplete")
    adjacency: dict[str, set[str]] = {str(node): set() for node in artifact_nodes}
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            raise ValueError("Canonical dependency graph is malformed")
        source_id, target_id = edge.get("source_id"), edge.get("target_id")
        if source_id in adjacency and target_id in artifact_nodes:
            adjacency[str(source_id)].add(str(target_id))
    pending = [request.subject_id]
    reachable: set[str] = set()
    while pending:
        node = pending.pop()
        if node not in reachable:
            reachable.add(node)
            pending.extend(adjacency[node] - reachable)
    reachable_artifacts = {artifact_nodes[node] for node in reachable}
    if reachable_artifacts != set(boundary_ids):
        raise ValueError("Canonical dependency closure does not match the selected boundary")
    return {
        "entry_artifact_id": request.subject_id,
        "sha256": _sha(source),
        "eligible_kind": "sas_program",
        "source_closure": closure,
        "source_closure_digest": digest_value(closure),
        "workload_digest": digest_value(workload),
        "discovery_digest": digest_value(recorded),
        "discovery_provider": provider,
        "discovery_namespace": request.discovery_namespace,
    }


def _load_governance_evidence(root: Path, path: Path, label: str) -> dict[str, Any]:
    evidence_path = _safe_file(root, path, label)
    try:
        value = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is malformed")
    _reject_sensitive(value, label)
    return value


def _verify_governed_decision(
    evidence: dict[str, Any],
    *,
    expected: dict[str, str],
    purpose: str,
    authority: str,
    verification_keys: Mapping[str, str],
) -> dict[str, str]:
    required = {
        "evidence_id",
        "state",
        "authority",
        "purpose",
        "decision_id",
        "owner_assignment_ref",
        "issued_at",
        "expires_at",
        *expected,
        "proof",
    }
    if set(evidence) != required or any(
        evidence.get(key) != value for key, value in expected.items()
    ):
        raise ValueError("Governed decision binding mismatch")
    if evidence.get("authority") != authority or evidence.get("purpose") != purpose:
        raise ValueError("Governed decision authority or purpose mismatch")
    for field in ("evidence_id", "decision_id", "owner_assignment_ref"):
        if not isinstance(evidence.get(field), str) or not _SAFE_ID.fullmatch(evidence[field]):
            raise ValueError("Governed decision identity is invalid")
    if evidence.get("state") not in {"approved", "pending", "denied"}:
        raise ValueError("Governed decision state is invalid")
    try:
        issued = datetime.fromisoformat(str(evidence["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(evidence["expires_at"]).replace("Z", "+00:00"))
        now = datetime.now(UTC)
        if issued.tzinfo is None or expires.tzinfo is None or now < issued or now >= expires:
            raise ValueError("Governed decision is stale or expired")
    except (KeyError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc) == "Governed decision is stale or expired":
            raise
        raise ValueError("Governed decision validity is invalid") from exc
    proof = evidence.get("proof")
    if not isinstance(proof, dict) or set(proof) != {"algorithm", "key_id", "value"}:
        raise ValueError("Governed decision proof is invalid")
    key_id = proof.get("key_id")
    if (
        proof.get("algorithm") != "ed25519"
        or not isinstance(key_id, str)
        or key_id not in verification_keys
    ):
        raise ValueError("Governed decision proof is invalid")
    try:
        public = base64.b64decode(verification_keys[key_id], validate=True)
        signature = base64.b64decode(proof["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, canonical_json({k: v for k, v in evidence.items() if k != "proof"})
        )
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("Governed decision signature is invalid") from exc
    return {
        "state": "verified" if evidence["state"] == "approved" else str(evidence["state"]),
        "evidence_id": str(evidence["evidence_id"]),
        "decision_id": str(evidence["decision_id"]),
        "owner_assignment_ref": str(evidence["owner_assignment_ref"]),
        "authority": authority,
        "issued_at": str(evidence["issued_at"]),
        "expires_at": str(evidence["expires_at"]),
        "evidence_digest": hashlib.sha256(canonical_json(evidence)).hexdigest(),
    }


def _requirements(path: Path) -> dict[str, Any]:
    payload = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    if not isinstance(payload, dict) or not isinstance(payload.get("requirements"), dict):
        raise ValueError("Competition requirements are malformed")
    folded: set[str] = set()
    for requirement_id, item in payload["requirements"].items():
        _identity(str(requirement_id), "requirement_id")
        if str(requirement_id).casefold() in folded:
            raise ValueError("Duplicate or case-ambiguous requirement identity")
        folded.add(str(requirement_id).casefold())
        if not isinstance(item, dict):
            raise ValueError("Competition requirement must be an object")
        evidence = item.get("approval_evidence")
        if evidence is not None and not isinstance(evidence, dict):
            raise ValueError("Approval evidence must be a governed decision object")
    _reject_sensitive(payload, "Competition requirements")
    return payload


def _readiness(
    path: Path | None,
    request: ArchitectureReviewRequest,
    deployment: Any,
    canonical_source: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if path is None:
        return {"state": "missing"}, [
            {
                "code": "readiness_evidence_missing",
                "state": "missing",
                "owner": "Humana platform owner",
            }
        ]
    manifest = load_readiness_manifest(path)
    expected = {
        "workload_id": request.workload_id,
        "boundary_id": request.boundary_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
    }
    binding = manifest["policy_snapshot"].get("prerequisite_binding", {})
    deployment_expected = {
        "client_id": deployment.client_id,
        "deployment_id": deployment.deployment_id,
        "environment_id": deployment.environment_id,
        "configuration_digest": deployment.configuration_digest,
    }
    if any(manifest.get(key) != value for key, value in expected.items()) or any(
        binding.get(key) != value for key, value in deployment_expected.items()
    ):
        raise ValueError("Readiness evidence is bound to a different execution subject")
    if manifest["workload_digest"] != canonical_source["workload_digest"]:
        raise ValueError("Readiness evidence workload does not match canonical discovery")
    qualified_workload = manifest["qualification_input"]["workload"]
    artifacts = {item["artifact_id"]: item for item in qualified_workload["artifacts"]}
    expected_closure = {
        item["artifact_id"]: (item["logical_path"], item["sha256"])
        for item in canonical_source["source_closure"]
    }
    actual_closure = {
        artifact_id: (artifacts[artifact_id]["logical_path"], artifacts[artifact_id]["checksum"])
        for artifact_id in expected_closure
        if artifact_id in artifacts
    }
    boundaries = [
        item
        for item in qualified_workload.get("boundaries", [])
        if item.get("boundary_id") == request.boundary_id
    ]
    if (
        actual_closure != expected_closure
        or len(boundaries) != 1
        or set(boundaries[0]["artifact_ids"]) != set(expected_closure)
        or request.subject_id not in expected_closure
    ):
        raise ValueError("Readiness evidence source closure does not match canonical discovery")
    state = (
        "qualified"
        if manifest["classification"] == "READY"
        else "denied"
        if any(item.get("state") == "denied" for item in manifest.get("prerequisite_checklist", []))
        else "pending"
    )
    blockers: list[dict[str, str]] = []
    if state != "qualified":
        blockers.append(
            {"code": "readiness_not_qualified", "state": state, "owner": "Humana platform owner"}
        )
    return {
        "state": state,
        "result_id": manifest["result_id"],
        "manifest_digest": manifest["content_digest"],
        "classification": manifest["classification"],
        "policy_id": manifest["policy_id"],
        "policy_version": manifest["policy_version"],
        "policy_digest": manifest["policy_digest"],
    }, blockers


def assemble_packet(request: ArchitectureReviewRequest) -> dict[str, Any]:
    """Assemble sanitized evidence. The result never grants execution authority."""

    root = request.repo_root.resolve()
    identities = {
        name: _identity(getattr(request, name), name)
        for name in (
            "workload_id",
            "subject_id",
            "boundary_id",
            "run_id",
            "attempt_id",
            "assessed_revision",
            "discovery_namespace",
        )
    }
    for label in ("recipient_class", "disclosure_policy_revision", "retention_policy_ref"):
        value = getattr(request, label)
        if value is not None:
            _identity(value, label)
    factory = _safe_file(root, request.factory_config, "Factory configuration")
    threat_path = _safe_file(root, request.threat_model, "Threat model")
    requirements_path = _safe_file(root, request.requirements, "Competition requirements")
    source = _safe_file(root, request.source, "Qualified source")
    source_bytes = source.read_bytes()
    if source.suffix.casefold() != ".sas":
        raise ValueError("Architecture review requires one meaningful SAS entry point")
    _meaningful_sas(source_bytes)
    canonical_source = _canonical_source(root, request, source)

    deployment = load_deployment_snapshot(factory)
    threat = load_security_threat_model(threat_path)
    requirements = _requirements(requirements_path)
    readiness_path = (
        _safe_file(root, request.readiness_manifest, "Readiness manifest")
        if request.readiness_manifest is not None
        else None
    )
    readiness, blockers = _readiness(readiness_path, request, deployment, canonical_source)
    security = None
    if request.security_policy is not None or request.security_bindings is not None:
        if request.security_policy is None or request.security_bindings is None:
            raise ValueError("Both governed security policy and bindings are required")
        security = load_security_configuration(
            _safe_file(root, request.security_policy, "Security policy"),
            _safe_file(root, request.security_bindings, "Security bindings"),
        )
    activation: dict[str, str] = {
        "state": "missing",
        "authority_contract": "signed_henv01_exact_subject_v1",
    }
    if request.activation_evidence is not None:
        if security is None:
            raise ValueError("Signed HENV-01 activation requires governed security configuration")
        if readiness.get("state") != "qualified":
            raise ValueError("Signed HENV-01 activation requires exact-source READY evidence")
        activation_expected = {
            "client_id": deployment.client_id,
            "deployment_id": deployment.deployment_id,
            "environment_id": deployment.environment_id,
            "workload_id": request.workload_id,
            "workload_digest": canonical_source["workload_digest"],
            "boundary_id": request.boundary_id,
            "subject_id": request.subject_id,
            "source_sha256": canonical_source["sha256"],
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
            "assessed_revision": request.assessed_revision,
            "configuration_digest": deployment.configuration_digest,
            "readiness_result_id": str(readiness.get("result_id", "missing")),
            "readiness_manifest_digest": str(readiness.get("manifest_digest", "missing")),
        }
        activation = {
            "authority_contract": "signed_henv01_exact_subject_v1",
            **_verify_governed_decision(
                _load_governance_evidence(root, request.activation_evidence, "HENV-01 activation"),
                expected=activation_expected,
                purpose="henv01-protected-execution",
                authority=security.authority,
                verification_keys=security.verification_keys,
            ),
        }
    if activation["state"] != "verified":
        blockers.append(
            {
                "code": "protected_execution_decision_missing",
                "state": "missing" if activation["state"] == "missing" else activation["state"],
                "owner": "Humana approval authority",
            }
        )

    disclosure: dict[str, str] = {"state": "missing"}
    disclosure_values = (
        request.recipient_class,
        request.disclosure_policy_revision,
        request.retention_policy_ref,
    )
    if request.disclosure_evidence is not None:
        if security is None or not all(disclosure_values):
            raise ValueError("Shared disclosure requires governed configuration and exact scope")
        disclosure_expected = {
            "client_id": deployment.client_id,
            "deployment_id": deployment.deployment_id,
            "environment_id": deployment.environment_id,
            "assessed_revision": request.assessed_revision,
            "recipient_class": str(request.recipient_class),
            "disclosure_policy_revision": str(request.disclosure_policy_revision),
            "retention_policy_ref": str(request.retention_policy_ref),
        }
        disclosure = _verify_governed_decision(
            _load_governance_evidence(root, request.disclosure_evidence, "Disclosure decision"),
            expected=disclosure_expected,
            purpose="architecture-review-shared-disclosure",
            authority=security.authority,
            verification_keys=security.verification_keys,
        )
    elif any(disclosure_values):
        blockers.append(
            {
                "code": "disclosure_decision_missing",
                "state": "missing",
                "owner": "Humana disclosure authority",
            }
        )

    approval_requests: list[dict[str, Any]] = []
    for requirement_id, item in requirements["requirements"].items():
        _identity(str(requirement_id), "requirement_id")
        evidence = item.get("approval_evidence")
        assignment = None
        state = "denied" if item.get("status") == "denied" else "pending"
        if evidence is not None:
            if security is None:
                raise ValueError("Approval evidence requires governed security configuration")
            assignment = _verify_governed_decision(
                evidence,
                expected={
                    "requirement_id": str(requirement_id),
                    "environment_id": deployment.environment_id,
                    "assessed_revision": request.assessed_revision,
                },
                purpose="competition-requirement-approval",
                authority=security.authority,
                verification_keys=security.verification_keys,
            )
            state = "approved" if assignment["state"] == "verified" else assignment["state"]
        role_value = str(item.get("owner_role", "unassigned"))
        _reject_sensitive(role_value, "Requirement owner role")
        owner_role_id = "role-" + hashlib.sha256(role_value.encode("utf-8")).hexdigest()[:16]
        approval_requests.append(
            {
                "requirement_refs": [requirement_id],
                "environment_id": deployment.environment_id,
                "assessed_revision": identities["assessed_revision"],
                "owner_role_id": owner_role_id,
                "assignment_decision": assignment,
                "decision_state": state,
                "unresolved_risk_code": None if state == "approved" else "approval_unresolved",
            }
        )
        if state != "approved":
            blockers.append(
                {
                    "code": "client_requirement_unresolved",
                    "state": state,
                    "owner": str(requirement_id),
                }
            )

    bindings = []
    for item in deployment.bindings:
        _reject_sensitive(item, "Deployment binding")
        bindings.append(
            {
                "binding_id": item["binding_id"],
                "role": item["role"],
                "state": item["state"],
                "requirement_refs": [item["owner_requirement"]],
                "value_digest": hashlib.sha256(item["value"].encode("utf-8")).hexdigest(),
            }
        )
    packet_id = digest_value(
        {
            "contract": "smf-architecture-review-v1",
            **identities,
            "client_id": deployment.client_id,
            "deployment_id": deployment.deployment_id,
            "environment_id": deployment.environment_id,
            "source": canonical_source,
            "configuration_digest": deployment.configuration_digest,
            "threat_model_digest": threat.content_digest,
            "requirements_digest": _sha(requirements_path),
        }
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "packet_id": packet_id,
        "packet_kind": "architecture_security_review_evidence",
        "authority": "non_authorizing",
        "assessed_revision": identities["assessed_revision"],
        "identity": {
            "client_id": deployment.client_id,
            "deployment_id": deployment.deployment_id,
            "environment_id": deployment.environment_id,
            **{
                key: identities[key]
                for key in ("workload_id", "subject_id", "boundary_id", "run_id", "attempt_id")
            },
        },
        "source": canonical_source,
        "configuration": {
            "configuration_digest": deployment.configuration_digest,
            "bundle_digest": deployment.bundle_digest,
            "files": list(deployment.file_inventory),
            "threat_model_digest": threat.content_digest,
            "requirements_digest": _sha(requirements_path),
        },
        "trust_boundaries": _json_value(threat.payload["boundaries"]),
        "data_flows": _json_value(threat.payload["flows"]),
        "controls": _json_value(threat.payload["controls"]),
        "risks": _json_value(threat.payload["threats"]),
        "endpoint_bindings": bindings,
        "approval_requests": approval_requests,
        "henv01_readiness": readiness,
        "protected_execution_decision": activation,
        "evidence_handling": {
            "sanitization": "before_persistence_or_hashing",
            "canonical_immutable": True,
            "shared_projection": "allowlist_only",
            "retention_policy_ref": request.retention_policy_ref,
            "recipient_class": request.recipient_class,
            "disclosure_policy_revision": request.disclosure_policy_revision,
            "disclosure_decision": disclosure,
        },
        "blockers": blockers,
        "terminal_disposition": "blocked" if blockers else "review_ready",
        "lifecycle": {
            "packet_generated": True,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "human_approved": False,
            "human_assisted": False,
            "blocked": bool(blockers),
        },
        "content_digest": "",
    }
    _reject_sensitive(payload, "Architecture review packet")
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    validate("architecture-review-packet.schema.json", payload)
    return payload
