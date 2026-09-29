"""Offline provenance graph construction and replay verification.

The graph is a projection over original, signed producer evidence.  It is not an
execution, validation, approval, certification, or promotion authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from smf.workload.lineage import RunLineage, verify_run_lineage

CONTRACT_VERSION = "1.0"
NODE_TYPES = (
    "source_intake",
    "strategy",
    "conversion",
    "generated_artifact",
    "execution",
    "validation",
    "repair",
    "human_decision",
)
STATUS_BY_TYPE: dict[str, frozenset[str]] = {
    "source_intake": frozenset({"admitted", "blocked", "failed"}),
    "strategy": frozenset({"selected", "blocked", "failed"}),
    "conversion": frozenset({"converted", "blocked", "unsupported", "failed"}),
    "generated_artifact": frozenset({"generated", "blocked", "failed"}),
    "execution": frozenset({"succeeded", "failed", "blocked", "submitted", "cancelled"}),
    "validation": frozenset({"validated", "failed", "blocked", "human_required"}),
    "repair": frozenset({"applied", "not_required", "failed", "blocked"}),
    "human_decision": frozenset({"approved", "not_required", "pending", "denied", "expired"}),
}
POSITIVE_STATUS = {
    "source_intake": "admitted",
    "strategy": "selected",
    "conversion": "converted",
    "generated_artifact": "generated",
    "execution": "succeeded",
    "validation": "validated",
    "repair": "applied",
    "human_decision": "approved",
}
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_CANARY = re.compile(r"(?i)secret(?:[-_. ]|%2d|%5f)*canary")
_PROTECTED = re.compile(
    r"(?i)(?:\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)|"
    r"\b(?:mrn|member[_ -]?id|patient[_ -]?id)\s*[:=]\s*[A-Za-z0-9-]{4,}\b)"
)


@dataclass(frozen=True)
class TrustedProducer:
    evidence_type: str
    authority: str
    key_id: str
    public_key: str


@dataclass(frozen=True)
class ProvenancePolicy:
    schema_version: str
    policy_id: str
    policy_version: str
    required_stages: tuple[str, ...]
    producers: tuple[TrustedProducer, ...]
    policy_digest: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{name} must contain an object")
    return value


def _validate_schema(name: str, payload: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        locations = ", ".join(
            ".".join(str(part) for part in error.path) or "fields" for error in errors
        )
        raise ValueError(f"Provenance {name} fields are invalid: {locations}")


def _safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe provenance {label}")
    views = [value]
    decoded = value
    for _ in range(3):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        views.append(expanded)
        decoded = expanded
    for candidate in tuple(views):
        for token in re.findall(r"[A-Za-z0-9+/=_-]{16,}", candidate):
            try:
                normalized = token.replace("-", "+").replace("_", "/")
                views.append(
                    base64.b64decode(
                        normalized + "=" * (-len(normalized) % 4), validate=True
                    ).decode()
                )
            except (ValueError, UnicodeDecodeError, binascii.Error):
                pass
    if any(_CANARY.search(item) or _PROTECTED.search(item) for item in views):
        raise ValueError(f"Unsafe provenance {label}")
    return value


def _contains_protected_text(value: str) -> bool:
    views = [value]
    decoded = value
    for _ in range(3):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        views.append(expanded)
        decoded = expanded
    for candidate in tuple(views):
        for token in re.findall(r"[A-Za-z0-9+/=_-]{16,}", candidate):
            try:
                normalized = token.replace("-", "+").replace("_", "/")
                views.append(
                    base64.b64decode(
                        normalized + "=" * (-len(normalized) % 4), validate=True
                    ).decode()
                )
            except (ValueError, UnicodeDecodeError, binascii.Error):
                pass
    return any(_CANARY.search(item) or _PROTECTED.search(item) for item in views)


def _reject_protected_bytes(path: Path, label: str) -> None:
    """Reject synthetic secret/protected-data canaries before hashing evidence."""

    carry = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            window = carry + chunk
            if _contains_protected_text(window.decode("utf-8", errors="ignore")):
                raise ValueError(f"Protected content is not allowed in provenance {label}")
            carry = window[-4096:]


def _relative_ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError(f"Unsafe provenance {label}")
    decoded = unquote(unquote(value))
    path = PurePosixPath(decoded)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"Unsafe provenance {label}")
    if _CANARY.search(decoded) or _PROTECTED.search(decoded):
        raise ValueError(f"Unsafe provenance {label}")
    return path.as_posix()


def _resolve(root: Path, reference: object, label: str) -> Path:
    safe = _relative_ref(reference, label)
    root = root.resolve()
    candidate = root.joinpath(*PurePosixPath(safe).parts)
    relative = candidate.relative_to(root)
    if any(
        root.joinpath(*relative.parts[:index]).is_symlink()
        for index in range(1, len(relative.parts) + 1)
    ):
        raise ValueError(f"Provenance {label} crosses a symlink boundary")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"Provenance {label} escapes its configured root")
    return resolved


def load_provenance_policy(path: Path) -> ProvenancePolicy:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Provenance policy must be an object")
    _validate_schema("provenance-policy.schema.json", payload)
    unsigned = dict(payload)
    supplied_digest = unsigned.pop("policy_digest")
    actual_digest = _sha256_bytes(_canonical(unsigned))
    if supplied_digest != actual_digest:
        raise ValueError("Provenance policy digest verification failed")
    required = tuple(payload["required_stages"])
    if required != NODE_TYPES:
        raise ValueError("Provenance policy must require the complete canonical stage sequence")
    producers = tuple(TrustedProducer(**item) for item in payload["producers"])
    keys = {(item.evidence_type, item.authority, item.key_id) for item in producers}
    if len(keys) != len(producers):
        raise ValueError("Duplicate provenance producer authority")
    for stage in required:
        if not any(item.evidence_type == stage for item in producers):
            raise ValueError(f"Required provenance stage lacks a trusted producer: {stage}")
    return ProvenancePolicy(
        schema_version=payload["schema_version"],
        policy_id=_safe_text(payload["policy_id"], "policy identity"),
        policy_version=_safe_text(payload["policy_version"], "policy version"),
        required_stages=required,
        producers=producers,
        policy_digest=actual_digest,
    )


def _node_material(node: Mapping[str, Any]) -> dict[str, Any]:
    material = dict(node)
    material.pop("node_id", None)
    material.pop("proof", None)
    return material


def derive_node_id(node: Mapping[str, Any]) -> str:
    digest = _sha256_bytes(
        _canonical(
            {
                "contract": "smf.provenance-node",
                "version": CONTRACT_VERSION,
                "material": _node_material(node),
            }
        )
    )
    return f"PN-v1-{digest}"


def _verify_signature(node: Mapping[str, Any], policy: ProvenancePolicy) -> None:
    matches = [
        item
        for item in policy.producers
        if item.evidence_type == node["node_type"]
        and item.authority == node["authority"]
        and item.key_id == node["proof"]["key_id"]
    ]
    if len(matches) != 1 or node["proof"]["algorithm"] != "ed25519":
        raise ValueError("Provenance node is not from one configured trusted producer")
    try:
        public = base64.b64decode(matches[0].public_key, validate=True)
        signature = base64.b64decode(node["proof"]["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, _canonical(_node_material(node) | {"node_id": node["node_id"]})
        )
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("Provenance node signature verification failed") from exc


def _verify_binding(binding: Mapping[str, Any], evidence_root: Path, *, emitted: bool) -> None:
    _safe_text(binding["artifact_id"], "artifact identity")
    path = _resolve(evidence_root, binding["artifact_ref"], "artifact reference")
    if not path.is_file():
        raise ValueError("Provenance artifact bytes do not match their immutable binding")
    _reject_protected_bytes(path, "artifact evidence")
    if _sha256_file(path) != binding["sha256"]:
        raise ValueError("Provenance artifact bytes do not match their immutable binding")
    if emitted and path.stat().st_size == 0:
        raise ValueError("Generated provenance artifact must contain meaningful bytes")


def _verify_node(
    raw: Mapping[str, Any],
    *,
    lineage: RunLineage,
    policy: ProvenancePolicy,
    evidence_root: Path,
) -> dict[str, Any]:
    node = dict(raw)
    _validate_schema("provenance-node.schema.json", node)
    if node["schema_version"] != CONTRACT_VERSION:
        raise ValueError("Unsupported provenance node version")
    if (
        node["node_type"] not in STATUS_BY_TYPE
        or node["status"] not in STATUS_BY_TYPE[node["node_type"]]
    ):
        raise ValueError("Unsupported provenance node status")
    expected_context = {
        "client_id": lineage.client_id,
        "workload_id": lineage.workload_id,
        "source_revision_id": lineage.source_revision_id,
        "run_id": lineage.run_id,
        "attempt_id": lineage.attempt_id,
        "lineage_id": lineage.lineage_id,
    }
    if any(node[field] != value for field, value in expected_context.items()):
        raise ValueError("Provenance node is substituted from another canonical context")
    if node["policy_digest"] != policy.policy_digest:
        raise ValueError("Provenance node is not bound to the trusted policy")
    if node["configuration_digest"] != lineage.configuration_digest:
        raise ValueError("Provenance node configuration binding changed")
    if node["strategy_digest"] != lineage.strategy_digest:
        raise ValueError("Provenance node strategy binding changed")
    if (
        node["original_evidence_type"] != f"smf.{node['node_type']}"
        or node["original_evidence_version"] != CONTRACT_VERSION
    ):
        raise ValueError("Unsupported original provenance evidence type or version")
    subjects = [item for item in lineage.artifacts if item.subject_id == node["subject_id"]]
    if len(subjects) != 1:
        raise ValueError("Provenance node subject does not resolve exactly once in source lineage")
    entrypoints = [item for item in lineage.artifacts if item.entrypoint]
    if len(entrypoints) != 1 or node["subject_id"] != entrypoints[0].subject_id:
        raise ValueError(
            "Provenance chain requires exactly one eligible entrypoint bound by every stage"
        )
    if node["node_type"] in {"conversion", "generated_artifact", "execution"} and (
        node["provider_id"] != lineage.provider
        or node["provider_version"] != lineage.provider_version
    ):
        raise ValueError("Provenance node provider binding changed")
    for field in (
        "subject_id",
        "authority",
        "producer_id",
        "producer_version",
        "decision_id",
        "original_evidence_type",
        "original_evidence_version",
        "reason_code",
    ):
        if node[field] is not None:
            _safe_text(node[field], field)
    if node["node_id"] != derive_node_id(node):
        raise ValueError("Provenance node identity verification failed")
    _verify_signature(node, policy)
    original = _resolve(evidence_root, node["original_evidence_ref"], "original evidence reference")
    if not original.is_file():
        raise ValueError("Original producer evidence is missing or changed")
    _reject_protected_bytes(original, "original producer evidence")
    if _sha256_file(original) != node["original_evidence_sha256"]:
        raise ValueError("Original producer evidence is missing or changed")
    for binding in node["inputs"]:
        _verify_binding(binding, evidence_root, emitted=False)
    for binding in node["outputs"]:
        _verify_binding(binding, evidence_root, emitted=node["node_type"] == "generated_artifact")
    for label in ("inputs", "outputs"):
        identities = [binding["artifact_id"].casefold() for binding in node[label]]
        if len(identities) != len(set(identities)):
            raise ValueError(f"Duplicate provenance {label} artifact identity")
    if node["node_type"] == "source_intake":
        expected_source = {
            (artifact.subject_id, artifact.logical_path, artifact.sha256)
            for artifact in lineage.artifacts
        }
        actual_source = {
            (binding["artifact_id"], binding["artifact_ref"], binding["sha256"])
            for binding in node["outputs"]
        }
        if actual_source != expected_source:
            raise ValueError("Source intake node does not bind the complete canonical closure")
    if node["status"] == POSITIVE_STATUS.get(node["node_type"]):
        if (
            node["node_type"] in {"conversion", "generated_artifact", "execution", "validation"}
            and not node["inputs"]
        ):
            raise ValueError("Positive provenance node lacks qualified input evidence")
        if node["node_type"] in {"conversion", "generated_artifact"} and not node["outputs"]:
            raise ValueError("Positive provenance node lacks emitted artifact evidence")
    return node


def _load_lineage(
    lineage_ref: str, evidence_root: Path, source_root: Path
) -> tuple[RunLineage, str]:
    path = _resolve(evidence_root, lineage_ref, "lineage reference")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Lineage evidence must be an object")
    lineage = verify_run_lineage(raw)
    for artifact in lineage.artifacts:
        source = _resolve(source_root, artifact.logical_path, "source artifact reference")
        if not source.is_file():
            raise ValueError("Canonical source closure bytes are missing or changed")
        _reject_protected_bytes(source, "source closure")
        if source.stat().st_size != artifact.size_bytes or _sha256_file(source) != artifact.sha256:
            raise ValueError("Canonical source closure bytes are missing or changed")
    return lineage, _sha256_file(path)


def _active_nodes(nodes: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    ids = {node["node_id"] for node in nodes}
    if len(ids) != len(nodes):
        raise ValueError("Duplicate provenance node identity")
    superseded = {
        node["supersedes_node_id"] for node in nodes if node["supersedes_node_id"] is not None
    }
    if not superseded.issubset(ids):
        raise ValueError("Provenance supersession references a missing node")
    by_id = {node["node_id"]: node for node in nodes}
    for node in nodes:
        previous = node["supersedes_node_id"]
        if previous is not None and by_id[previous]["node_type"] != node["node_type"]:
            raise ValueError("Provenance supersession crosses stage types")
    active = [node for node in nodes if node["node_id"] not in superseded]
    types = [node["node_type"] for node in active]
    if len(types) != len(set(types)):
        raise ValueError("Multiple active provenance nodes have the same stage identity")
    return active


def _verify_graph(nodes: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {node["node_id"]: node for node in nodes}
    for node in nodes:
        if node["node_id"] in node["predecessor_node_ids"]:
            raise ValueError("Provenance graph contains a self-cycle")
        for predecessor in node["predecessor_node_ids"]:
            if predecessor not in by_id:
                raise ValueError("Provenance graph references a missing predecessor")
            if NODE_TYPES.index(by_id[predecessor]["node_type"]) > NODE_TYPES.index(
                node["node_type"]
            ):
                raise ValueError("Provenance graph contains a backward or cyclic edge")
    active = sorted(_active_nodes(nodes), key=lambda item: NODE_TYPES.index(item["node_type"]))
    for index, node in enumerate(active[1:], start=1):
        if node["status"] == POSITIVE_STATUS.get(node["node_type"]):
            prior = active[index - 1]
            if prior["node_id"] not in node["predecessor_node_ids"]:
                raise ValueError("Positive provenance node is disconnected from its predecessor")
            produced = {(item["artifact_id"], item["sha256"]) for item in prior["outputs"]}
            consumed = {(item["artifact_id"], item["sha256"]) for item in node["inputs"]}
            if produced and not produced.intersection(consumed):
                raise ValueError("Provenance edge does not bind an exact predecessor artifact")
    return active


def _derive_outcome(
    active: Sequence[dict[str, Any]], required: Sequence[str]
) -> tuple[str, list[str], dict[str, bool]]:
    by_type = {node["node_type"]: node for node in active}
    missing = [stage for stage in required if stage not in by_type]
    statuses = {stage: node["status"] for stage, node in by_type.items()}
    if missing:
        terminal = "blocked_missing"
    elif statuses.get("human_decision") == "denied":
        terminal = "human_denied"
    elif (
        statuses.get("human_decision") in {"pending", "expired"}
        or statuses.get("validation") == "human_required"
    ):
        terminal = "human_pending"
    elif "cancelled" in statuses.values():
        terminal = "cancelled"
    elif "unsupported" in statuses.values():
        terminal = "unsupported"
    elif "failed" in statuses.values():
        terminal = "failed"
    elif any(value in {"blocked", "submitted"} for value in statuses.values()):
        terminal = "blocked_unresolved"
    elif statuses.get("validation") == "validated" and statuses.get("execution") == "succeeded":
        terminal = "validated"
    else:
        terminal = "blocked_unresolved"
    generated = (
        statuses.get("conversion") == "converted"
        and statuses.get("generated_artifact") == "generated"
    )
    executed = generated and statuses.get("execution") == "succeeded"
    validated = executed and statuses.get("validation") == "validated"
    telemetry = {
        "generated": generated,
        "executed": executed,
        "validated": validated,
        "parity_passed": False,
        "human_assisted": statuses.get("repair") == "applied",
        "human_approved": statuses.get("human_decision") == "approved",
        "certified": False,
        "blocked": terminal != "validated",
    }
    return terminal, missing, telemetry


def _chain_identity(payload: Mapping[str, Any]) -> str:
    material = dict(payload)
    material.pop("chain_id", None)
    material.pop("content_digest", None)
    identity_material = {
        "contract": "smf.provenance-chain",
        "version": CONTRACT_VERSION,
        "material": material,
    }
    return f"PC-v1-{_sha256_bytes(_canonical(identity_material))}"


def _construct_chain(
    *,
    lineage_ref: str,
    node_refs: Sequence[str],
    evidence_root: Path,
    source_root: Path,
    policy: ProvenancePolicy,
) -> dict[str, Any]:
    lineage_ref = _relative_ref(lineage_ref, "lineage reference")
    lineage, lineage_digest = _load_lineage(lineage_ref, evidence_root, source_root)
    if len([artifact for artifact in lineage.artifacts if artifact.entrypoint]) != 1:
        raise ValueError("Provenance chain requires exactly one eligible entrypoint")
    if lineage.policy_digest != policy.policy_digest:
        raise ValueError("Canonical lineage is not bound to the trusted provenance policy")
    refs = tuple(_relative_ref(item, "node reference") for item in node_refs)
    if len(set(item.casefold() for item in refs)) != len(refs):
        raise ValueError("Duplicate or ambiguous provenance node reference")
    nodes: list[dict[str, Any]] = []
    node_bindings: list[dict[str, str]] = []
    for reference in refs:
        path = _resolve(evidence_root, reference, "node reference")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Provenance node must be an object")
        node = _verify_node(raw, lineage=lineage, policy=policy, evidence_root=evidence_root)
        nodes.append(node)
        node_bindings.append(
            {"node_id": node["node_id"], "node_ref": reference, "node_sha256": _sha256_file(path)}
        )
    active = _verify_graph(nodes)
    terminal, missing, telemetry = _derive_outcome(active, policy.required_stages)
    payload: dict[str, Any] = {
        "schema_version": CONTRACT_VERSION,
        "chain_id": "",
        "content_digest": "",
        "client_id": lineage.client_id,
        "workload_id": lineage.workload_id,
        "source_revision_id": lineage.source_revision_id,
        "run_id": lineage.run_id,
        "attempt_id": lineage.attempt_id,
        "lineage_id": lineage.lineage_id,
        "lineage_ref": lineage_ref,
        "lineage_sha256": lineage_digest,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_digest": policy.policy_digest,
        "required_stages": list(policy.required_stages),
        "nodes": node_bindings,
        "active_node_ids": [node["node_id"] for node in active],
        "missing_stages": missing,
        "terminal_disposition": terminal,
        "telemetry": telemetry,
        "authorizes_execution": False,
        "authorizes_approval": False,
        "authorizes_certification": False,
    }
    payload["chain_id"] = _chain_identity(payload)
    without_digest = dict(payload)
    without_digest.pop("content_digest")
    payload["content_digest"] = _sha256_bytes(_canonical(without_digest))
    _validate_schema("provenance-chain.schema.json", payload)
    return payload


def build_provenance_chain(
    *,
    lineage_ref: str,
    node_refs: Sequence[str],
    evidence_root: Path,
    source_root: Path,
    policy: ProvenancePolicy,
) -> dict[str, Any]:
    """Reconstruct a chain entirely from original evidence and trusted policy."""

    return _construct_chain(
        lineage_ref=lineage_ref,
        node_refs=node_refs,
        evidence_root=evidence_root,
        source_root=source_root,
        policy=policy,
    )


def _publish(path: Path, payload: Mapping[str, Any]) -> Path:
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == encoded:
            return path
        raise FileExistsError("Conflicting immutable provenance chain publication")
    descriptor, name = tempfile.mkstemp(prefix=".provenance-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != encoded:
                raise FileExistsError(
                    "Conflicting immutable provenance chain publication"
                ) from None
    finally:
        temporary.unlink(missing_ok=True)
    return path


def _publication_path(output_root: Path, chain: Mapping[str, Any]) -> Path:
    if output_root.is_symlink():
        raise ValueError("Provenance publication crosses a symlink boundary")
    output_root.mkdir(parents=True, exist_ok=True)
    if output_root.is_symlink():
        raise ValueError("Provenance publication crosses a symlink boundary")
    root = output_root.resolve()
    parts = (
        "runs",
        _safe_text(chain["run_id"], "run identity"),
        "workloads",
        _safe_text(chain["workload_id"], "workload identity"),
        "attempts",
        _safe_text(chain["attempt_id"], "attempt identity"),
        "provenance",
    )
    parent = root
    for part in parts:
        parent = parent / part
        if parent.is_symlink():
            raise ValueError("Provenance publication crosses a symlink boundary")
        parent.mkdir(exist_ok=True)
        if parent.is_symlink() or not parent.resolve().is_relative_to(root):
            raise ValueError("Provenance publication crosses a symlink boundary")
    return parent / "chain.json"


def publish_provenance_chain(
    output_root: Path,
    chain: Mapping[str, Any],
    *,
    evidence_root: Path,
    source_root: Path,
    policy: ProvenancePolicy,
) -> Path:
    """Reconstruct caller-supplied chain before immutable canonical publication."""

    supplied = dict(chain)
    _validate_schema("provenance-chain.schema.json", supplied)
    reconstructed = _construct_chain(
        lineage_ref=supplied["lineage_ref"],
        node_refs=[item["node_ref"] for item in supplied["nodes"]],
        evidence_root=evidence_root,
        source_root=source_root,
        policy=policy,
    )
    if supplied != reconstructed:
        raise ValueError("Provenance chain failed original-evidence reconstruction")
    path = _publication_path(output_root, reconstructed)
    canonical = _publish(path, reconstructed)
    telemetry = path.with_name("telemetry.json")
    _publish(
        telemetry,
        {"chain_id": reconstructed["chain_id"], **dict(reconstructed["telemetry"])},
    )
    return canonical


def verify_provenance_chain(
    chain_path: Path,
    *,
    evidence_root: Path,
    source_root: Path,
    policy: ProvenancePolicy,
) -> dict[str, Any]:
    """Replay originals and require byte-for-byte semantic chain reconstruction."""

    stored = json.loads(chain_path.read_text(encoding="utf-8"))
    if not isinstance(stored, dict):
        raise ValueError("Provenance chain must be an object")
    _validate_schema("provenance-chain.schema.json", stored)
    if stored["policy_digest"] != policy.policy_digest:
        raise ValueError("Provenance chain policy binding changed")
    reconstructed = _construct_chain(
        lineage_ref=stored["lineage_ref"],
        node_refs=[item["node_ref"] for item in stored["nodes"]],
        evidence_root=evidence_root,
        source_root=source_root,
        policy=policy,
    )
    if stored != reconstructed:
        raise ValueError("Provenance chain does not match reconstruction from original evidence")
    return reconstructed
