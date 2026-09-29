"""Verification of canonical inventory bindings and immutable source bytes."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.assessment import (
    load_workload_complexity_policy,
    load_workload_complexity_result,
    verify_workload_complexity_attestation,
)
from smf.pilot.schema import validate_inventory
from smf.readiness import load_manifest as load_readiness_manifest
from smf.readiness.policy import digest_value
from smf.workload.sanitization import sanitize_discovery_value

_MEANINGFUL_SAS = re.compile(r"(?im)^\s*(?:data\s+[A-Za-z_]|proc\s+[A-Za-z_]|%macro\s+[A-Za-z_])")


def inventory_digest(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("inventory_digest", None)
    unsigned.pop("proof", None)
    return digest_value(unsigned)


def _safe_file(root: Path, relative: str, label: str) -> Path:
    if not relative or urlparse(relative).scheme:
        raise ValueError(f"Unsafe {label} reference")
    decoded = relative
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    path = Path(decoded)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"Unsafe {label} reference")
    resolved_root = root.resolve()
    has_symlink = any(
        root.joinpath(*path.parts[:index]).is_symlink() for index in range(1, len(path.parts) + 1)
    )
    resolved = (root / path).resolve()
    if has_symlink or not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError(f"{label} reference escapes or is missing")
    return resolved


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_no_secrets(payload: dict[str, Any]) -> None:
    if sanitize_discovery_value(payload) != payload:
        raise ValueError("Pilot inventory contains secret-bearing values")


def _verify_prerequisite(
    item: dict[str, Any], candidate: dict[str, Any], root: Path, policy: dict[str, Any]
) -> str | None:
    state = item["state"]
    if state != "passed":
        return cast(str, state)
    uri = item.get("readiness_manifest_uri")
    digest = item.get("readiness_manifest_digest")
    if not uri or not digest:
        return "missing"
    path = _safe_file(root, uri, "readiness manifest")
    if _sha256(path) != digest:
        return "failed"
    manifest = load_readiness_manifest(path)
    exact = (
        manifest["classification"] == "READY"
        and manifest["workload_id"] == candidate["workload_id"]
        and manifest["boundary_id"] == candidate["boundary_id"]
        and manifest["run_id"] == item["evidence_run_id"]
        and manifest["attempt_id"] == item["evidence_attempt_id"]
        and manifest["workload_digest"] == candidate["discovery_workload_digest"]
        and manifest["policy_digest"] in policy["approval_policy"]["readiness_policy_digests"]
    )
    return None if exact else "failed"


def _canonical_closure_reasons(
    discovered: dict[str, Any], candidate: dict[str, Any]
) -> tuple[str, ...]:
    artifacts = discovered.get("artifacts")
    boundaries = discovered.get("boundaries")
    graph = discovered.get("dependency_graph")
    if (
        not isinstance(artifacts, list)
        or not isinstance(boundaries, list)
        or not isinstance(graph, dict)
    ):
        return ("canonical_discovery_closure_missing",)
    artifact_items = [item for item in artifacts if isinstance(item, dict)]
    artifact_by_id = {item.get("artifact_id"): item for item in artifact_items}
    if len(artifact_items) != len(artifacts) or len(artifact_by_id) != len(artifact_items):
        raise ValueError("Duplicate or malformed canonical discovery artifact identity")
    matches = [
        item
        for item in boundaries
        if isinstance(item, dict) and item.get("boundary_id") == candidate["boundary_id"]
    ]
    if len(matches) != 1:
        return ("canonical_boundary_missing_or_ambiguous",)
    boundary = matches[0]
    boundary_ids = boundary.get("artifact_ids")
    metadata = boundary.get("metadata")
    if (
        not isinstance(boundary_ids, list)
        or not boundary_ids
        or len(boundary_ids) != len(set(boundary_ids))
        or not isinstance(metadata, dict)
    ):
        return ("canonical_boundary_closure_invalid",)
    reasons: list[str] = []
    if metadata.get("entry_point_artifact_id") != candidate["entry_point_artifact_id"]:
        reasons.append("canonical_entry_point_mismatch")
    candidate_artifacts = {item["artifact_id"]: item for item in candidate["source_closure"]}
    if set(candidate_artifacts) != set(boundary_ids):
        reasons.append("canonical_source_closure_mismatch")
    for artifact_id in set(candidate_artifacts) & set(boundary_ids):
        canonical = artifact_by_id.get(artifact_id)
        candidate_artifact = candidate_artifacts[artifact_id]
        if (
            canonical is None
            or canonical.get("checksum") != candidate_artifact["sha256"]
            or canonical.get("logical_path") != candidate_artifact["logical_path"]
        ):
            reasons.append("canonical_artifact_identity_mismatch")

    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        reasons.append("canonical_dependency_graph_invalid")
        return tuple(sorted(set(reasons)))
    node_to_artifact: dict[str, str] = {}
    artifact_to_node: dict[str, str] = {}
    for node in nodes:
        if not isinstance(node, dict) or node.get("kind") != "artifact":
            continue
        node_id = node.get("node_id")
        entity_id = node.get("entity_id")
        if not isinstance(node_id, str) or not isinstance(entity_id, str):
            raise ValueError("Malformed canonical dependency artifact node")
        if node_id in node_to_artifact or entity_id in artifact_to_node:
            raise ValueError("Duplicate canonical dependency artifact identity")
        node_to_artifact[node_id] = entity_id
        artifact_to_node[entity_id] = node_id
    entry_node = artifact_to_node.get(candidate["entry_point_artifact_id"])
    if entry_node is None or not set(boundary_ids).issubset(artifact_to_node):
        reasons.append("canonical_dependency_closure_mismatch")
        return tuple(sorted(set(reasons)))
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_to_artifact}
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("Malformed canonical dependency edge")
        source = edge.get("source_id")
        target = edge.get("target_id")
        if source in adjacency and target in node_to_artifact:
            adjacency[source].add(target)
    pending = [entry_node]
    reachable_nodes: set[str] = set()
    while pending:
        node_id = pending.pop()
        if node_id in reachable_nodes:
            continue
        reachable_nodes.add(node_id)
        pending.extend(adjacency[node_id] - reachable_nodes)
    reachable_artifacts = {node_to_artifact[node_id] for node_id in reachable_nodes}
    if reachable_artifacts != set(boundary_ids):
        reasons.append("canonical_dependency_closure_mismatch")
    return tuple(sorted(set(reasons)))


def verify_inventory(
    raw: dict[str, Any],
    root: Path,
    policy: dict[str, Any],
    run_id: str,
    attempt_id: str,
    *,
    verified_at: datetime | None = None,
) -> tuple[dict[str, tuple[str, ...]], int]:
    """Return candidate blockers and the recomputed unique-script denominator."""

    validate_inventory(raw)
    _verify_no_secrets(raw)
    if raw["inventory_digest"] != inventory_digest(raw):
        raise ValueError("Pilot inventory digest mismatch")
    proof = raw["proof"]
    provenance = policy["inventory_provenance"]
    if (
        raw["authority"] not in provenance["authorities"]
        or proof["key_id"] not in provenance["key_ids"]
    ):
        raise ValueError("Pilot inventory authority is not permitted")
    try:
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(policy["verification_keys"][proof["key_id"]], validate=True)
        )
        key.verify(
            base64.b64decode(proof["value"], validate=True), bytes.fromhex(raw["inventory_digest"])
        )
    except (KeyError, ValueError, InvalidSignature) as exc:
        raise ValueError("Pilot inventory attestation is invalid") from exc
    if raw["client_id"] != policy["client_id"]:
        raise ValueError("Pilot inventory client binding mismatch")
    if raw["run_id"] != run_id or raw["attempt_id"] != attempt_id:
        raise ValueError("Pilot inventory run or attempt binding mismatch")

    snapshot = _safe_file(root, raw["discovery_snapshot"]["uri"], "discovery snapshot")
    if _sha256(snapshot) != raw["discovery_snapshot"]["digest"]:
        raise ValueError("Discovery snapshot digest mismatch")
    try:
        discovery = json.loads(snapshot.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Discovery snapshot is not canonical JSON") from exc
    if sanitize_discovery_value(discovery) != discovery:
        raise ValueError("Discovery snapshot contains secret-bearing material")
    if digest_value(discovery) != raw["discovery_snapshot"]["content_digest"]:
        raise ValueError("Discovery snapshot content digest mismatch")

    identities: dict[str, set[str]] = {
        "workload": set(),
        "boundary": set(),
        "artifact": set(),
        "script": set(),
    }
    blockers: dict[str, tuple[str, ...]] = {}
    all_scripts: set[str] = set()
    discovery_by_id = {
        item.get("workload_id"): item
        for item in discovery.get("workloads", [])
        if isinstance(item, dict)
    }
    if len(discovery_by_id) != len(discovery.get("workloads", [])):
        raise ValueError("Duplicate or malformed discovery workload identity")

    for candidate in raw["candidates"]:
        workload_id = candidate["workload_id"]
        reasons: list[str] = []
        for kind, value in (("workload", workload_id), ("boundary", candidate["boundary_id"])):
            if value in identities[kind]:
                raise ValueError(f"Duplicate canonical {kind} identity")
            identities[kind].add(value)
        for script_id in candidate["script_ids"]:
            if script_id in identities["script"]:
                raise ValueError("Duplicate canonical script identity")
            identities["script"].add(script_id)
            all_scripts.add(script_id)
        artifacts = candidate["source_closure"]
        artifact_ids = [item["artifact_id"] for item in artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("Duplicate source artifact identity")
        if candidate["entry_point_artifact_id"] not in artifact_ids:
            reasons.append("missing_entry_point")
        closure_projection: list[dict[str, Any]] = []
        meaningful = False
        for artifact in artifacts:
            try:
                path = _safe_file(root, artifact["source_uri"], "source artifact")
            except ValueError:
                reasons.append("source_artifact_missing_or_unsafe")
                continue
            data = path.read_bytes()
            try:
                decoded = data.decode("utf-8")
            except UnicodeDecodeError:
                decoded = ""
            if decoded and sanitize_discovery_value(decoded) != decoded:
                raise ValueError("Pilot source contains secret-bearing material")
            if (
                len(data) != artifact["size_bytes"]
                or hashlib.sha256(data).hexdigest() != artifact["sha256"]
            ):
                reasons.append("source_bytes_changed")
                continue
            closure_projection.append(
                {
                    key: artifact[key]
                    for key in ("artifact_id", "logical_path", "sha256", "size_bytes")
                }
            )
            if artifact["artifact_id"] == candidate["entry_point_artifact_id"]:
                try:
                    meaningful = bool(_MEANINGFUL_SAS.search(decoded))
                except UnicodeDecodeError:  # pragma: no cover - decoded above
                    meaningful = False
        if (
            digest_value(sorted(closure_projection, key=lambda value: value["artifact_id"]))
            != candidate["source_closure_digest"]
        ):
            reasons.append("source_closure_mismatch")
        if set(candidate["closure_evidence_artifact_ids"]) != set(artifact_ids):
            reasons.append("incomplete_source_closure")
        if not meaningful:
            reasons.append("no_meaningful_sas_entry_point")
        discovered = discovery_by_id.get(workload_id)
        if discovered is None or digest_value(discovered) != candidate["discovery_workload_digest"]:
            reasons.append("discovery_binding_mismatch")
        else:
            reasons.extend(_canonical_closure_reasons(discovered, candidate))
        try:
            assessment_path = _safe_file(root, candidate["assessment"]["uri"], "assessment")
        except ValueError:
            reasons.append("assessment_missing_or_unsafe")
            assessment_path = None
        if assessment_path is None:
            pass
        elif _sha256(assessment_path) != candidate["assessment"]["digest"]:
            reasons.append("assessment_digest_mismatch")
        else:
            try:
                assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                reasons.append("assessment_invalid")
                assessment = {}
            if sanitize_discovery_value(assessment) != assessment:
                raise ValueError("Pilot assessment contains secret-bearing material")
            policy_path: Path | None
            try:
                policy_path = _safe_file(
                    root, candidate["assessment"]["policy_uri"], "complexity policy"
                )
            except ValueError:
                reasons.append("assessment_policy_missing_or_unsafe")
                policy_path = None
            complexity_policy = None
            if policy_path is not None:
                try:
                    complexity_policy = load_workload_complexity_policy(policy_path)
                except ValueError:
                    reasons.append("assessment_policy_invalid")
                else:
                    if (
                        complexity_policy.policy_digest != candidate["assessment"]["policy_digest"]
                        or complexity_policy.policy_digest
                        not in policy["approval_policy"]["workload_complexity_policy_digests"]
                    ):
                        reasons.append("assessment_policy_not_trusted")
            try:
                governed = load_workload_complexity_result(assessment_path)
            except ValueError:
                reasons.append("assessment_invalid")
                governed = {}
            if governed and complexity_policy is not None:
                try:
                    verify_workload_complexity_attestation(
                        governed, complexity_policy, verified_at=verified_at
                    )
                except ValueError as exc:
                    reason = str(exc)
                    if reason in {
                        "assessment_policy_pending",
                        "assessment_policy_denied",
                        "assessment_policy_expired",
                        "assessment_policy_failed",
                        "assessment_policy_blocked",
                    }:
                        reasons.append(reason)
                    else:
                        reasons.append("assessment_attestation_invalid")
            required_bindings = {
                "client_id": raw["client_id"],
                "workload_id": workload_id,
                "boundary_id": candidate["boundary_id"],
                "entry_point_artifact_id": candidate["entry_point_artifact_id"],
                "source_closure_digest": candidate["source_closure_digest"],
                "workload_digest": candidate["discovery_workload_digest"],
                "discovery_digest": raw["discovery_snapshot"]["content_digest"],
                "run_id": raw["run_id"],
                "attempt_id": raw["attempt_id"],
                "policy_digest": candidate["assessment"]["policy_digest"],
                "result_digest": candidate["assessment"]["result_digest"],
            }
            if any(governed.get(key) != value for key, value in required_bindings.items()):
                reasons.append("assessment_binding_mismatch")
            entry_digest = next(
                (
                    item["sha256"]
                    for item in governed.get("artifacts", [])
                    if item.get("artifact_id") == candidate["entry_point_artifact_id"]
                ),
                None,
            )
            expected_entry_digest = next(
                (
                    item["sha256"]
                    for item in artifacts
                    if item["artifact_id"] == candidate["entry_point_artifact_id"]
                ),
                None,
            )
            if entry_digest != expected_entry_digest:
                reasons.append("assessment_source_binding_mismatch")
            projections = governed.get("projections", {})
            expected_projections = {
                "complexity": governed.get("tier"),
                "complexity_score": governed.get("score"),
                "constructs": projections.get("constructs"),
                "macro_behaviors": projections.get("macro_behaviors"),
                "dependency_characteristics": projections.get("dependency_characteristics"),
                "data_access_categories": projections.get("data_access_categories"),
                "validation_difficulty": projections.get("validation_difficulty"),
            }
            if any(candidate.get(key) != value for key, value in expected_projections.items()):
                reasons.append("assessment_projection_mismatch")
            if governed.get("tier") == "unknown" or governed.get("blockers"):
                reasons.append("assessment_unqualified")
        prereqs = {item["prerequisite_id"]: item for item in candidate["prerequisites"]}
        if len(prereqs) != len(candidate["prerequisites"]):
            raise ValueError("Duplicate prerequisite identity")
        for prerequisite_id in policy["required_prerequisites"]:
            item = prereqs.get(prerequisite_id)
            if item is None:
                reasons.append(f"prerequisite_missing:{prerequisite_id}")
                continue
            failed_state = _verify_prerequisite(item, candidate, root, policy)
            if failed_state is not None:
                reasons.append(f"prerequisite_{failed_state}:{prerequisite_id}")
        blockers[workload_id] = tuple(sorted(set(reasons)))

    for item in raw["unprocessable"]:
        for script_id in item["script_ids"]:
            if script_id in identities["script"]:
                raise ValueError("Duplicate canonical script identity")
            identities["script"].add(script_id)
            all_scripts.add(script_id)
    if len(all_scripts) != raw["observed_unique_script_denominator"]:
        raise ValueError("Observed inventory denominator does not match unique script contents")
    return blockers, len(all_scripts)
