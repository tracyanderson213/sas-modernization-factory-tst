"""Deterministic workload-level complexity assessment over canonical discovery evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from smf.assessment.workload_policy import WorkloadComplexityPolicy, workload_policy_digest
from smf.assessment.workload_schema import validate_workload_complexity_result
from smf.readiness.policy import digest_value
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MEANINGFUL_SAS = re.compile(r"(?im)^\s*(?:data\s+[A-Za-z_]|proc\s+[A-Za-z_]|%macro\s+[A-Za-z_])")
_SUPPORTED_FEATURES = {
    "sas_program",
    "sas_macro_artifact",
    "sas_include_artifact",
    "format_catalog",
    "dependency_edge",
    "unresolved_dependency",
    "external_dependency",
    "dataset",
    "data_relationship",
    "eligible_artifact",
    "meaningful_entry_point",
    "macro_observation",
    "macro_dynamic",
    "macro_external",
    "macro_cyclic",
    "macro_runtime_dependent",
    "macro_unsupported",
    "macro_unresolved",
    "macro_blocker",
}


@dataclass(frozen=True)
class WorkloadComplexityRequest:
    client_id: str
    workload_id: str
    boundary_id: str
    run_id: str
    attempt_id: str
    execution_id: str
    discovery_snapshot: dict[str, Any]
    source_closure: tuple[dict[str, Any], ...]
    source_root: Path


def _safe_id(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}")
    if sanitize_discovery_value(value) != value or contains_protected_data(value):
        raise ValueError(f"Unsafe {label}")
    return value


def _safe_source(root: Path, relative: str) -> Path:
    if not relative or urlparse(relative).scheme:
        raise ValueError("Unsafe source artifact reference")
    decoded = relative
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    path = Path(decoded)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Unsafe source artifact reference")
    resolved_root = root.resolve()
    has_symlink = any(
        root.joinpath(*path.parts[:index]).is_symlink() for index in range(1, len(path.parts) + 1)
    )
    resolved = (root / path).resolve()
    if has_symlink or not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError("Source artifact reference escapes or is missing")
    return resolved


def _unique(items: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        identity = item.get(key)
        if not isinstance(identity, str) or identity in result:
            raise ValueError(f"Duplicate or malformed {label} identity")
        result[identity] = item
    return result


def _add_observation(
    observations: dict[str, dict[str, Any]],
    *,
    dimension_id: str,
    feature_id: str,
    subject_id: str,
    evidence_id: str,
    origin_digest: str,
    method: str,
) -> None:
    canonical_identity = digest_value(
        {
            "dimension_id": dimension_id,
            "feature_id": feature_id,
            "subject_id": subject_id,
            "evidence_id": evidence_id,
            "origin_digest": origin_digest,
            "method": method,
        }
    )
    if canonical_identity in observations:
        return
    observations[canonical_identity] = {
        "observation_id": stable_id("OBS", canonical_identity),
        "canonical_identity": canonical_identity,
        "dimension_id": dimension_id,
        "feature_id": feature_id,
        "subject_id": subject_id,
        "evidence_id": evidence_id,
        "method": method,
        "origin_digest": origin_digest,
        "locator": f"evidence://{evidence_id}",
    }


def _policy_state(policy: dict[str, Any], now: datetime) -> str | None:
    if policy["status"] != "active":
        return str(policy["status"])
    start = datetime.fromisoformat(policy["valid_from"].replace("Z", "+00:00"))
    end = (
        datetime.fromisoformat(policy["valid_until"].replace("Z", "+00:00"))
        if policy["valid_until"]
        else None
    )
    if now < start:
        return "pending"
    if end is not None and now > end:
        return "expired"
    return None


def assess_workload_complexity(
    request: WorkloadComplexityRequest,
    policy: WorkloadComplexityPolicy,
    *,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    """Assess one exact workload boundary without accepting projected scores."""

    for label, value in (
        ("client_id", request.client_id),
        ("workload_id", request.workload_id),
        ("boundary_id", request.boundary_id),
        ("run_id", request.run_id),
        ("attempt_id", request.attempt_id),
        ("execution_id", request.execution_id),
    ):
        _safe_id(value, label)
    if sanitize_discovery_value(
        request.discovery_snapshot
    ) != request.discovery_snapshot or contains_protected_data(
        json.dumps(request.discovery_snapshot, sort_keys=True)
    ):
        raise ValueError("Discovery snapshot contains protected or secret-bearing values")
    if sanitize_discovery_value(list(request.source_closure)) != list(
        request.source_closure
    ) or contains_protected_data(json.dumps(request.source_closure, sort_keys=True)):
        raise ValueError("Source closure contains protected or secret-bearing values")
    if workload_policy_digest(policy.payload) != policy.policy_digest:
        raise ValueError("Workload complexity policy object is not canonical")
    if request.client_id not in policy.payload["allowed_clients"]:
        raise ValueError("Workload complexity client is outside policy scope")
    if (
        request.discovery_snapshot.get("provider")
        not in policy.payload["authoritative_versions"]["discovery_providers"]
    ):
        raise ValueError("Discovery provider is not authoritative for this policy")
    unknown_features = {
        feature["feature_id"]
        for dimension in policy.payload["dimensions"]
        for feature in dimension["features"]
    } - _SUPPORTED_FEATURES
    if unknown_features:
        raise ValueError("Workload complexity policy contains unsupported feature identifiers")

    workloads = request.discovery_snapshot.get("workloads")
    if not isinstance(workloads, list):
        raise ValueError("Canonical discovery workloads are missing")
    matches = [item for item in workloads if item.get("workload_id") == request.workload_id]
    if len(matches) != 1:
        raise ValueError("Canonical workload is missing or ambiguous")
    workload = matches[0]
    artifacts = _unique(workload.get("artifacts", []), "artifact_id", "artifact")
    boundaries = _unique(workload.get("boundaries", []), "boundary_id", "boundary")
    if request.boundary_id not in boundaries:
        raise ValueError("Canonical boundary is missing")
    boundary = boundaries[request.boundary_id]
    boundary_ids = boundary.get("artifact_ids")
    if (
        not isinstance(boundary_ids, list)
        or not boundary_ids
        or len(boundary_ids) != len(set(boundary_ids))
    ):
        raise ValueError("Canonical boundary closure is empty or ambiguous")
    entry_id = (boundary.get("metadata") or {}).get("entry_point_artifact_id")
    if not isinstance(entry_id, str) or entry_id not in boundary_ids:
        raise ValueError("Canonical boundary lacks a unique eligible entry point")

    closure = _unique(list(request.source_closure), "artifact_id", "source closure artifact")
    if set(closure) != set(boundary_ids):
        raise ValueError("Source closure does not match the canonical boundary")
    closure_projection: list[dict[str, Any]] = []
    source_bytes: dict[str, bytes] = {}
    meaningful_entry = False
    for artifact_id in sorted(closure):
        item = closure[artifact_id]
        canonical = artifacts.get(artifact_id)
        if (
            canonical is None
            or canonical.get("checksum") != item.get("sha256")
            or canonical.get("logical_path") != item.get("logical_path")
        ):
            raise ValueError("Source closure artifact binding mismatch")
        path = _safe_source(request.source_root, str(item.get("source_uri", "")))
        data = path.read_bytes()
        if len(data) != item.get("size_bytes") or hashlib.sha256(data).hexdigest() != item.get(
            "sha256"
        ):
            raise ValueError("Qualified source bytes changed")
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Eligible SAS source is not UTF-8") from exc
        if sanitize_discovery_value(decoded) != decoded or contains_protected_data(decoded):
            raise ValueError("Source closure contains protected or secret-bearing values")
        if artifact_id == entry_id:
            meaningful_entry = bool(_MEANINGFUL_SAS.search(decoded))
        source_bytes[artifact_id] = data
        closure_projection.append(
            {
                key: item[key]
                for key in (
                    "artifact_id",
                    "logical_path",
                    "source_uri",
                    "sha256",
                    "size_bytes",
                )
            }
        )
    if not meaningful_entry:
        raise ValueError("Canonical boundary has no meaningful SAS entry point")

    graph = workload.get("dependency_graph")
    if not isinstance(graph, dict) or not isinstance(graph.get("graph_id"), str):
        raise ValueError("Canonical dependency graph is missing")
    graph_nodes = _unique(graph.get("nodes", []), "node_id", "dependency node")
    graph_edges = _unique(graph.get("edges", []), "edge_id", "dependency edge")
    unresolved = _unique(graph.get("unresolved", []), "unresolved_id", "unresolved dependency")
    artifact_nodes: dict[str, str] = {}
    for node_id, node in graph_nodes.items():
        if node.get("kind") == "artifact":
            entity_id = node.get("entity_id")
            if not isinstance(entity_id, str) or entity_id in artifact_nodes:
                raise ValueError("Duplicate dependency artifact identity")
            artifact_nodes[entity_id] = node_id
    if not set(boundary_ids).issubset(artifact_nodes):
        raise ValueError("Dependency graph omits boundary artifacts")
    adjacency: dict[str, set[str]] = {artifact_nodes[item]: set() for item in boundary_ids}
    for edge in graph_edges.values():
        source = edge.get("source_id")
        target = edge.get("target_id")
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
    pending = [artifact_nodes[entry_id]]
    reached: set[str] = set()
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        reached.add(current)
        pending.extend(adjacency[current] - reached)
    if {item for item, node in artifact_nodes.items() if node in reached} != set(boundary_ids):
        raise ValueError("Dependency graph does not reconstruct the complete source closure")

    dimension_by_feature = {
        feature["feature_id"]: dimension["dimension_id"]
        for dimension in policy.payload["dimensions"]
        for feature in dimension["features"]
    }
    observations: dict[str, dict[str, Any]] = {}

    def observe(feature: str, subject: str, evidence: str, origin: Any, method: str) -> None:
        dimension = dimension_by_feature.get(feature)
        if dimension is not None:
            _add_observation(
                observations,
                dimension_id=dimension,
                feature_id=feature,
                subject_id=subject,
                evidence_id=evidence,
                origin_digest=digest_value(origin),
                method=method,
            )

    kind_features = {
        "sas_program": "sas_program",
        "sas_macro": "sas_macro_artifact",
        "sas_include": "sas_include_artifact",
        "format_catalog": "format_catalog",
    }
    for artifact_id in sorted(boundary_ids):
        artifact = artifacts[artifact_id]
        observe("eligible_artifact", artifact_id, artifact_id, artifact, "filesystem")
        artifact_kind = artifact.get("kind")
        feature = kind_features.get(artifact_kind) if isinstance(artifact_kind, str) else None
        if feature:
            observe(feature, artifact_id, artifact_id, artifact, "static_analysis")
    observe("meaningful_entry_point", entry_id, entry_id, closure[entry_id], "filesystem")
    for edge_id, edge in sorted(graph_edges.items()):
        if edge.get("source_id") in adjacency:
            observe("dependency_edge", str(edge.get("source_id")), edge_id, edge, "static_analysis")
    for item_id, item in sorted(unresolved.items()):
        observe(
            "unresolved_dependency", str(item.get("source_id")), item_id, item, "static_analysis"
        )
    external = _unique(
        workload.get("external_dependencies", []), "dependency_id", "external dependency"
    )
    for item_id, item in sorted(external.items()):
        observe("external_dependency", item_id, item_id, item, "static_analysis")
    datasets = _unique(workload.get("datasets", []), "dataset_id", "dataset")
    for item_id, item in sorted(datasets.items()):
        observe("dataset", item_id, item_id, item, "static_analysis")
    relationships = _unique(workload.get("relationships", []), "relationship_id", "relationship")
    for item_id, item in sorted(relationships.items()):
        if item.get("kind") in {"reads", "writes", "produces", "consumes"}:
            observe(
                "data_relationship", str(item.get("source_id")), item_id, item, "static_analysis"
            )

    macro = workload.get("macro_analysis")
    macro_status = "unknown"
    if isinstance(macro, dict):
        strategy_digest = macro.get("strategy_digest")
        if (
            strategy_digest
            not in policy.payload["authoritative_versions"]["macro_strategy_digests"]
        ):
            raise ValueError("Macro analysis strategy is not authoritative for this policy")
        inventories = macro.get("source_inventory")
        if not isinstance(inventories, list):
            raise ValueError("Macro analysis source binding mismatch")
        inventory = _unique(inventories, "source_artifact_id", "macro source inventory")
        if set(inventory) != set(boundary_ids) or any(
            inventory[artifact_id].get("source_checksum") != closure[artifact_id]["sha256"]
            for artifact_id in boundary_ids
        ):
            raise ValueError("Macro analysis source binding mismatch")
        macro_status = "observed" if macro.get("complete") is True else "partial"
        macro_observations = _unique(
            macro.get("observations", []), "observation_id", "macro observation"
        )
        for item_id, item in sorted(macro_observations.items()):
            location = item.get("location")
            if not isinstance(location, dict):
                raise ValueError("Macro analysis source binding mismatch")
            source_artifact_id = location.get("source_artifact_id")
            if (
                source_artifact_id not in closure
                or location.get("source_checksum") != closure[source_artifact_id]["sha256"]
            ):
                raise ValueError("Macro analysis source binding mismatch")
            byte_start = location.get("byte_start")
            byte_end = location.get("byte_end")
            data = source_bytes[source_artifact_id]
            if (
                not isinstance(byte_start, int)
                or isinstance(byte_start, bool)
                or not isinstance(byte_end, int)
                or isinstance(byte_end, bool)
                or byte_start < 0
                or byte_end <= byte_start
                or byte_end > len(data)
                or location.get("span_digest")
                != hashlib.sha256(data[byte_start:byte_end]).hexdigest()
            ):
                raise ValueError("Macro analysis source binding mismatch")
            observe(
                "macro_observation",
                str(item.get("normalized_identity")),
                item_id,
                item,
                "static_analysis",
            )
            if item.get("kind") == "dynamic_invocation":
                observe(
                    "macro_dynamic",
                    str(item.get("normalized_identity")),
                    item_id,
                    item,
                    "static_analysis",
                )
        resolution_feature = {
            "missing": "macro_unresolved",
            "ambiguous": "macro_unresolved",
            "dynamic": "macro_dynamic",
            "cyclic": "macro_cyclic",
            "runtime_dependent": "macro_runtime_dependent",
            "unsupported": "macro_unsupported",
        }
        resolutions = _unique(macro.get("resolutions", []), "resolution_id", "macro resolution")
        for item_id, item in sorted(resolutions.items()):
            resolution_kind = item.get("kind")
            feature = (
                resolution_feature.get(resolution_kind)
                if isinstance(resolution_kind, str)
                else None
            )
            if feature:
                observe(feature, str(item.get("observation_id")), item_id, item, "static_analysis")
        macro_blockers = _unique(macro.get("blockers", []), "blocker_id", "macro blocker")
        for item_id, item in sorted(macro_blockers.items()):
            observe(
                "macro_blocker",
                str(item.get("source_artifact_id") or entry_id),
                item_id,
                item,
                "static_analysis",
            )

    status_by_dimension = {
        "static_constructs": "observed",
        "dependency_topology": "observed",
        "data_access": "observed",
        "source_scale": "observed",
        "macro_behavior": macro_status,
        "validation_difficulty": (
            "observed"
            if macro_status == "observed"
            else "partial"
            if macro_status == "partial"
            else "unknown"
        ),
    }
    policy_dimensions = {item["dimension_id"]: item for item in policy.payload["dimensions"]}
    if set(policy_dimensions) != set(status_by_dimension):
        raise ValueError("Policy must define the complete supported dimension registry")

    dimension_results: list[dict[str, Any]] = []
    scored_observations: list[dict[str, Any]] = []
    for dimension_id in sorted(policy_dimensions):
        definition = policy_dimensions[dimension_id]
        contribution = 0
        feature_results: list[dict[str, Any]] = []
        for feature in sorted(definition["features"], key=lambda item: item["feature_id"]):
            matched = sorted(
                [
                    item
                    for item in observations.values()
                    if item["feature_id"] == feature["feature_id"]
                ],
                key=lambda item: item["canonical_identity"],
            )
            count = min(len(matched), feature["max_count"])
            points = count * feature["weight"]
            contribution += points
            feature_results.append(
                {
                    "feature_id": feature["feature_id"],
                    "observed_count": len(matched),
                    "counted_count": count,
                    "weight": feature["weight"],
                    "contribution": points,
                    "observation_ids": [item["observation_id"] for item in matched],
                }
            )
            scored_observations.extend(matched)
        capped = min(contribution, definition["cap"])
        dimension_results.append(
            {
                "dimension_id": dimension_id,
                "status": status_by_dimension[dimension_id],
                "required": definition["required"],
                "tier_critical": definition["tier_critical"],
                "raw_contribution": contribution,
                "contribution": capped,
                "cap": definition["cap"],
                "cap_applied": capped != contribution,
                "features": feature_results,
            }
        )
    scored_observations = sorted(
        {item["canonical_identity"]: item for item in scored_observations}.values(),
        key=lambda item: item["canonical_identity"],
    )
    current_score = sum(item["contribution"] for item in dimension_results)
    unknowns = [item["dimension_id"] for item in dimension_results if item["status"] != "observed"]
    tier_blocking = [
        item["dimension_id"]
        for item in dimension_results
        if item["tier_critical"] and item["status"] != "observed"
    ]
    tier = "unknown"
    if not tier_blocking:
        tier = max(
            (
                item["tier"]
                for item in policy.payload["thresholds"]
                if current_score >= item["min_score"]
            ),
            key=lambda item: ["simple", "moderate", "complex", "highly_complex"].index(item),
        )
    maximum_score = current_score + sum(
        item["cap"] - item["contribution"]
        for item in dimension_results
        if item["status"] != "observed"
    )
    blockers = [
        f"required_dimension_{item['status']}:{item['dimension_id']}"
        for item in dimension_results
        if item["required"] and item["status"] != "observed"
    ]
    instant = (evaluated_at or datetime.now(UTC)).astimezone(UTC)
    inactive_state = _policy_state(policy.payload, instant)
    if inactive_state is not None:
        blockers.append(f"policy_{inactive_state}")
        tier = "unknown"

    constructs = sorted(
        {
            item["feature_id"]
            for item in scored_observations
            if item["dimension_id"] == "static_constructs"
        }
    )
    macro_behaviors = sorted(
        {
            {
                "macro_dynamic": "dynamic",
                "macro_external": "external",
                "macro_cyclic": "cyclic",
                "macro_runtime_dependent": "runtime_dependent",
                "macro_unsupported": "unsupported",
                "macro_unresolved": "unresolved",
            }.get(item["feature_id"], "static")
            for item in scored_observations
            if item["dimension_id"] == "macro_behavior"
        }
    ) or (["none"] if macro_status == "observed" else ["unresolved"])
    dependency_characteristics = sorted(
        ({"internal"} if graph_edges else {"isolated"})
        | ({"external"} if external else set())
        | ({"unresolved"} if unresolved else set())
        | (
            {"cyclic"}
            if any(item.get("reason") == "cyclic" for item in unresolved.values())
            else set()
        )
    )
    data_access = sorted(
        {
            {
                "sas_dataset": "files",
                "database_table": "database",
                "file": "files",
                "api": "api",
                "external_feed": "warehouse",
                "intermediate": "files",
                "unknown": "unknown",
            }.get(str(item.get("kind")), "unknown")
            for item in datasets.values()
        }
    ) or ["none"]
    validation_difficulty = (
        "unknown"
        if status_by_dimension["validation_difficulty"] != "observed"
        else "high"
        if unresolved
        or any(
            value in macro_behaviors for value in ("dynamic", "cyclic", "unsupported", "unresolved")
        )
        else "medium"
        if graph_edges or datasets
        else "low"
    )
    discovery_digest = digest_value(request.discovery_snapshot)
    workload_digest = digest_value(workload)
    closure_digest = digest_value(
        [
            {key: artifact[key] for key in ("artifact_id", "logical_path", "sha256", "size_bytes")}
            for artifact in closure_projection
        ]
    )
    graph_digest = digest_value(graph)
    macro_digest = digest_value(macro) if isinstance(macro, dict) else None
    assessment_id = stable_id(
        "WCA",
        {
            "client_id": request.client_id,
            "workload_id": request.workload_id,
            "boundary_id": request.boundary_id,
            "source_closure_digest": closure_digest,
            "policy_digest": policy.policy_digest,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
            "execution_id": request.execution_id,
        },
    )
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "assessment_id": assessment_id,
        "client_id": request.client_id,
        "workload_id": request.workload_id,
        "boundary_id": request.boundary_id,
        "entry_point_artifact_id": entry_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "execution_id": request.execution_id,
        "discovery_digest": discovery_digest,
        "workload_digest": workload_digest,
        "source_closure_digest": closure_digest,
        "artifacts": closure_projection,
        "dependency_graph_id": graph["graph_id"],
        "dependency_graph_digest": graph_digest,
        "macro_analysis_id": macro.get("analysis_id") if isinstance(macro, dict) else None,
        "macro_analysis_digest": macro_digest,
        "macro_strategy_digest": macro.get("strategy_digest") if isinstance(macro, dict) else None,
        "policy_id": policy.payload["policy_id"],
        "policy_version": policy.payload["policy_version"],
        "policy_digest": policy.policy_digest,
        "strategy_id": policy.payload["strategy"]["strategy_id"],
        "strategy_version": policy.payload["strategy"]["strategy_version"],
        "dimensions": dimension_results,
        "observations": scored_observations,
        "score": current_score,
        "tier": tier,
        "confidence_basis": "complete_tier_critical_dimensions"
        if not tier_blocking
        else "incomplete_tier_critical_dimensions",
        "unknowns": unknowns,
        "blockers": sorted(blockers),
        "warnings": [],
        "sensitivity": {
            "current_score": current_score,
            "minimum_score": current_score,
            "maximum_score": maximum_score,
            "unknown_dimensions": unknowns,
            "threshold_distance": {
                item["tier"]: item["min_score"] - current_score
                for item in policy.payload["thresholds"]
            },
        },
        "projections": {
            "constructs": constructs,
            "macro_behaviors": macro_behaviors,
            "dependency_characteristics": dependency_characteristics,
            "data_access_categories": data_access,
            "validation_difficulty": validation_difficulty,
        },
        "evaluated_at": instant.isoformat(),
        "authorizes_readiness": False,
        "authorizes_execution": False,
        "authorizes_parity": False,
        "authorizes_certification": False,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
        "proof": None,
    }
    result["result_digest"] = digest_value(result)
    validate_workload_complexity_result(result)
    return result
