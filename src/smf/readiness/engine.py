"""Pure, fail-closed readiness evaluation over supplied durable evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from smf.discovery.include_reconciliation import (
    INCLUDE_POLICY_DIGEST,
    RESOLVER_ID,
    RESOLVER_VERSION,
)
from smf.discovery.macro_strategy import STRATEGY_DIGEST, STRATEGY_ID, STRATEGY_VERSION
from smf.readiness.attestation import has_valid_attestation
from smf.readiness.models import (
    BlockerCategory,
    CheckStatus,
    EvidenceReference,
    MissingEvidence,
    NextAction,
    PrerequisiteChecklistEntry,
    PrerequisiteState,
    ReadinessBlocker,
    ReadinessCheck,
    ReadinessClassification,
    ReadinessPolicy,
    ReadinessRequest,
    ReadinessResult,
)
from smf.readiness.policy import canonical_json, digest_value, serialize_readiness_policy
from smf.readiness.schema import validate_input_schema
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value


def _items(value: Any) -> list[dict[str, Any]]:
    # Input schema validation guarantees this shape. Keep this assertion here so
    # future callers cannot accidentally reintroduce lossy normalization.
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("Canonical workload collections must contain only objects")
    return value


def _ids(items: Iterable[dict[str, Any]], key: str) -> set[str]:
    return {str(item[key]) for item in items if isinstance(item.get(key), str)}


def _classification_for_missing() -> ReadinessClassification:
    return ReadinessClassification.NEEDS_EVIDENCE


def _is_canonical_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _include_relationship_valid(
    workload_id: str,
    relationship: dict[str, Any],
    artifact_by_id: dict[str, dict[str, Any]],
) -> bool:
    """Reconstruct the include decision identity from canonical workload facts."""

    metadata = relationship.get("metadata")
    if not isinstance(metadata, dict):
        return False
    state = metadata.get("include_resolution")
    valid_states = {
        "resolved",
        "dynamic",
        "missing",
        "ambiguous",
        "boundary_escape",
        "cyclic",
        "unsupported",
        "limit_exceeded",
    }
    if state not in valid_states:
        raise ValueError(f"Unsupported include resolution: {state!r}")
    source = artifact_by_id.get(str(relationship.get("source_id")))
    candidates = metadata.get("candidate_artifacts")
    if source is None or not isinstance(candidates, list | tuple):
        return False
    if (
        metadata.get("include_resolver_id") != RESOLVER_ID
        or metadata.get("include_resolver_version") != RESOLVER_VERSION
        or metadata.get("include_policy_digest") != INCLUDE_POLICY_DIGEST
        or metadata.get("source_checksum") != source.get("checksum")
        or not isinstance(metadata.get("byte_start"), int)
        or not isinstance(metadata.get("byte_end"), int)
        or metadata["byte_end"] <= metadata["byte_start"]
        or not _is_canonical_sha256(metadata.get("span_digest"))
        or not isinstance(metadata.get("normalized_reference"), str)
        or not metadata.get("normalized_reference")
        or not isinstance(metadata.get("considered_candidate_paths"), list | tuple)
    ):
        return False
    candidate_tuples: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False
        artifact = artifact_by_id.get(str(candidate.get("artifact_id")))
        if artifact is None or any(
            candidate.get(key) != artifact.get(key)
            for key in ("artifact_id", "logical_path", "checksum")
        ):
            return False
        candidate_tuples.append(
            {
                "artifact_id": candidate["artifact_id"],
                "logical_path": candidate["logical_path"],
                "checksum": candidate["checksum"],
            }
        )
    candidate_ids = tuple(item["artifact_id"] for item in candidate_tuples)
    if tuple(metadata.get("candidate_artifact_ids", ())) != candidate_ids:
        return False
    if state in {"resolved", "cyclic"} and (
        len(candidate_tuples) != 1
        or relationship.get("target_id") != candidate_tuples[0]["artifact_id"]
    ):
        return False
    if state == "ambiguous" and len(candidate_tuples) < 2:
        return False
    if state in {"dynamic", "missing", "boundary_escape", "unsupported"} and candidate_tuples:
        return False
    base_identity = {
        "workload": workload_id,
        "source_artifact": relationship.get("source_id"),
        "source_checksum": source.get("checksum"),
        "byte_start": metadata.get("byte_start"),
        "byte_end": metadata.get("byte_end"),
        "span_digest": metadata.get("span_digest"),
        "reference": metadata.get("normalized_reference"),
        "policy": INCLUDE_POLICY_DIGEST,
        "candidates": tuple(candidate_tuples),
        "state": "resolved" if state in {"cyclic", "limit_exceeded"} else state,
    }
    expected = stable_id("IRES", base_identity)
    if state in {"cyclic", "limit_exceeded"}:
        if metadata.get("pre_cycle_resolution_id") != expected:
            return False
        expected = stable_id("IRES", {"prior_resolution": expected, "state": state})
    return metadata.get("include_resolution_id") == expected


_RESULT_FIELDS = {
    "schema_version",
    "result_id",
    "prerequisite_id",
    "client_id",
    "deployment_id",
    "environment_id",
    "workload_id",
    "workload_digest",
    "boundary_id",
    "run_id",
    "attempt_id",
    "configuration_digest",
    "owner_assignment_ref",
    "authority",
    "acquisition_source",
    "execution_id",
    "decision_id",
    "checked_target",
    "status",
    "reason_code",
    "observed_at",
    "valid_until",
}


def _valid_result_payload(payload: Any, evidence: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or set(payload) != _RESULT_FIELDS:
        return False
    safe = sanitize_discovery_value(payload)
    if safe != payload:
        return False
    decision_identity = evidence.get("execution_id") or evidence.get("decision_id")
    expected = {
        "schema_version": "1.0",
        "result_id": decision_identity,
        "prerequisite_id": evidence.get("prerequisite_id"),
        "client_id": evidence.get("client_id"),
        "deployment_id": evidence.get("deployment_id"),
        "environment_id": evidence.get("environment_id"),
        "workload_id": evidence.get("workload_id"),
        "workload_digest": evidence.get("workload_digest"),
        "boundary_id": evidence.get("qualified_boundary_id"),
        "run_id": evidence.get("evidence_run_id"),
        "attempt_id": evidence.get("evidence_attempt_id"),
        "configuration_digest": evidence.get("configuration_digest"),
        "owner_assignment_ref": evidence.get("owner_assignment_ref"),
        "authority": evidence.get("authority"),
        "acquisition_source": evidence.get("acquisition_source"),
        "execution_id": evidence.get("execution_id"),
        "decision_id": evidence.get("decision_id"),
        "status": evidence.get("status"),
        "reason_code": evidence.get("reason_code"),
        "observed_at": evidence.get("observed_at"),
        "valid_until": evidence.get("valid_until"),
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        return False
    checked_target = payload.get("checked_target")
    return (
        isinstance(checked_target, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", checked_target) is not None
    )


def _verified_result_artifacts(
    evidence: list[dict[str, Any]], request: ReadinessRequest
) -> tuple[dict[str, Any], ...]:
    """Resolve prerequisite results once, then persist canonical verified bytes for replay."""

    supplied = {
        item.get("evidence_id"): item
        for item in request.result_artifacts
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    }
    if len(supplied) != len(request.result_artifacts):
        return ()
    root = request.result_root.resolve() if request.result_root is not None else None
    verified: list[dict[str, Any]] = []
    for item in evidence:
        if item.get("prerequisite_id") is None:
            continue
        evidence_id = str(item["evidence_id"])
        uri = item.get("result_uri")
        claimed_digest = item.get("result_digest")
        if not isinstance(uri, str) or not _is_canonical_sha256(claimed_digest):
            continue
        payload: Any
        existing = supplied.get(evidence_id)
        if existing is not None:
            if existing.get("result_uri") != uri or existing.get("result_digest") != claimed_digest:
                continue
            payload = existing.get("payload")
            content = canonical_json(payload).encode("utf-8")
        else:
            relative = Path(uri)
            if (
                root is None
                or not uri.startswith("results/")
                or relative.is_absolute()
                or relative.suffix != ".json"
                or any(part in {"", ".", ".."} for part in relative.parts)
            ):
                continue
            candidate = root / relative
            has_symlink = any(
                root.joinpath(*relative.parts[:index]).is_symlink()
                for index in range(1, len(relative.parts) + 1)
            )
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root) or not resolved.is_file() or has_symlink:
                continue
            try:
                content = resolved.read_bytes()
                if len(content) > 1024 * 1024:
                    continue
                payload = json.loads(content)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            # Persisting the parsed payload is byte-faithful only for canonical JSON.
            if content != canonical_json(payload).encode("utf-8"):
                continue
        actual_digest = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(actual_digest, str(claimed_digest)):
            continue
        if not _valid_result_payload(payload, item):
            continue
        verified.append(
            {
                "evidence_id": evidence_id,
                "result_uri": uri,
                "result_digest": claimed_digest,
                "payload": payload,
            }
        )
    return tuple(sorted(verified, key=lambda value: value["evidence_id"]))


def _verified_baseline_evidence(
    evidence: list[dict[str, Any]], request: ReadinessRequest, policy: ReadinessPolicy
) -> frozenset[str]:
    """Replay canonical BASE-01 results and hash their immutable output bytes."""

    from smf.baseline.manifest import load_baseline_result, readiness_evidence
    from smf.baseline.policy import baseline_policy_from_dict

    root = request.result_root.resolve() if request.result_root is not None else None
    verified: set[str] = set()
    for item in evidence:
        if item.get("kind") != "baseline" or item.get("baseline_result_id") is None:
            continue
        uri = item.get("result_uri")
        if root is None or not isinstance(uri, str):
            continue
        relative = Path(uri)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            continue
        candidate = root / relative
        if any(
            root.joinpath(*relative.parts[:index]).is_symlink()
            for index in range(1, len(relative.parts) + 1)
        ):
            continue
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root) or not resolved.is_file():
            continue
        try:
            raw_result = json.loads(resolved.read_text(encoding="utf-8"))
            if not isinstance(raw_result, dict):
                continue
            acquisition_policy = baseline_policy_from_dict(raw_result["policy_snapshot"])
            receipt = raw_result.get("receipt_snapshot") or {}
            proof = receipt.get("proof") or {}
            key_id = proof.get("key_id")
            approval = raw_result.get("approval") or {}
            approval_proof = approval.get("proof") or {}
            approval_key_id = approval_proof.get("key_id")
            acquisition_policy_matches = [
                trusted
                for trusted in policy.trusted_baseline_acquisition_policies
                if trusted["policy_digest"] == raw_result.get("policy_digest")
            ]
            if (
                len(acquisition_policy_matches) != 1
                or item.get("authority") not in policy.evidence_authorities["baseline"]
                or item.get("acquisition_source")
                not in policy.evidence_acquisition_sources["baseline"]
                or key_id not in policy.evidence_key_ids["baseline"]
                or acquisition_policy.payload.get("verification_keys", {}).get(key_id)
                != policy.verification_keys.get(key_id)
            ):
                continue
            trusted_acquisition = acquisition_policy_matches[0]
            if (
                receipt.get("producer_authority") not in trusted_acquisition["producer_authorities"]
                or key_id not in trusted_acquisition["producer_key_ids"]
                or approval.get("authority") not in trusted_acquisition["approval_authorities"]
                or approval_key_id not in trusted_acquisition["approval_key_ids"]
                or acquisition_policy.payload.get("verification_keys", {}).get(approval_key_id)
                != policy.verification_keys.get(str(approval_key_id))
            ):
                continue
            result = load_baseline_result(
                resolved, output_root=root, trusted_policy=acquisition_policy
            )
        except (KeyError, OSError, ValueError, json.JSONDecodeError):
            continue
        if result.get("content_digest") != item.get("result_digest"):
            continue
        projections = readiness_evidence(result)
        if sum(projection == item for projection in projections) != 1:
            continue
        if (
            item.get("workload_id") != request.workload.get("workload_id")
            or item.get("qualified_boundary_id") != request.boundary_id
            or item.get("evidence_run_id") != request.run_id
            or item.get("evidence_attempt_id") != request.attempt_id
        ):
            continue
        verified.add(str(item["evidence_id"]))
    return frozenset(verified)


def _has_attributable_discovery_evidence(value: Any) -> bool:
    return bool(value) and all(
        isinstance(item, dict)
        and all(
            isinstance(item.get(key), str) and item[key]
            for key in ("evidence_id", "method", "source", "confidence")
        )
        for item in value
    )


def approval_subject_digest(
    workload: dict[str, Any],
    evidence: Iterable[dict[str, Any]],
    *,
    policy_digest: str,
    run_id: str,
    attempt_id: str,
    boundary_id: str | None = None,
) -> str:
    """Identify the exact immutable technical qualification an approval covers."""

    safe_workload = sanitize_discovery_value(workload)
    technical_evidence = [item for item in evidence if item.get("kind") != "approval"]
    assert isinstance(safe_workload, dict)
    if boundary_id is not None:
        boundaries = _items(safe_workload.get("boundaries"))
        matching_boundaries = [
            item for item in boundaries if item.get("boundary_id") == boundary_id
        ]
        if len(matching_boundaries) != 1:
            raise ValueError("Approval boundary_id must identify exactly one workload boundary")
        boundary = matching_boundaries[0]
        scoped_subjects = {
            str(safe_workload.get("workload_id")),
            boundary_id,
            *map(str, boundary.get("artifact_ids", [])),
            *map(str, boundary.get("dataset_ids", [])),
            *map(str, boundary.get("external_dependency_ids", [])),
            *map(str, boundary.get("output_ids", [])),
        }
        technical_evidence = [
            item for item in technical_evidence if item.get("subject_id") in scoped_subjects
        ]
    safe_evidence = sanitize_discovery_value(technical_evidence)
    assert isinstance(safe_evidence, list)
    safe_evidence.sort(key=lambda item: str(item.get("evidence_id", "")))
    return digest_value(
        {
            "workload": safe_workload,
            "evidence": safe_evidence,
            "policy_digest": policy_digest,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "boundary_id": boundary_id,
        }
    )


def evaluate_readiness(
    request: ReadinessRequest,
    policy: ReadinessPolicy,
    *,
    _evaluated_at: datetime | None = None,
) -> ReadinessResult:
    """Evaluate an evidence bundle without acquiring or inventing missing facts."""

    started = time.monotonic_ns()
    safe_workload = sanitize_discovery_value(request.workload)
    safe_evidence = sanitize_discovery_value(list(request.evidence))
    assert isinstance(safe_workload, dict)
    assert isinstance(safe_evidence, list)
    unique_evidence: dict[str, dict[str, Any]] = {}
    for item in safe_evidence:
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str):
            raise ValueError("Evidence IDs must be present and unique")
        previous_evidence = unique_evidence.get(evidence_id)
        if previous_evidence is not None and previous_evidence != item:
            raise ValueError("Conflicting evidence records share an evidence ID")
        unique_evidence[evidence_id] = item
    safe_evidence = sorted(unique_evidence.values(), key=lambda item: str(item["evidence_id"]))
    validate_input_schema(
        {
            "workload": safe_workload,
            "evidence": safe_evidence,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
            "boundary_id": request.boundary_id,
            **(
                {"result_artifacts": list(request.result_artifacts)}
                if request.result_artifacts
                else {}
            ),
        }
    )
    verified_result_artifacts = _verified_result_artifacts(safe_evidence, request)
    verified_result_evidence_ids = {str(item["evidence_id"]) for item in verified_result_artifacts}
    verified_baseline_evidence_ids = _verified_baseline_evidence(safe_evidence, request, policy)
    workload_id = safe_workload.get("workload_id")
    if not isinstance(workload_id, str) or workload_id != request.workload.get("workload_id"):
        raise ValueError("Canonical workload_id is missing or unsafe")

    all_artifacts = _items(safe_workload.get("artifacts"))
    all_datasets = _items(safe_workload.get("datasets"))
    all_relationships = _items(safe_workload.get("relationships"))
    all_dependencies = _items(safe_workload.get("external_dependencies"))
    boundaries = _items(safe_workload.get("boundaries"))
    all_outputs = _items(safe_workload.get("outputs"))
    boundary_ids = _ids(boundaries, "boundary_id")
    if boundaries and not request.boundary_id:
        raise ValueError("boundary_id is required when workload boundaries exist")
    if request.boundary_id and request.boundary_id not in boundary_ids:
        raise ValueError("boundary_id does not belong to workload")

    all_artifact_ids = _ids(all_artifacts, "artifact_id")
    all_dataset_ids = _ids(all_datasets, "dataset_id")
    all_dependency_ids = _ids(all_dependencies, "dependency_id")
    all_output_ids = _ids(all_outputs, "output_id")
    identity_locations: dict[str, str] = {workload_id: "workload"}
    for collection, key, label in (
        (all_artifacts, "artifact_id", "artifact"),
        (all_datasets, "dataset_id", "dataset"),
        (all_dependencies, "dependency_id", "external dependency"),
        (all_outputs, "output_id", "output"),
        (boundaries, "boundary_id", "boundary"),
    ):
        for item in collection:
            canonical_id = str(item[key])
            previous = identity_locations.get(canonical_id)
            if previous is not None:
                raise ValueError(
                    f"Workload has duplicate canonical identity {canonical_id!r} "
                    f"for {previous} and {label}"
                )
            identity_locations[canonical_id] = label
    all_graph_subjects = all_artifact_ids | all_dataset_ids | all_dependency_ids
    artifact_by_id = {str(item["artifact_id"]): item for item in all_artifacts}
    for relationship in all_relationships:
        if relationship["source_id"] not in all_graph_subjects:
            raise ValueError("Relationship source_id does not belong to workload")
        if relationship["target_id"] not in all_graph_subjects:
            raise ValueError("Relationship target_id does not belong to workload")
        if relationship.get("kind") == "includes" and not _include_relationship_valid(
            workload_id, relationship, artifact_by_id
        ):
            raise ValueError("Include relationship has invalid or unbound resolution evidence")
    for output in all_outputs:
        if output["dataset_id"] not in all_dataset_ids:
            raise ValueError("Output dataset_id does not belong to workload")
    for boundary in boundaries:
        references = (
            ("artifact_ids", all_artifact_ids),
            ("dataset_ids", all_dataset_ids),
            ("external_dependency_ids", all_dependency_ids),
            ("output_ids", all_output_ids),
        )
        for key, known_ids in references:
            if any(item not in known_ids for item in boundary.get(key, [])):
                raise ValueError(f"Boundary {key} contains a cross-workload reference")

    graph = safe_workload.get("dependency_graph")
    if graph is not None:
        assert isinstance(graph, dict)
        graph_id = str(graph["graph_id"])
        previous = identity_locations.get(graph_id)
        if previous is not None:
            raise ValueError(
                f"Workload has duplicate canonical identity {graph_id!r} "
                f"for {previous} and dependency graph"
            )
        identity_locations[graph_id] = "dependency graph"
        for unresolved in _items(graph.get("unresolved")):
            unresolved_id = str(unresolved["unresolved_id"])
            previous = identity_locations.get(unresolved_id)
            if previous is not None:
                raise ValueError(
                    f"Workload has duplicate canonical identity {unresolved_id!r} "
                    f"for {previous} and unresolved dependency"
                )
            identity_locations[unresolved_id] = "unresolved dependency"
            if unresolved["source_id"] not in all_graph_subjects:
                raise ValueError("Unresolved dependency source_id does not belong to workload")

    selected_boundary = next(
        (item for item in boundaries if item["boundary_id"] == request.boundary_id), None
    )
    if selected_boundary is None:
        artifact_ids = all_artifact_ids
        dataset_ids = all_dataset_ids
        dependency_ids = all_dependency_ids
        output_ids = all_output_ids
    else:
        artifact_ids = set(map(str, selected_boundary.get("artifact_ids", [])))
        dataset_ids = set(map(str, selected_boundary.get("dataset_ids", [])))
        dependency_ids = set(map(str, selected_boundary.get("external_dependency_ids", [])))
        output_ids = set(map(str, selected_boundary.get("output_ids", [])))

        # A boundary is an admission scope, not merely a filtering hint. Reject
        # scopes that omit either endpoint of a discovered relationship; silently
        # dropping such an edge could hide required mappings or prerequisites.
        selected_graph_subjects = artifact_ids | dataset_ids | dependency_ids
        for relationship in all_relationships:
            source_selected = relationship["source_id"] in selected_graph_subjects
            target_selected = relationship["target_id"] in selected_graph_subjects
            if source_selected != target_selected:
                raise ValueError(
                    f"Boundary {request.boundary_id} is not closed over relationship "
                    f"{relationship['source_id']} -> {relationship['target_id']}"
                )
        for output in all_outputs:
            output_selected = output["output_id"] in output_ids
            dataset_selected = output["dataset_id"] in dataset_ids
            if output_selected != dataset_selected:
                raise ValueError(
                    f"Boundary {request.boundary_id} is not closed over output "
                    f"{output['output_id']} -> {output['dataset_id']}"
                )

    graph_subjects = artifact_ids | dataset_ids | dependency_ids
    artifacts = [item for item in all_artifacts if item["artifact_id"] in artifact_ids]
    dependencies = [item for item in all_dependencies if item["dependency_id"] in dependency_ids]
    outputs = [item for item in all_outputs if item["output_id"] in output_ids]
    relationships = [
        item
        for item in all_relationships
        if item["source_id"] in graph_subjects and item["target_id"] in graph_subjects
    ]

    known_subjects = (
        {workload_id}
        | all_artifact_ids
        | all_dataset_ids
        | all_dependency_ids
        | all_output_ids
        | boundary_ids
    )
    seen_evidence_ids: set[str] = set()
    scoped_evidence_ids: set[str] = set()
    scoped_subjects = {workload_id} | graph_subjects | output_ids
    if request.boundary_id is not None:
        scoped_subjects.add(request.boundary_id)
    scoped_evidence: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    stale_evidence: list[dict[str, Any]] = []
    now = _evaluated_at or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("Readiness evaluation time must be timezone-aware")
    now = now.astimezone(UTC)
    for item in safe_evidence:
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or evidence_id in seen_evidence_ids:
            raise ValueError("Evidence IDs must be present and unique")
        seen_evidence_ids.add(evidence_id)
        if item.get("workload_id") != workload_id:
            raise ValueError(f"Evidence {evidence_id} has a cross-workload reference")
        subject_id = item.get("subject_id")
        if subject_id not in known_subjects:
            raise ValueError(f"Evidence {evidence_id} references unknown subject {subject_id}")
        if subject_id not in scoped_subjects:
            continue
        scoped_evidence_ids.add(evidence_id)
        evidence_policy_digest = item.get("policy_digest")
        if evidence_policy_digest is not None and evidence_policy_digest != policy.policy_digest:
            raise ValueError(f"Evidence {evidence_id} has a policy digest mismatch")
        scoped_evidence.append(item)
        if policy.max_evidence_age_seconds is not None:
            observed_at = item.get("observed_at")
            try:
                observed = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
                if observed.tzinfo is None:
                    raise ValueError
                age = (now - observed.astimezone(UTC)).total_seconds()
            except (TypeError, ValueError):
                age = float("inf")
            if age < 0 or age > policy.max_evidence_age_seconds:
                stale_evidence.append(item)
            else:
                evidence.append(item)
        else:
            evidence.append(item)

    by_kind: dict[str, list[dict[str, Any]]] = {}
    for item in evidence:
        by_kind.setdefault(str(item["kind"]), []).append(item)

    checks: list[ReadinessCheck] = []
    prerequisite_checklist: list[PrerequisiteChecklistEntry] = []
    missing: list[MissingEvidence] = []

    def add(
        check_id: str,
        category: BlockerCategory,
        status: CheckStatus,
        classification: ReadinessClassification | None,
        subject_id: str,
        matched: Iterable[dict[str, Any]] = (),
        diagnostic: str = "",
    ) -> None:
        matched_items = tuple(matched)
        checks.append(
            ReadinessCheck(
                check_id=check_id,
                category=category,
                status=status,
                classification=classification,
                subject_id=subject_id,
                evidence_ids=tuple(sorted(str(item["evidence_id"]) for item in matched_items)),
                diagnostic=diagnostic,
            )
        )
        if status is CheckStatus.MISSING:
            missing.append(MissingEvidence(check_id, subject_id, diagnostic))

    def evidence_for(
        kind: str, subject_id: str, check_id: str | None = None
    ) -> list[dict[str, Any]]:
        return [
            item
            for item in by_kind.get(kind, [])
            if item.get("subject_id") == subject_id
            and (check_id is None or item.get("check_id") == check_id)
        ]

    def trusted_provenance(item: dict[str, Any], kind: str) -> bool:
        if kind == "baseline" and item.get("baseline_result_id") is not None:
            return str(item.get("evidence_id")) in verified_baseline_evidence_ids
        return item.get("policy_digest") == policy.policy_digest and has_valid_attestation(
            item,
            allowed_authorities=policy.evidence_authorities[kind],
            allowed_acquisition_sources=policy.evidence_acquisition_sources[kind],
            allowed_key_ids=policy.evidence_key_ids[kind],
            verification_keys=policy.verification_keys,
        )

    workload_digest = digest_value(safe_workload)
    approval_digest = approval_subject_digest(
        safe_workload,
        safe_evidence,
        policy_digest=policy.policy_digest,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
        boundary_id=request.boundary_id,
    )

    for item in stale_evidence:
        add(
            f"evidence-freshness:{item['evidence_id']}",
            BlockerCategory.EVIDENCE_INTEGRITY,
            CheckStatus.MISSING,
            ReadinessClassification.NEEDS_EVIDENCE,
            str(item["subject_id"]),
            (item,),
            "evidence timestamp is absent, invalid, future-dated, or stale",
        )

    # Per-item discovery labels cannot attest that omitted relationships or outputs
    # never existed. The governed snapshot binds the complete supplied inventory.
    discovery_candidates = evidence_for("discovery_snapshot", workload_id)
    governed_snapshot_candidates = [
        item
        for item in discovery_candidates
        if trusted_provenance(item, "discovery_snapshot")
        and item.get("workload_digest") == workload_digest
        and isinstance(item.get("snapshot_uri"), str)
        and bool(item.get("snapshot_uri"))
        and bool(item.get("execution_id"))
    ]
    governed_snapshots = [
        item for item in governed_snapshot_candidates if item.get("status") == "pass"
    ]
    discovery_denied = any(item.get("status") == "fail" for item in governed_snapshot_candidates)
    discovery_status = (
        CheckStatus.FAIL
        if discovery_denied
        else CheckStatus.PASS
        if governed_snapshots
        else CheckStatus.MISSING
    )
    add(
        "discovery-snapshot",
        BlockerCategory.DISCOVERY,
        discovery_status,
        ReadinessClassification.BLOCKED
        if discovery_denied
        else None
        if governed_snapshots
        else ReadinessClassification.NEEDS_EVIDENCE,
        workload_id,
        governed_snapshot_candidates or discovery_candidates,
        (
            "governed discovery snapshot failed or conflicts with another authoritative snapshot"
            if discovery_denied
            else "complete workload inventory lacks a matching governed discovery snapshot"
            if not governed_snapshots
            else ""
        ),
    )

    # Canonical source attribution and supported artifact inventory.
    if not any(item.get("kind") == "sas_program" for item in artifacts):
        add(
            "convertible-source",
            BlockerCategory.DISCOVERY,
            CheckStatus.MISSING,
            ReadinessClassification.NEEDS_EVIDENCE,
            workload_id,
            diagnostic="workload has no convertible SAS program entry point to qualify",
        )
    for artifact in sorted(artifacts, key=lambda item: str(item.get("artifact_id"))):
        artifact_id = str(artifact.get("artifact_id", "<unknown-artifact>"))
        source_ok = _is_canonical_sha256(artifact.get("checksum")) and bool(
            _has_attributable_discovery_evidence(artifact.get("evidence"))
        )
        add(
            f"discovery:{artifact_id}",
            BlockerCategory.DISCOVERY,
            CheckStatus.PASS if source_ok else CheckStatus.MISSING,
            None if source_ok else _classification_for_missing(),
            artifact_id,
            diagnostic="artifact requires canonical SHA-256 and attributable discovery evidence",
        )
        kind = str(artifact.get("kind", ""))
        supported = kind in policy.supported_artifact_kinds
        add(
            f"artifact-support:{artifact_id}",
            BlockerCategory.UNSUPPORTED_CONSTRUCT,
            CheckStatus.PASS if supported else CheckStatus.FAIL,
            None if supported else ReadinessClassification.UNSUPPORTED,
            artifact_id,
            diagnostic=(
                f"artifact kind {kind!r} is not supported by policy" if not supported else ""
            ),
        )

    macro_analysis = safe_workload.get("macro_analysis")
    if not isinstance(macro_analysis, dict):
        add(
            "macro-analysis",
            BlockerCategory.DISCOVERY,
            CheckStatus.MISSING,
            ReadinessClassification.NEEDS_EVIDENCE,
            workload_id,
            diagnostic="selected SAS artifacts lack canonical macro-analysis coverage",
        )
    else:
        snapshot = macro_analysis.get("strategy_snapshot")
        strategy_valid = (
            macro_analysis.get("workload_id") == workload_id
            and macro_analysis.get("strategy_id") == STRATEGY_ID
            and macro_analysis.get("strategy_version") == STRATEGY_VERSION
            and macro_analysis.get("strategy_digest") == STRATEGY_DIGEST
            and isinstance(snapshot, dict)
            and digest_value(snapshot) == STRATEGY_DIGEST
            and snapshot.get("expansion_mode") == "none"
            and macro_analysis.get("expansion_mode") == "none"
        )
        inventory_items = _items(macro_analysis.get("source_inventory"))
        inventory_pairs = [
            (str(item.get("source_artifact_id")), str(item.get("source_checksum")))
            for item in inventory_items
        ]
        expected_pairs = {
            (str(item["artifact_id"]), str(item.get("checksum")))
            for item in all_artifacts
            if item.get("kind") in {"sas_program", "sas_macro", "sas_include"}
        }
        inventory_valid = len(inventory_pairs) == len(
            set(inventory_pairs)
        ) and expected_pairs == set(inventory_pairs)
        observations = _items(macro_analysis.get("observations"))
        logical_artifacts = _items(macro_analysis.get("logical_artifacts"))
        resolutions = _items(macro_analysis.get("resolutions"))
        macro_blockers = _items(macro_analysis.get("blockers"))
        observation_ids = _ids(observations, "observation_id")
        logical_ids = _ids(logical_artifacts, "logical_artifact_id")
        resolution_ids = _ids(resolutions, "resolution_id")
        blocker_ids = _ids(macro_blockers, "blocker_id")
        required_resolution_observation_ids = {
            str(item["observation_id"])
            for item in observations
            if item.get("kind")
            in {
                "literal_invocation",
                "dynamic_invocation",
                "variable_reference",
                "include_reference",
                "intrinsic_operation",
                "quoting_operation",
            }
        }
        resolved_observation_ids = {str(item.get("observation_id")) for item in resolutions}
        include_relationship_resolution_ids = {
            str(item.get("metadata", {}).get("include_resolution_id"))
            for item in all_relationships
            if item.get("kind") == "includes"
        }
        macro_include_resolution_ids = {
            str(item.get("resolution_id"))
            for item in resolutions
            if item.get("relationship_kind") == "sas_include_reference"
        }
        expected_discovery_id = stable_id(
            "MDISC",
            {
                "workload": workload_id,
                "inventory": inventory_items,
                "strategy": STRATEGY_DIGEST,
            },
        )
        expected_analysis_id = stable_id(
            "MAN",
            {
                "discovery": expected_discovery_id,
                "workload": workload_id,
                "inventory": inventory_items,
                "strategy": STRATEGY_DIGEST,
                "limits": macro_analysis.get("limits_applied"),
                "logical_artifacts": sorted(logical_ids),
                "observations": sorted(observation_ids),
                "resolutions": sorted(resolution_ids),
                "blockers": sorted(blocker_ids),
                "complete": macro_analysis.get("complete"),
            },
        )
        identity_valid = (
            len(observation_ids) == len(observations)
            and len(logical_ids) == len(logical_artifacts)
            and len(resolution_ids) == len(resolutions)
            and len(blocker_ids) == len(macro_blockers)
            and required_resolution_observation_ids == resolved_observation_ids
            and include_relationship_resolution_ids == macro_include_resolution_ids
            and macro_analysis.get("discovery_id") == expected_discovery_id
            and macro_analysis.get("analysis_id") == expected_analysis_id
            and all(item.get("observation_id") in observation_ids for item in resolutions)
            and all(
                item.get("target_definition_id") is None
                or item.get("target_definition_id") in logical_ids
                for item in resolutions
            )
            and all(
                set(map(str, item.get("candidate_definition_ids", []))).issubset(logical_ids)
                for item in resolutions
            )
        )
        checksum_by_artifact = {
            str(item["artifact_id"]): str(item.get("checksum")) for item in all_artifacts
        }
        locations = [item.get("location") for item in (*observations, *logical_artifacts)]
        locations_valid = all(
            isinstance(location, dict)
            and location.get("source_artifact_id") in checksum_by_artifact
            and location.get("source_checksum")
            == checksum_by_artifact.get(str(location.get("source_artifact_id")))
            and int(location.get("byte_end", 0)) > int(location.get("byte_start", -1))
            for location in locations
        )
        macro_valid = (
            strategy_valid
            and inventory_valid
            and identity_valid
            and locations_valid
            and macro_analysis.get("complete") is True
        )
        add(
            "macro-analysis",
            BlockerCategory.DISCOVERY,
            CheckStatus.PASS if macro_valid else CheckStatus.MISSING,
            None if macro_valid else ReadinessClassification.NEEDS_EVIDENCE,
            workload_id,
            diagnostic=(
                "macro analysis is incomplete, unbound, duplicated, or uses an unapproved strategy"
                if not macro_valid
                else ""
            ),
        )
        for macro_blocker in sorted(macro_blockers, key=lambda item: str(item.get("blocker_id"))):
            source_artifact_id = macro_blocker.get("source_artifact_id")
            if source_artifact_id is not None and source_artifact_id not in artifact_ids:
                continue
            reason = str(macro_blocker.get("reason"))
            classification = policy.unresolved_dependencies.get(reason)
            if classification is None:
                raise ValueError(f"Policy does not define macro blocker reason {reason!r}")
            add(
                f"macro:{macro_blocker['blocker_id']}",
                BlockerCategory.DEPENDENCY,
                CheckStatus.FAIL,
                classification,
                str(source_artifact_id or workload_id),
                diagnostic=f"unresolved macro behavior: {reason}",
            )

    if graph is None:
        add(
            "dependency-graph",
            BlockerCategory.DEPENDENCY,
            CheckStatus.MISSING,
            ReadinessClassification.NEEDS_EVIDENCE,
            workload_id,
            diagnostic="canonical dependency graph is absent",
        )
    else:
        assert isinstance(graph, dict)
        add("dependency-graph", BlockerCategory.DEPENDENCY, CheckStatus.PASS, None, workload_id)
        for unresolved in sorted(
            _items(graph.get("unresolved")), key=lambda x: str(x.get("unresolved_id"))
        ):
            reason = str(unresolved.get("reason", ""))
            classification = policy.unresolved_dependencies.get(reason)
            if classification is None:
                raise ValueError(f"Policy does not define unresolved dependency reason {reason!r}")
            unresolved_id = str(unresolved.get("unresolved_id", "<unknown-dependency>"))
            if unresolved["source_id"] not in graph_subjects:
                continue
            add(
                f"dependency:{unresolved_id}",
                BlockerCategory.DEPENDENCY,
                CheckStatus.FAIL,
                classification,
                str(unresolved.get("source_id", workload_id)),
                diagnostic=f"unresolved {reason} dependency: {unresolved.get('reference', '')}",
            )

    # Each SAS entry point requires an attributable assessment.
    assessment_items = by_kind.get("assessment", [])
    review_required = False
    required_assessment_outputs = (
        "complexity",
        "risk_factors",
        "unsupported_constructs",
    )
    for artifact in sorted(artifacts, key=lambda item: str(item.get("artifact_id"))):
        if artifact.get("kind") != "sas_program":
            continue
        artifact_id = str(artifact["artifact_id"])
        candidates = evidence_for("assessment", artifact_id)
        matched = [item for item in candidates if trusted_provenance(item, "assessment")]
        if not matched:
            add(
                f"assessment:{artifact_id}",
                BlockerCategory.ASSESSMENT,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                artifact_id,
                matched=candidates,
                diagnostic=(
                    "assessment evidence lacks a valid governed attestation"
                    if candidates
                    else "convertible entry point has no assessment evidence"
                ),
            )
            continue
        incomplete = [
            item
            for item in matched
            if any(field not in item for field in required_assessment_outputs)
        ]
        if incomplete:
            absent_outputs = sorted(
                {
                    field
                    for item in incomplete
                    for field in required_assessment_outputs
                    if field not in item
                }
            )
            add(
                f"assessment-completeness:{artifact_id}",
                BlockerCategory.ASSESSMENT,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                artifact_id,
                matched,
                "governed assessment is missing decision-critical outputs: "
                + ", ".join(absent_outputs),
            )
        failed = any(item["status"] == "fail" for item in matched)
        pending_assessment = any(item["status"] == "pending" for item in matched)
        unsupported = sorted(
            {str(value) for item in matched for value in item.get("unsupported_constructs", [])}
        )
        classification = (
            ReadinessClassification.UNSUPPORTED
            if unsupported
            else ReadinessClassification.BLOCKED
            if failed
            else ReadinessClassification.NEEDS_EVIDENCE
            if pending_assessment
            else None
        )
        add(
            f"assessment:{artifact_id}",
            BlockerCategory.UNSUPPORTED_CONSTRUCT if unsupported else BlockerCategory.ASSESSMENT,
            CheckStatus.MISSING
            if pending_assessment and not failed and not unsupported
            else CheckStatus.FAIL
            if classification
            else CheckStatus.PASS,
            classification,
            artifact_id,
            matched,
            f"confirmed unsupported constructs: {', '.join(unsupported)}"
            if unsupported
            else "assessment is pending governed completion"
            if pending_assessment
            else "assessment failed",
        )
        review_required = review_required or any(
            str(item.get("complexity", "")) in policy.human_review_complexities
            or bool(
                set(map(str, item.get("risk_factors", []))) & set(policy.human_review_risk_factors)
            )
            for item in matched
        )

    artifact_checksums = {str(item.get("artifact_id")): item.get("checksum") for item in artifacts}
    for item in assessment_items:
        expected = item.get("source_checksum")
        subject = str(item["subject_id"])
        if expected is None:
            raise ValueError(f"Evidence {item['evidence_id']} has no source checksum")
        if expected != artifact_checksums.get(subject):
            raise ValueError(f"Evidence {item['evidence_id']} has a source checksum mismatch")

    input_dataset_ids = {
        str(item.get("target_id"))
        for item in relationships
        if item.get("kind") in {"reads", "consumes"}
    }
    output_dataset_ids = {
        str(item.get("target_id"))
        for item in relationships
        if item.get("kind") in {"writes", "produces"}
    } | {str(item.get("dataset_id")) for item in outputs if item.get("dataset_id")}

    for output in sorted(outputs, key=lambda item: str(item.get("output_id"))):
        output_id = str(output["output_id"])
        resolution = output.get("consumer_resolution")
        consumers = output.get("consumer_ids")
        resolved = (
            resolution == "confirmed"
            and isinstance(consumers, list)
            and bool(consumers)
            and all(isinstance(item, str) and item for item in consumers)
        )
        add(
            f"output-lineage:{output_id}",
            BlockerCategory.DEPENDENCY,
            CheckStatus.PASS if resolved else CheckStatus.MISSING,
            None if resolved else ReadinessClassification.NEEDS_EVIDENCE,
            output_id,
            diagnostic=(
                "downstream consumer lineage requires concrete attributable consumer identities"
                if not resolved
                else ""
            ),
        )

    def check_mapping(dataset_id: str, direction: str) -> None:
        candidates = [
            item
            for item in evidence_for("dataset_mapping", dataset_id)
            if item.get("direction") in {direction, "both"}
        ]
        matched = [item for item in candidates if trusted_provenance(item, "dataset_mapping")]
        if not matched:
            add(
                f"mapping:{direction}:{dataset_id}",
                BlockerCategory.DATASET_MAPPING,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                dataset_id,
                candidates,
                diagnostic=(
                    f"approved {direction} dataset mapping lacks policy-trusted provenance"
                    if candidates
                    else f"approved {direction} dataset mapping is absent"
                ),
            )
            return
        governed_decisions = {
            (
                str(item["decision_id"]),
                str(item["target_dataset_id"]),
                str(item["target_catalog"]),
                str(item["target_schema"]),
                str(item["mapping_digest"]),
            )
            for item in matched
        }
        if len(governed_decisions) > 1:
            add(
                f"mapping:{direction}:{dataset_id}",
                BlockerCategory.DATASET_MAPPING,
                CheckStatus.FAIL,
                ReadinessClassification.BLOCKED,
                dataset_id,
                matched,
                "conflicting governed decisions exist for the same dataset and direction",
            )
            return
        failed = any(
            item["status"] != "pass" or not item.get("approved", False) for item in matched
        )
        add(
            f"mapping:{direction}:{dataset_id}",
            BlockerCategory.DATASET_MAPPING,
            CheckStatus.FAIL if failed else CheckStatus.PASS,
            ReadinessClassification.BLOCKED if failed else None,
            dataset_id,
            matched,
            "dataset mapping failed or is not approved" if failed else "",
        )

    if policy.require_input_mappings:
        for dataset_id in sorted(input_dataset_ids):
            check_mapping(dataset_id, "input")
    if policy.require_output_mappings:
        for dataset_id in sorted(output_dataset_ids):
            check_mapping(dataset_id, "output")

    for dataset_id in sorted(output_dataset_ids):
        candidates = evidence_for("baseline", dataset_id)
        trusted = [item for item in candidates if trusted_provenance(item, "baseline")]
        if not trusted:
            add(
                f"baseline:{dataset_id}",
                BlockerCategory.BASELINE,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                dataset_id,
                matched=candidates,
                diagnostic=(
                    "baseline evidence lacks a valid governed attestation"
                    if candidates
                    else "authoritative source-executed baseline is absent"
                ),
            )
            continue
        matched = [
            item
            for item in trusted
            if item.get("workload_digest") == workload_digest
            and item.get("qualified_boundary_id") == request.boundary_id
        ]
        if not matched:
            add(
                f"baseline:{dataset_id}",
                BlockerCategory.BASELINE,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                dataset_id,
                trusted,
                "baseline execution inputs do not match the exact qualified workload revision",
            )
            continue
        reconstructable = all(
            isinstance(item.get("artifact_uri"), str)
            and bool(item.get("artifact_uri"))
            and item.get("artifact_digest") is not None
            and item.get("schema_digest") is not None
            and isinstance(item.get("measurement_ids"), list)
            and bool(item.get("measurement_ids"))
            and all(isinstance(value, str) and value for value in item["measurement_ids"])
            for item in matched
        )
        if not reconstructable:
            add(
                f"baseline:{dataset_id}",
                BlockerCategory.BASELINE,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                dataset_id,
                matched,
                "baseline lacks a retrievable immutable artifact, verified digest, "
                "schema, or measurement set",
            )
            continue
        governed_baselines = {
            (
                item.get("baseline_result_id"),
                item.get("acquisition_id"),
                item.get("output_id"),
                item.get("artifact_digest"),
                item.get("schema_digest"),
                item.get("source_execution_id"),
                item.get("execution_receipt_digest"),
                item.get("runtime_configuration_digest"),
                item.get("acquisition_policy_digest"),
                item.get("input_snapshot_digest"),
                item.get("result_digest"),
            )
            for item in matched
        }
        if len(governed_baselines) > 1:
            add(
                f"baseline:{dataset_id}",
                BlockerCategory.BASELINE,
                CheckStatus.FAIL,
                ReadinessClassification.BLOCKED,
                dataset_id,
                matched,
                "conflicting authoritative baseline decisions exist for the same subject",
            )
            continue
        valid = all(
            item["status"] == "pass"
            and item.get("authority") in policy.required_baseline_authorities
            and _is_canonical_sha256(item.get("checksum"))
            and _is_canonical_sha256(item.get("artifact_digest"))
            and item.get("artifact_digest") == item.get("checksum")
            and _is_canonical_sha256(item.get("schema_digest"))
            and (not policy.require_source_execution_id or bool(item.get("source_execution_id")))
            for item in matched
        )
        add(
            f"baseline:{dataset_id}",
            BlockerCategory.BASELINE,
            CheckStatus.PASS if valid else CheckStatus.FAIL,
            None if valid else ReadinessClassification.BLOCKED,
            dataset_id,
            matched,
            "baseline is not deterministic, authoritative, or linked to source execution"
            if not valid
            else "",
        )

    def check_named(kind: str, check_id: str, subject_id: str, category: BlockerCategory) -> None:
        candidates = evidence_for(kind, subject_id, check_id)
        matched = [item for item in candidates if trusted_provenance(item, kind)]
        if not matched:
            add(
                f"{kind}:{check_id}:{subject_id}",
                category,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                subject_id,
                candidates,
                diagnostic=(
                    f"required {kind} check {check_id!r} lacks policy-trusted provenance"
                    if candidates
                    else f"required {kind} check {check_id!r} is absent"
                ),
            )
            return
        failed = any(item["status"] != "pass" for item in matched)
        add(
            f"{kind}:{check_id}:{subject_id}",
            category,
            CheckStatus.FAIL if failed else CheckStatus.PASS,
            ReadinessClassification.BLOCKED if failed else None,
            subject_id,
            matched,
            f"required {kind} check {check_id!r} failed" if failed else "",
        )

    for check_id in policy.required_environment_checks:
        check_named("environment", check_id, workload_id, BlockerCategory.ENVIRONMENT)
    for check_id in policy.required_runtime_checks:
        check_named("runtime", check_id, workload_id, BlockerCategory.RUNTIME)

    binding = policy.prerequisite_binding
    if policy.prerequisites:
        if binding is None:  # Defensive fail closed if a caller bypasses policy loading.
            raise ValueError("Readiness prerequisite policy lacks an environment binding")
        for definition in policy.prerequisites:
            prerequisite_id = str(definition["prerequisite_id"])
            kind = str(definition["evidence_kind"])
            category = BlockerCategory.RUNTIME if kind == "runtime" else BlockerCategory.ENVIRONMENT
            candidates = [
                item
                for item in scoped_evidence
                if item.get("kind") == kind
                and item.get("subject_id") == workload_id
                and item.get("check_id") == prerequisite_id
            ]
            identity_bound = [
                item
                for item in candidates
                if trusted_provenance(item, kind)
                and item.get("prerequisite_id") == prerequisite_id
                and item.get("client_id") == binding["client_id"]
                and item.get("deployment_id") == binding["deployment_id"]
                and item.get("environment_id") == binding["environment_id"]
                and item.get("configuration_digest") == binding["configuration_digest"]
                and item.get("workload_digest") == workload_digest
                and item.get("qualified_boundary_id") == request.boundary_id
                and item.get("evidence_run_id") == request.run_id
                and item.get("evidence_attempt_id") == request.attempt_id
                and definition["owner_assignment_ref"] is not None
                and item.get("owner_assignment_ref") == definition["owner_assignment_ref"]
                and bool(item.get("execution_id") or item.get("decision_id"))
                and (
                    (item.get("status") == "pass" and item.get("reason_code") is None)
                    or (item.get("status") == "fail" and item.get("reason_code") == "access_denied")
                    or (
                        item.get("status") == "pending"
                        and item.get("reason_code") == "approval_pending"
                    )
                )
            ]
            attributable = [
                item
                for item in identity_bound
                if item.get("evidence_id") in verified_result_evidence_ids
            ]
            current: list[dict[str, Any]] = []
            expired: list[dict[str, Any]] = []
            for item in attributable:
                try:
                    observed = datetime.fromisoformat(
                        str(item["observed_at"]).replace("Z", "+00:00")
                    )
                    evidence_expires = datetime.fromisoformat(
                        str(item["valid_until"]).replace("Z", "+00:00")
                    )
                    valid = (
                        observed.tzinfo is not None
                        and evidence_expires.tzinfo is not None
                        and observed.astimezone(UTC) <= now
                        and evidence_expires.astimezone(UTC) >= now
                        and evidence_expires.astimezone(UTC) >= observed.astimezone(UTC)
                        and (now - observed.astimezone(UTC)).total_seconds()
                        <= int(definition["max_age_seconds"])
                    )
                except (KeyError, TypeError, ValueError):
                    valid = False
                (current if valid else expired).append(item)

            statuses = {str(item["status"]) for item in current}
            governed_results = {
                (
                    str(item["status"]),
                    str(item.get("execution_id") or item.get("decision_id")),
                    str(item["result_uri"]),
                    str(item["result_digest"]),
                )
                for item in current
            }
            if len(statuses) > 1 or len(governed_results) > 1:
                state = PrerequisiteState.CONFLICTING
                classification_for_check = ReadinessClassification.BLOCKED
                reason_code = "evidence_conflict"
                status = CheckStatus.FAIL
                selected = current
            elif statuses == {"fail"}:
                state = PrerequisiteState.DENIED
                classification_for_check = ReadinessClassification.BLOCKED
                reason_code = "access_denied"
                status = CheckStatus.FAIL
                selected = current
            elif statuses == {"pending"}:
                state = PrerequisiteState.PENDING
                classification_for_check = ReadinessClassification.HUMAN_REQUIRED
                reason_code = "approval_pending"
                status = CheckStatus.MISSING
                selected = current
            elif statuses == {"pass"}:
                state = PrerequisiteState.PASS
                classification_for_check = None
                reason_code = None
                status = CheckStatus.PASS
                selected = current
            elif expired:
                state = PrerequisiteState.EXPIRED
                classification_for_check = ReadinessClassification.NEEDS_EVIDENCE
                reason_code = "evidence_expired"
                status = CheckStatus.MISSING
                selected = expired
            else:
                state = PrerequisiteState.MISSING
                classification_for_check = ReadinessClassification.NEEDS_EVIDENCE
                reason_code = (
                    "result_unverifiable"
                    if identity_bound
                    else "binding_mismatch"
                    if candidates
                    else "evidence_missing"
                )
                status = CheckStatus.MISSING
                selected = candidates

            diagnostic = (
                ""
                if state is PrerequisiteState.PASS
                else (f"prerequisite {prerequisite_id!r} is {state.value}: {reason_code}")
            )
            add(
                f"prerequisite:{prerequisite_id}",
                category,
                status,
                classification_for_check,
                workload_id,
                selected,
                diagnostic,
            )
            observed_values = sorted(
                str(item["observed_at"]) for item in selected if item.get("observed_at")
            )
            expiry_values = sorted(
                str(item["valid_until"]) for item in selected if item.get("valid_until")
            )
            prerequisite_checklist.append(
                PrerequisiteChecklistEntry(
                    prerequisite_id=prerequisite_id,
                    domain=str(definition["domain"]),
                    evidence_kind=kind,
                    subject_id=workload_id,
                    state=state,
                    owner_role=str(definition["owner_role"]),
                    requirement_refs=tuple(str(item) for item in definition["requirement_refs"]),
                    owner_assignment_ref=(
                        str(definition["owner_assignment_ref"])
                        if definition["owner_assignment_ref"] is not None
                        else None
                    ),
                    evidence_ids=tuple(sorted(str(item["evidence_id"]) for item in selected)),
                    evidence_digests=tuple(sorted(digest_value(item) for item in selected)),
                    result_uris=tuple(
                        sorted(
                            str(item["result_uri"]) for item in selected if item.get("result_uri")
                        )
                    ),
                    result_digests=tuple(
                        sorted(
                            str(item["result_digest"])
                            for item in selected
                            if item.get("result_digest")
                        )
                    ),
                    observed_at=observed_values[-1] if observed_values else None,
                    valid_until=expiry_values[0] if expiry_values else None,
                    blocker_reason_code=reason_code,
                    next_action=str(definition["next_action"]),
                )
            )
    for dependency in sorted(dependencies, key=lambda item: str(item.get("dependency_id"))):
        dependency_id = str(dependency["dependency_id"])
        candidates = evidence_for("environment", dependency_id)
        matched = [item for item in candidates if trusted_provenance(item, "environment")]
        if not matched:
            add(
                f"environment:dependency:{dependency_id}",
                BlockerCategory.ENVIRONMENT,
                CheckStatus.MISSING,
                ReadinessClassification.NEEDS_EVIDENCE,
                dependency_id,
                candidates,
                diagnostic=(
                    "external dependency environment evidence lacks policy-trusted provenance"
                    if candidates
                    else "external dependency has no current environment evidence"
                ),
            )
        else:
            failed = any(item["status"] != "pass" for item in matched)
            add(
                f"environment:dependency:{dependency_id}",
                BlockerCategory.ENVIRONMENT,
                CheckStatus.FAIL if failed else CheckStatus.PASS,
                ReadinessClassification.BLOCKED if failed else None,
                dependency_id,
                matched,
                "external dependency environment check failed" if failed else "",
            )

    approval_candidates = evidence_for("approval", request.boundary_id or workload_id)
    approvals = [
        item
        for item in approval_candidates
        if trusted_provenance(item, "approval")
        and "approved_boundary_id" in item
        and item.get("approved_run_id") == request.run_id
        and item.get("approved_attempt_id") == request.attempt_id
        and item.get("approved_boundary_id") == request.boundary_id
        and item.get("approved_workload_digest") == workload_digest
        and item.get("qualification_subject_digest") == approval_digest
    ]
    denied = any(item["status"] == "fail" for item in approvals)
    approved = bool(approvals) and all(item["status"] == "pass" for item in approvals)
    if denied:
        add(
            "human-approval",
            BlockerCategory.HUMAN_APPROVAL,
            CheckStatus.FAIL,
            ReadinessClassification.BLOCKED,
            request.boundary_id or workload_id,
            approvals,
            "governed human approval was denied",
        )
    elif review_required and not approved:
        add(
            "human-approval",
            BlockerCategory.HUMAN_APPROVAL,
            CheckStatus.MISSING,
            ReadinessClassification.HUMAN_REQUIRED,
            request.boundary_id or workload_id,
            approval_candidates,
            (
                "policy requires approval with policy-trusted provenance"
                if approval_candidates
                else "policy requires explicit human approval for assessed complexity or risk"
            ),
        )
    elif review_required:
        add(
            "human-approval",
            BlockerCategory.HUMAN_APPROVAL,
            CheckStatus.PASS,
            None,
            request.boundary_id or workload_id,
            approvals,
        )

    checks.sort(key=lambda item: item.check_id)
    prerequisite_checklist.sort(key=lambda item: item.prerequisite_id)
    findings = {item.classification for item in checks if item.classification is not None}
    classification = next(
        (item for item in policy.classification_precedence if item in findings),
        ReadinessClassification.READY,
    )
    blockers = tuple(
        ReadinessBlocker(
            blocker_id=stable_id("RBLK", {"check": item.check_id, "workload": workload_id}),
            category=item.category,
            classification=item.classification,
            owner=policy.owners[item.category.value],
            subject_id=item.subject_id,
            evidence_ids=item.evidence_ids,
            diagnostic=item.diagnostic,
        )
        for item in checks
        if item.classification is not None
    )
    action_categories = sorted({item.category for item in blockers}, key=lambda item: item.value)
    next_actions = tuple(
        NextAction(category, policy.owners[category.value], policy.next_actions[category.value])
        for category in action_categories
    )
    verified_result_artifacts = tuple(
        item for item in verified_result_artifacts if item["evidence_id"] in scoped_evidence_ids
    )
    digest_input = {
        "workload": safe_workload,
        "evidence": scoped_evidence,
        "policy_digest": policy.policy_digest,
    }
    if policy.prerequisites:
        digest_input["result_artifacts"] = list(verified_result_artifacts)
    input_digest = digest_value(digest_input)
    qualification_input = {
        "workload": safe_workload,
        "evidence": scoped_evidence,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "boundary_id": request.boundary_id,
    }
    if policy.prerequisites:
        qualification_input["result_artifacts"] = list(verified_result_artifacts)
    policy_snapshot = serialize_readiness_policy(policy)
    evidence_references = tuple(
        EvidenceReference(
            evidence_id=str(item["evidence_id"]),
            kind=str(item["kind"]),
            subject_id=str(item["subject_id"]),
            status=str(item["status"]),
            evidence_digest=digest_value(item),
            source_checksum=item.get("source_checksum"),
            target_dataset_id=item.get("target_dataset_id"),
            target_catalog=item.get("target_catalog"),
            target_schema=item.get("target_schema"),
            mapping_digest=item.get("mapping_digest"),
            authority=item.get("authority"),
            source_execution_id=item.get("source_execution_id"),
            acquisition_source=item.get("acquisition_source"),
            execution_id=item.get("execution_id"),
            decision_id=item.get("decision_id"),
            approver_id=item.get("approver_id"),
            observed_at=item.get("observed_at"),
            attestation_key_id=(item.get("proof") or {}).get("key_id"),
            workload_digest=item.get("workload_digest"),
            qualified_boundary_id=item.get("qualified_boundary_id"),
            snapshot_uri=item.get("snapshot_uri"),
            artifact_uri=item.get("artifact_uri"),
            artifact_digest=item.get("artifact_digest"),
            schema_digest=item.get("schema_digest"),
            qualification_subject_digest=item.get("qualification_subject_digest"),
            approved_run_id=item.get("approved_run_id"),
            approved_attempt_id=item.get("approved_attempt_id"),
            approved_boundary_id=item.get("approved_boundary_id"),
            approved_workload_digest=item.get("approved_workload_digest"),
            client_id=item.get("client_id"),
            deployment_id=item.get("deployment_id"),
            environment_id=item.get("environment_id"),
            prerequisite_id=item.get("prerequisite_id"),
            configuration_digest=item.get("configuration_digest"),
            evidence_run_id=item.get("evidence_run_id"),
            evidence_attempt_id=item.get("evidence_attempt_id"),
            result_uri=item.get("result_uri"),
            result_digest=item.get("result_digest"),
            valid_until=item.get("valid_until"),
            owner_assignment_ref=item.get("owner_assignment_ref"),
            reason_code=item.get("reason_code"),
            workload_revision_id=item.get("workload_revision_id"),
            baseline_result_id=item.get("baseline_result_id"),
            acquisition_id=item.get("acquisition_id"),
            acquisition_mode=item.get("acquisition_mode"),
            acquisition_policy_digest=item.get("acquisition_policy_digest"),
            execution_receipt_digest=item.get("execution_receipt_digest"),
            input_snapshot_digest=item.get("input_snapshot_digest"),
            runtime_configuration_digest=item.get("runtime_configuration_digest"),
            output_id=item.get("output_id"),
        )
        for item in scoped_evidence
    )
    identity = {
        "workload_id": workload_id,
        "boundary_id": request.boundary_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "policy_digest": policy.policy_digest,
        "input_digest": input_digest,
        "classification": classification.value,
        "checks": [item.check_id for item in checks],
    }
    result_id = stable_id("READY", identity)
    evaluated_at = now.isoformat()
    result_valid_until: str | None = None
    if policy.max_evidence_age_seconds is not None:
        observed_times: list[datetime] = []
        for item in scoped_evidence:
            try:
                observed = datetime.fromisoformat(
                    str(item.get("observed_at")).replace("Z", "+00:00")
                )
            except ValueError:
                continue
            if observed.tzinfo is not None:
                observed_times.append(observed.astimezone(UTC))
        oldest = min(observed_times, default=now)
        result_valid_until = (
            oldest + timedelta(seconds=policy.max_evidence_age_seconds)
        ).isoformat()
    prerequisite_expirations: list[datetime] = []
    for checklist_entry in prerequisite_checklist:
        if (
            checklist_entry.state is not PrerequisiteState.PASS
            or checklist_entry.valid_until is None
        ):
            continue
        expires = datetime.fromisoformat(checklist_entry.valid_until.replace("Z", "+00:00"))
        prerequisite_expirations.append(expires.astimezone(UTC))
    if prerequisite_expirations:
        earliest = min(prerequisite_expirations).isoformat()
        if result_valid_until is None or earliest < result_valid_until:
            result_valid_until = earliest
    result = ReadinessResult(
        schema_version="1.0",
        result_id=result_id,
        workload_id=workload_id,
        boundary_id=request.boundary_id,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_digest=policy.policy_digest,
        input_digest=input_digest,
        workload_digest=workload_digest,
        qualification_input=qualification_input,
        policy_snapshot=policy_snapshot,
        evidence_references=evidence_references,
        classification=classification,
        checks=tuple(checks),
        prerequisite_checklist=tuple(prerequisite_checklist),
        blockers=blockers,
        missing_evidence=tuple(
            sorted(missing, key=lambda item: (item.evidence_kind, item.subject_id))
        ),
        next_actions=next_actions,
        evidence_ids=tuple(sorted(scoped_evidence_ids)),
        evaluated_at=evaluated_at,
        valid_until=result_valid_until,
        elapsed_ms=max(0, (time.monotonic_ns() - started) // 1_000_000),
        terminal_disposition="admitted"
        if classification is ReadinessClassification.READY
        else "not_admitted",
    )
    payload = result.to_dict()
    payload.pop("content_digest")
    return ReadinessResult(**{**result.__dict__, "content_digest": digest_value(payload)})
