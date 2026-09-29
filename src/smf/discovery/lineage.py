"""Occurrence-bound, evidence-backed static SAS data-lineage derivation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from typing import Any

from smf.discovery.sas_data import (
    LINEAGE_POLICY_DIGEST,
    LINEAGE_STRATEGY_ID,
    LINEAGE_STRATEGY_VERSION,
    dataset_access_id,
)
from smf.workload.identity import stable_id
from smf.workload.models import (
    DataAccessObservation,
    DataLineageAnalysis,
    DataLineageBlocker,
    DataLineageBlockerReason,
    DataProducerResolution,
    Dataset,
    DatasetIdentityResolution,
    DatasetKind,
    DatasetLineageResolution,
    DiscoveryEvidence,
    Relationship,
    RelationshipKind,
    Workload,
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _merge_evidence(*groups: tuple[DiscoveryEvidence, ...]) -> tuple[DiscoveryEvidence, ...]:
    merged: dict[str, DiscoveryEvidence] = {}
    for group in groups:
        for item in group:
            merged[item.evidence_id] = item
    return tuple(merged[key] for key in sorted(merged))


def _assert_unique(label: str, values: tuple[Any, ...], key: str) -> None:
    identifiers = [getattr(item, key) for item in values]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"Duplicate canonical {label} identity")


def _relationship(
    workload: Workload,
    *,
    source_id: str,
    kind: RelationshipKind,
    target_id: str,
    evidence: tuple[DiscoveryEvidence, ...],
    metadata: dict[str, object] | None = None,
) -> Relationship:
    details = metadata or {}
    identity = {
        "workload": workload.workload_id,
        "source": source_id,
        "kind": kind.value,
        "target": target_id,
    }
    dependency_domain = details.get("dependency_domain")
    if isinstance(dependency_domain, str):
        identity["dependency_domain"] = dependency_domain
    source_access_id = details.get("source_access_id")
    consumer_access_id = details.get("consumer_access_id")
    if isinstance(source_access_id, str):
        identity["source_access_id"] = source_access_id
    if isinstance(consumer_access_id, str):
        identity["consumer_access_id"] = consumer_access_id
    return Relationship(
        relationship_id=stable_id("REL", identity),
        source_id=source_id,
        kind=kind,
        target_id=target_id,
        evidence=evidence,
        metadata=details,
    )


def _identity_resolution(dataset: Dataset) -> DatasetIdentityResolution:
    raw = dataset.metadata.get("resolution")
    if raw is None:
        return DatasetIdentityResolution.RESOLVED
    try:
        return DatasetIdentityResolution(str(raw))
    except ValueError as exc:
        raise ValueError(f"Unsupported dataset identity resolution: {raw!r}") from exc


def _access_observation(
    relationship: Relationship,
    *,
    workload_id: str,
    artifacts: dict[str, Any],
    datasets: dict[str, Dataset],
    artifact_bytes: dict[str, bytes] | None,
) -> DataAccessObservation | None:
    if relationship.kind not in {RelationshipKind.READS, RelationshipKind.WRITES}:
        return None
    artifact = artifacts.get(relationship.source_id)
    dataset = datasets.get(relationship.target_id)
    if artifact is None or dataset is None:
        raise ValueError("Dataset access relationship references an unknown artifact or dataset")
    if len(relationship.evidence) != 1:
        if artifact.checksum is None:
            return None
        raise ValueError("Dataset access requires exactly one occurrence evidence record")
    evidence = relationship.evidence[0]
    metadata = evidence.metadata
    if metadata.get("observation") != "sas_dataset_access":
        if artifact.checksum is None:
            return None
        raise ValueError("Checksum-bound SAS access is missing canonical occurrence evidence")

    required = {
        "access_id",
        "artifact_id",
        "artifact_checksum",
        "role",
        "normalized_reference",
        "identity_resolution",
        "line",
        "column",
        "byte_start",
        "byte_end",
        "source_checksum",
        "span_digest",
        "lineage_policy_digest",
    }
    missing = sorted(required - metadata.keys())
    if missing:
        raise ValueError("Dataset access evidence is incomplete: " + ", ".join(missing))
    if not isinstance(relationship.kind, RelationshipKind):
        raise ValueError(f"Unsupported dataset access role: {relationship.kind!r}")
    if metadata["role"] != relationship.kind.value:
        raise ValueError("Dataset access role does not match relationship role")
    if metadata["artifact_id"] != artifact.artifact_id:
        raise ValueError("Dataset access artifact identity mismatch")
    if not isinstance(artifact.checksum, str) or not _SHA256_RE.fullmatch(artifact.checksum):
        raise ValueError("Dataset access artifact revision must be a canonical SHA-256 checksum")
    if metadata["artifact_checksum"] != artifact.checksum:
        raise ValueError("Dataset access artifact checksum mismatch")
    if metadata["source_checksum"] != artifact.checksum:
        raise ValueError("Dataset access source checksum mismatch")
    if metadata["lineage_policy_digest"] != LINEAGE_POLICY_DIGEST:
        raise ValueError("Dataset access lineage policy digest mismatch")
    for field in ("line", "column", "byte_start", "byte_end"):
        if not isinstance(metadata[field], int):
            raise ValueError(f"Dataset access {field} must be an integer")
    if metadata["line"] < 1 or metadata["column"] < 1:
        raise ValueError("Dataset access source location is invalid")
    if metadata["byte_start"] < 0 or metadata["byte_end"] <= metadata["byte_start"]:
        raise ValueError("Dataset access byte range is invalid")
    if not isinstance(metadata["span_digest"], str) or not _SHA256_RE.fullmatch(
        metadata["span_digest"]
    ):
        raise ValueError("Dataset access span digest must be a canonical SHA-256 checksum")
    resolution = _identity_resolution(dataset)
    if metadata["identity_resolution"] != resolution.value:
        raise ValueError("Dataset access identity resolution mismatch")
    normalized_reference = dataset.metadata.get("canonical_dataset_name", dataset.name)
    if metadata["normalized_reference"] != normalized_reference:
        raise ValueError("Dataset access normalized reference mismatch")
    if artifact_bytes is None or artifact.artifact_id not in artifact_bytes:
        raise ValueError("Dataset access requires immutable acquired source bytes")
    acquired_bytes = artifact_bytes[artifact.artifact_id]
    if hashlib.sha256(acquired_bytes).hexdigest() != artifact.checksum:
        raise ValueError("Dataset access acquired source checksum mismatch")
    byte_start = int(metadata["byte_start"])
    byte_end = int(metadata["byte_end"])
    if byte_end > len(acquired_bytes):
        raise ValueError("Dataset access byte range exceeds acquired source bytes")
    span = acquired_bytes[byte_start:byte_end]
    if hashlib.sha256(span).hexdigest() != metadata["span_digest"]:
        raise ValueError("Dataset access span digest mismatch")
    try:
        prefix = acquired_bytes[:byte_start].decode("utf-8", errors="strict")
        span_text = span.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Dataset access span is not valid UTF-8 source text") from exc
    expected_line = prefix.count("\n") + 1
    expected_column = len(prefix.rsplit("\n", 1)[-1]) + 1
    if metadata["line"] != expected_line or metadata["column"] != expected_column:
        raise ValueError("Dataset access line or column does not match acquired source bytes")
    if not isinstance(evidence.observed_value, str) or (
        span_text.casefold() != evidence.observed_value.casefold()
    ):
        raise ValueError("Dataset access span does not match its observed source reference")
    expected_access_id = dataset_access_id(
        workload_id=workload_id,
        artifact_id=artifact.artifact_id,
        artifact_checksum=artifact.checksum,
        role=relationship.kind.value,
        normalized_reference=str(normalized_reference),
        line=int(metadata["line"]),
        column=int(metadata["column"]),
        byte_start=int(metadata["byte_start"]),
        byte_end=int(metadata["byte_end"]),
        source_checksum=str(metadata["source_checksum"]),
        span_digest=str(metadata["span_digest"]),
        dataset_kind=dataset.kind.value,
        dataset_system=dataset.system,
        dataset_location=dataset.location,
        identity_resolution=resolution.value,
        scope_discriminator=(
            str(dataset.metadata["scope_discriminator"])
            if dataset.metadata.get("scope_discriminator") is not None
            else None
        ),
    )
    if metadata["access_id"] != expected_access_id:
        raise ValueError("Dataset access identity does not match occurrence evidence")
    expected_relationship_id = stable_id(
        "REL",
        {
            "workload": workload_id,
            "source": relationship.source_id,
            "kind": relationship.kind.value,
            "target": relationship.target_id,
            "occurrence": {"access_id": expected_access_id},
        },
    )
    if relationship.relationship_id != expected_relationship_id:
        raise ValueError("Dataset access relationship identity mismatch")

    return DataAccessObservation(
        access_id=str(metadata["access_id"]),
        role=relationship.kind,
        artifact_id=artifact.artifact_id,
        artifact_checksum=artifact.checksum,
        source_path=artifact.logical_path or artifact.name,
        normalized_reference=str(normalized_reference),
        dataset_id=dataset.dataset_id,
        identity_resolution=resolution,
        line=int(metadata["line"]),
        column=int(metadata["column"]),
        byte_start=int(metadata["byte_start"]),
        byte_end=int(metadata["byte_end"]),
        source_checksum=str(metadata["source_checksum"]),
        span_digest=str(metadata["span_digest"]),
        policy_digest=str(metadata["lineage_policy_digest"]),
        relationship_id=relationship.relationship_id,
    )


def _blocker(
    workload: Workload,
    reason: DataLineageBlockerReason,
    *,
    dataset_id: str | None = None,
    access_id: str | None = None,
    detail: str,
) -> DataLineageBlocker:
    return DataLineageBlocker(
        blocker_id=stable_id(
            "DLBLOCK",
            {
                "workload": workload.workload_id,
                "reason": reason.value,
                "dataset": dataset_id,
                "access": access_id,
                "detail": detail,
                "policy": LINEAGE_POLICY_DIGEST,
            },
        ),
        reason=reason,
        dataset_id=dataset_id,
        access_id=access_id,
        detail=detail,
    )


def derive_data_lineage(
    workload: Workload,
    *,
    artifact_bytes: dict[str, bytes] | None = None,
) -> Workload:
    """Derive static lineage without selecting ambiguous or unresolved producers."""

    _assert_unique("artifact", workload.artifacts, "artifact_id")
    _assert_unique("dataset", workload.datasets, "dataset_id")
    _assert_unique("relationship", workload.relationships, "relationship_id")
    for dataset_item in workload.datasets:
        if not isinstance(dataset_item.kind, DatasetKind):
            raise ValueError(f"Unsupported dataset kind: {dataset_item.kind!r}")
    for relationship in workload.relationships:
        if not isinstance(relationship.kind, RelationshipKind):
            raise ValueError(f"Unsupported relationship kind: {relationship.kind!r}")
    artifacts = {item.artifact_id: item for item in workload.artifacts}
    datasets = {item.dataset_id: item for item in workload.datasets}
    relationships = {
        item.relationship_id: item
        for item in workload.relationships
        if item.kind not in {RelationshipKind.PRODUCES, RelationshipKind.CONSUMED_BY}
        and not (
            item.kind in {RelationshipKind.PRECEDES, RelationshipKind.DEPENDS_ON}
            and item.metadata.get("dependency_domain") == "data"
        )
    }
    writes_by_dataset: dict[str, list[tuple[Relationship, DataAccessObservation | None]]] = {}
    reads_by_dataset: dict[str, list[tuple[Relationship, DataAccessObservation | None]]] = {}
    accesses: list[DataAccessObservation] = []
    for item in workload.relationships:
        if item.kind not in {RelationshipKind.READS, RelationshipKind.WRITES}:
            continue
        observation = _access_observation(
            item,
            workload_id=workload.workload_id,
            artifacts=artifacts,
            datasets=datasets,
            artifact_bytes=artifact_bytes,
        )
        if observation is not None:
            accesses.append(observation)
        target = writes_by_dataset if item.kind is RelationshipKind.WRITES else reads_by_dataset
        target.setdefault(item.target_id, []).append((item, observation))

    access_ids = [item.access_id for item in accesses]
    if len(access_ids) != len(set(access_ids)):
        raise ValueError("Duplicate canonical dataset access identity")

    blockers: list[DataLineageBlocker] = []
    resolutions: list[DatasetLineageResolution] = []
    resolved_edge_ids: set[str] = set()
    if not accesses:
        blockers.append(
            _blocker(
                workload,
                DataLineageBlockerReason.NO_ELIGIBLE_ACCESS,
                detail="No occurrence-bound eligible SAS dataset access was discovered",
            )
        )

    observed_dataset_ids = sorted({*writes_by_dataset, *reads_by_dataset})
    for dataset_id in observed_dataset_ids:
        dataset = datasets.get(dataset_id)
        if dataset is None:
            raise ValueError(f"Dataset access references unknown dataset: {dataset_id}")
        identity_resolution = _identity_resolution(dataset)
        writes = writes_by_dataset.get(dataset_id, [])
        reads = reads_by_dataset.get(dataset_id, [])
        canonical_writes = [(rel, obs) for rel, obs in writes if obs is not None]
        canonical_reads = [(rel, obs) for rel, obs in reads if obs is not None]

        if identity_resolution is DatasetIdentityResolution.UNRESOLVED:
            producer_resolution = DataProducerResolution.UNRESOLVED
            for _relationship_item, observation in canonical_reads or canonical_writes:
                assert observation is not None
                blockers.append(
                    _blocker(
                        workload,
                        DataLineageBlockerReason.UNRESOLVED_IDENTITY,
                        dataset_id=dataset_id,
                        access_id=observation.access_id,
                        detail="Dataset identity is not qualified by a local binding",
                    )
                )
        elif len(canonical_writes) != len(writes) or len(canonical_reads) != len(reads):
            producer_resolution = DataProducerResolution.UNRESOLVED
        elif len(canonical_writes) > 1:
            producer_resolution = DataProducerResolution.CONFLICTING
            blockers.append(
                _blocker(
                    workload,
                    DataLineageBlockerReason.CONFLICTING_PRODUCERS,
                    dataset_id=dataset_id,
                    detail="Multiple static write occurrences have no proven runtime order",
                )
            )
        elif not canonical_writes and canonical_reads:
            producer_resolution = DataProducerResolution.MISSING
            for _relationship_item, observation in canonical_reads:
                assert observation is not None
                blockers.append(
                    _blocker(
                        workload,
                        DataLineageBlockerReason.MISSING_PRODUCER,
                        dataset_id=dataset_id,
                        access_id=observation.access_id,
                        detail="No qualified producer was discovered for this read",
                    )
                )
        else:
            producer_resolution = DataProducerResolution.OBSERVED

        for relationship_item, observation in (*writes, *reads):
            if observation is None:
                blockers.append(
                    _blocker(
                        workload,
                        DataLineageBlockerReason.INVALID_EVIDENCE,
                        dataset_id=dataset_id,
                        detail=(
                            "Dataset access relationship lacks occurrence-bound "
                            "acquisition evidence: "
                            f"{relationship_item.relationship_id}"
                        ),
                    )
                )

        if identity_resolution is not DatasetIdentityResolution.UNRESOLVED:
            for write, write_observation in canonical_writes:
                assert write_observation is not None
                source_access_id = write_observation.access_id
                produces = _relationship(
                    workload,
                    source_id=write.source_id,
                    kind=RelationshipKind.PRODUCES,
                    target_id=dataset_id,
                    evidence=write.evidence,
                    metadata={
                        "derived_from": (write.relationship_id,),
                        "source_access_id": source_access_id,
                        "artifact_revision": (write_observation.artifact_checksum),
                        "lineage_policy_digest": LINEAGE_POLICY_DIGEST,
                    },
                )
                relationships[produces.relationship_id] = produces
                resolved_edge_ids.add(produces.relationship_id)
            for read, read_observation in canonical_reads:
                assert read_observation is not None
                consumer_access_id = read_observation.access_id
                consumed_by = _relationship(
                    workload,
                    source_id=dataset_id,
                    kind=RelationshipKind.CONSUMED_BY,
                    target_id=read.source_id,
                    evidence=read.evidence,
                    metadata={
                        "derived_from": (read.relationship_id,),
                        "consumer_access_id": consumer_access_id,
                        "artifact_revision": (read_observation.artifact_checksum),
                        "lineage_policy_digest": LINEAGE_POLICY_DIGEST,
                    },
                )
                relationships[consumed_by.relationship_id] = consumed_by
                resolved_edge_ids.add(consumed_by.relationship_id)

        if (
            identity_resolution is not DatasetIdentityResolution.UNRESOLVED
            and len(canonical_writes) == 1
        ):
            write, write_observation = canonical_writes[0]
            assert write_observation is not None
            for read, read_observation in canonical_reads:
                assert read_observation is not None
                if write.source_id == read.source_id:
                    continue
                metadata: dict[str, object] = {
                    "dependency_domain": "data",
                    "via_dataset_ids": (dataset_id,),
                    "via_dataset_names": (dataset.name,),
                    "via_dataset_id": dataset_id,
                    "via_dataset_name": dataset.name,
                    "derived_from": (write.relationship_id, read.relationship_id),
                    "producer_resolution": DataProducerResolution.OBSERVED.value,
                    "candidate_producer_access_ids": tuple(
                        item.access_id for _rel, item in canonical_writes if item is not None
                    ),
                    "source_access_id": (
                        write_observation.access_id
                        if write_observation is not None
                        else write.relationship_id
                    ),
                    "consumer_access_id": (
                        read_observation.access_id
                        if read_observation is not None
                        else read.relationship_id
                    ),
                    "lineage_policy_digest": LINEAGE_POLICY_DIGEST,
                }
                evidence = _merge_evidence(write.evidence, read.evidence)
                for source_id, kind, target_id in (
                    (write.source_id, RelationshipKind.PRECEDES, read.source_id),
                    (read.source_id, RelationshipKind.DEPENDS_ON, write.source_id),
                ):
                    edge = _relationship(
                        workload,
                        source_id=source_id,
                        kind=kind,
                        target_id=target_id,
                        evidence=evidence,
                        metadata=metadata,
                    )
                    relationships[edge.relationship_id] = edge
                    resolved_edge_ids.add(edge.relationship_id)

        resolutions.append(
            DatasetLineageResolution(
                resolution_id=stable_id(
                    "DLRES",
                    {
                        "workload": workload.workload_id,
                        "dataset": dataset_id,
                        "identity_resolution": identity_resolution.value,
                        "producer_resolution": producer_resolution.value,
                        "writers": tuple(
                            item.access_id for _rel, item in canonical_writes if item is not None
                        ),
                        "readers": tuple(
                            item.access_id for _rel, item in canonical_reads if item is not None
                        ),
                        "policy": LINEAGE_POLICY_DIGEST,
                    },
                ),
                dataset_id=dataset_id,
                dataset_name=dataset.name,
                identity_resolution=identity_resolution,
                producer_resolution=producer_resolution,
                candidate_producer_access_ids=tuple(
                    sorted(item.access_id for _rel, item in canonical_writes if item is not None)
                ),
                candidate_producer_artifact_ids=tuple(
                    sorted(
                        {item.artifact_id for _rel, item in canonical_writes if item is not None}
                    )
                ),
                consumer_access_ids=tuple(
                    sorted(item.access_id for _rel, item in canonical_reads if item is not None)
                ),
            )
        )

    inventory = tuple(
        sorted(
            (
                item.artifact_id,
                item.logical_path or item.name,
                item.kind.value,
                item.checksum or "",
                str(item.metadata.get("size_bytes", "")),
            )
            for item in workload.artifacts
        )
    )
    artifact_revisions = tuple(
        sorted({(item.artifact_id, item.artifact_checksum) for item in accesses})
    )
    accesses.sort(key=lambda item: item.access_id)
    resolutions.sort(key=lambda item: item.resolution_id)
    blockers = sorted(
        {item.blocker_id: item for item in blockers}.values(), key=lambda item: item.blocker_id
    )
    source_closure_digest = _canonical_digest(inventory)
    analysis_payload = {
        "workload": workload.workload_id,
        "strategy": LINEAGE_POLICY_DIGEST,
        "source_closure": source_closure_digest,
        "artifact_revisions": artifact_revisions,
        "access_ids": tuple(item.access_id for item in accesses),
        "resolved_edge_ids": tuple(sorted(resolved_edge_ids)),
        "resolution_ids": tuple(item.resolution_id for item in resolutions),
        "blocker_ids": tuple(item.blocker_id for item in blockers),
    }
    analysis = DataLineageAnalysis(
        analysis_id=stable_id("DLAN", analysis_payload),
        workload_id=workload.workload_id,
        strategy_id=LINEAGE_STRATEGY_ID,
        strategy_version=LINEAGE_STRATEGY_VERSION,
        policy_digest=LINEAGE_POLICY_DIGEST,
        source_closure_digest=source_closure_digest,
        artifact_revisions=artifact_revisions,
        access_ids=tuple(item.access_id for item in accesses),
        resolved_edge_ids=tuple(sorted(resolved_edge_ids)),
        accesses=tuple(accesses),
        dataset_resolutions=tuple(resolutions),
        blockers=tuple(blockers),
        complete=bool(accesses) and not blockers,
    )
    return replace(
        workload,
        relationships=tuple(sorted(relationships.values(), key=lambda item: item.relationship_id)),
        data_lineage_analysis=analysis,
    )
