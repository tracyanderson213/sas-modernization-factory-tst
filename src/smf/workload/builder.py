"""Builder for canonical workloads from discovery-provider observations."""

from dataclasses import dataclass, field, replace
from typing import Any

from smf.workload.identity import stable_id
from smf.workload.lineage import contains_protected_identity
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    Confidence,
    Dataset,
    DatasetKind,
    DiscoveryEvidence,
    EvidenceMethod,
    ExternalDependency,
    ExternalDependencyKind,
    Relationship,
    RelationshipKind,
    Workload,
)
from smf.workload.sanitization import sanitize_discovery_value


def _merge_evidence(*groups: tuple[DiscoveryEvidence, ...]) -> tuple[DiscoveryEvidence, ...]:
    merged: dict[str, DiscoveryEvidence] = {}
    for group in groups:
        for item in group:
            merged[item.evidence_id] = item
    return tuple(merged.values())


@dataclass
class WorkloadBuilder:
    """Accumulates discovered facts without requiring a hand-authored manifest."""

    name: str
    namespace: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)
    _artifacts: dict[str, Artifact] = field(default_factory=dict)
    _datasets: dict[str, Dataset] = field(default_factory=dict)
    _relationships: dict[str, Relationship] = field(default_factory=dict)
    _external_dependencies: dict[str, ExternalDependency] = field(default_factory=dict)

    @property
    def workload_id(self) -> str:
        safe_namespace = sanitize_discovery_value(self.namespace)
        safe_name = sanitize_discovery_value(self.name)
        return stable_id(
            "WL",
            {"namespace": safe_namespace, "name": safe_name},
        )

    def evidence(
        self,
        *,
        method: EvidenceMethod,
        source: str,
        confidence: Confidence,
        locator: str | None = None,
        observed_value: str | None = None,
        confirmed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> DiscoveryEvidence:
        safe_source = sanitize_discovery_value(source)
        safe_locator = sanitize_discovery_value(locator)
        safe_observed_value = sanitize_discovery_value(observed_value)
        safe_metadata = sanitize_discovery_value(metadata or {})
        identity = {
            "method": method.value,
            "source": safe_source,
            "locator": safe_locator,
            "observed_value": safe_observed_value,
        }
        return DiscoveryEvidence(
            evidence_id=stable_id("EV", identity),
            method=method,
            source=safe_source,
            confidence=confidence,
            locator=safe_locator,
            observed_value=safe_observed_value,
            confirmed=confirmed,
            metadata=safe_metadata,
        )

    def add_artifact(
        self,
        *,
        kind: ArtifactKind,
        name: str,
        logical_path: str | None = None,
        checksum: str | None = None,
        evidence: tuple[DiscoveryEvidence, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> Artifact:
        safe_name = sanitize_discovery_value(name)
        safe_logical_path = sanitize_discovery_value(logical_path)
        safe_metadata = sanitize_discovery_value(metadata or {})
        identity = {
            "workload": self.workload_id,
            "kind": kind.value,
            "name": safe_name,
            "logical_path": safe_logical_path,
        }
        artifact = Artifact(
            artifact_id=stable_id("ART", identity),
            kind=kind,
            name=safe_name,
            logical_path=safe_logical_path,
            checksum=checksum,
            evidence=evidence,
            metadata=safe_metadata,
        )
        existing = self._artifacts.get(artifact.artifact_id)
        if existing is not None:
            artifact = replace(
                existing,
                checksum=artifact.checksum or existing.checksum,
                evidence=_merge_evidence(existing.evidence, artifact.evidence),
                metadata={**existing.metadata, **artifact.metadata},
            )
        self._artifacts[artifact.artifact_id] = artifact
        return artifact

    def add_dataset(
        self,
        *,
        kind: DatasetKind,
        name: str,
        location: str | None = None,
        system: str | None = None,
        evidence: tuple[DiscoveryEvidence, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> Dataset:
        safe_name = sanitize_discovery_value(name)
        safe_location = sanitize_discovery_value(location)
        safe_system = sanitize_discovery_value(system)
        safe_metadata = sanitize_discovery_value(metadata or {})
        identity_values = (name, location, system)
        if (
            safe_name != name
            or safe_location != location
            or safe_system != system
            or any(
                contains_protected_identity(value)
                for value in identity_values
                if isinstance(value, str)
            )
        ):
            raise ValueError("Dataset identity contains a credential-bearing unsafe value")
        canonical_name = safe_metadata.get("canonical_dataset_name", safe_name)
        identity_scope = safe_metadata.get("scope_discriminator")
        identity_resolution = safe_metadata.get("resolution")
        identity = {
            "workload": self.workload_id,
            "kind": kind.value,
            "name": canonical_name,
            "location": safe_location,
            "system": safe_system,
            "scope_discriminator": identity_scope,
            "resolution": identity_resolution,
        }
        dataset = Dataset(
            dataset_id=stable_id("DATA", identity),
            kind=kind,
            name=safe_name,
            location=safe_location,
            system=safe_system,
            evidence=evidence,
            metadata=safe_metadata,
        )
        existing = self._datasets.get(dataset.dataset_id)
        if existing is not None:
            dataset = replace(
                existing,
                evidence=_merge_evidence(existing.evidence, dataset.evidence),
                metadata={**existing.metadata, **dataset.metadata},
            )
        self._datasets[dataset.dataset_id] = dataset
        return dataset

    def add_external_dependency(
        self,
        *,
        kind: ExternalDependencyKind,
        name: str,
        location: str | None = None,
        system: str | None = None,
        evidence: tuple[DiscoveryEvidence, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> ExternalDependency:
        safe_name = sanitize_discovery_value(name)
        safe_location = sanitize_discovery_value(location)
        safe_system = sanitize_discovery_value(system)
        safe_metadata = sanitize_discovery_value(metadata or {})
        identity = {
            "workload": self.workload_id,
            "kind": kind.value,
            "name": safe_name,
            "location": safe_location,
            "system": safe_system,
        }
        dependency = ExternalDependency(
            dependency_id=stable_id("EXT", identity),
            kind=kind,
            name=safe_name,
            location=safe_location,
            system=safe_system,
            evidence=evidence,
            metadata=safe_metadata,
        )
        existing = self._external_dependencies.get(dependency.dependency_id)
        if existing is not None:
            dependency = replace(
                existing,
                evidence=_merge_evidence(existing.evidence, dependency.evidence),
                metadata={**existing.metadata, **dependency.metadata},
            )
        self._external_dependencies[dependency.dependency_id] = dependency
        return dependency

    def add_relationship(
        self,
        *,
        source_id: str,
        kind: RelationshipKind,
        target_id: str,
        evidence: tuple[DiscoveryEvidence, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> Relationship:
        identity: dict[str, Any] = {
            "workload": self.workload_id,
            "source": source_id,
            "kind": kind.value,
            "target": target_id,
        }
        dependency_domain = (metadata or {}).get("dependency_domain")
        if isinstance(dependency_domain, str):
            identity["dependency_domain"] = dependency_domain
        if kind is RelationshipKind.INCLUDES:
            if len(evidence) != 1:
                raise ValueError("Include relationships require exactly one source observation")
            occurrence = evidence[0].metadata
            identity["occurrence"] = {
                "byte_start": occurrence.get("byte_start"),
                "byte_end": occurrence.get("byte_end"),
                "span_digest": occurrence.get("span_digest"),
            }
        if kind in {RelationshipKind.READS, RelationshipKind.WRITES} and evidence:
            if len(evidence) != 1:
                raise ValueError(
                    "Dataset access relationships require exactly one source observation"
                )
            occurrence = evidence[0].metadata
            access_id = occurrence.get("access_id")
            if access_id is not None:
                required = {
                    "artifact_checksum",
                    "byte_start",
                    "byte_end",
                    "source_checksum",
                    "span_digest",
                    "lineage_policy_digest",
                }
                missing = sorted(required - occurrence.keys())
                if missing:
                    raise ValueError(
                        "Dataset access occurrence evidence is incomplete: " + ", ".join(missing)
                    )
                identity["occurrence"] = {"access_id": access_id}
        relationship = Relationship(
            relationship_id=stable_id("REL", identity),
            source_id=source_id,
            kind=kind,
            target_id=target_id,
            evidence=evidence,
            metadata=metadata or {},
        )
        existing = self._relationships.get(relationship.relationship_id)
        if existing is not None:
            relationship = replace(
                existing,
                evidence=_merge_evidence(existing.evidence, relationship.evidence),
                metadata={**existing.metadata, **relationship.metadata},
            )
        self._relationships[relationship.relationship_id] = relationship
        return relationship

    def build(self) -> Workload:
        return Workload(
            workload_id=self.workload_id,
            name=self.name,
            artifacts=tuple(self._artifacts.values()),
            datasets=tuple(self._datasets.values()),
            relationships=tuple(self._relationships.values()),
            external_dependencies=tuple(self._external_dependencies.values()),
            metadata=dict(self.metadata),
        )
