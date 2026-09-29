"""Typed models for modernization corpus manifests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CorpusSourceRef:
    """Provenance for a corpus scenario or imported artifact."""

    source_id: str
    origin: str
    license: str
    upstream_url: str | None = None
    upstream_ref: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class CorpusArtifact:
    """A file that belongs to a corpus scenario."""

    path: Path
    role: str
    sha256: str | None = None
    source_id: str | None = None
    upstream_path: str | None = None


@dataclass(frozen=True)
class CorpusArtifactRelationship:
    """Declared relationship between artifacts in a multi-artifact corpus workload."""

    source_path: Path
    target_path: Path
    relationship: str


@dataclass(frozen=True)
class CorpusWorkloadDefinition:
    """Portable workload-level fixture definition carried by a corpus manifest."""

    root: Path
    entrypoints: tuple[Path, ...]
    relationships: tuple[CorpusArtifactRelationship, ...] = ()


@dataclass(frozen=True)
class CorpusValidationPolicyRef:
    """Versioned validation policy selected for a regression subject."""

    policy_id: str
    policy_version: str
    validation_kind: str


@dataclass(frozen=True)
class CorpusGoldenExpectation:
    """Versioned expected conversion outcome with attributable change provenance."""

    golden_id: str
    golden_version: str
    expected_disposition: str
    comparison_mode: str
    provider_id: str
    provider_version: str
    strategy_id: str
    strategy_version: str
    behavioral_expectation_id: str | None
    behavioral_evidence_digest: str | None
    rationale: str
    review_reference: str
    fixture_classification: str
    artifact_path: Path | None = None


@dataclass(frozen=True)
class CorpusRegressionSubject:
    """One exact, eligible conversion subject in a corpus workload."""

    subject_id: str
    workload_id: str
    entrypoint: Path
    target: str
    source_closure: tuple[Path, ...]
    stages: tuple[str, ...]
    validation_policy: CorpusValidationPolicyRef
    evidence_scope: str
    environment: str
    oracle_ids: tuple[str, ...] = ()
    baseline_evidence_ids: tuple[str, ...] = ()
    golden: CorpusGoldenExpectation | None = None


@dataclass(frozen=True)
class CorpusRegressionDefinition:
    """Versioned regression subjects declared by a corpus scenario."""

    version: int
    subjects: tuple[CorpusRegressionSubject, ...]


@dataclass(frozen=True)
class CorpusDependencyExpectation:
    """Expected dependency evidence, including deliberately unresolved references."""

    expectation_id: str
    source_path: Path
    relationship: str
    resolution: str
    evidence_method: str
    target_path: Path | None = None
    unresolved_reference: str | None = None


@dataclass(frozen=True)
class CorpusDataFixture:
    """Deterministic input dataset attached to a corpus scenario."""

    fixture_id: str
    dataset: str
    artifact_path: Path
    format: str
    deterministic: bool = True
    contains_private_data: bool = False


@dataclass(frozen=True)
class CorpusOutputEvidence:
    """Expected or baseline output evidence with explicit provenance and authority."""

    evidence_id: str
    logical_output: str
    artifact_path: Path
    format: str
    evidence_origin: str
    producer: str
    content_hash: str
    deterministic: bool
    authoritative: bool
    source_execution_id: str | None = None


@dataclass(frozen=True)
class CorpusSemanticColumn:
    """Column contract for a normalized semantic result."""

    name: str
    logical_type: str
    nullable: bool
    length: int | None = None
    absolute_tolerance: float = 0.0
    relative_tolerance: float = 0.0


@dataclass(frozen=True)
class CorpusSemanticSession:
    """Pinned SAS session assumptions needed to interpret an oracle."""

    yearcutoff: int
    locale: str
    encoding: str
    sort_sequence: str
    timezone: str


@dataclass(frozen=True)
class CorpusSemanticOracle:
    """Exact comparison contract bound to authoritative output evidence."""

    oracle_id: str
    logical_output: str
    evidence_id: str
    comparison: str
    columns: tuple[CorpusSemanticColumn, ...]
    session: CorpusSemanticSession
    behavior: str
    keys: tuple[str, ...] = ()
    authoritative_values: str = "underlying"


@dataclass(frozen=True)
class CorpusManifest:
    """Canonical description of a regression corpus scenario."""

    schema_version: int
    scenario_id: str
    name: str
    domain: str
    description: str
    source: CorpusSourceRef
    capabilities: tuple[str, ...] = ()
    artifacts: tuple[CorpusArtifact, ...] = ()
    expected: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    workload: CorpusWorkloadDefinition | None = None
    data_fixtures: tuple[CorpusDataFixture, ...] = ()
    output_evidence: tuple[CorpusOutputEvidence, ...] = ()
    semantic_oracles: tuple[CorpusSemanticOracle, ...] = ()
    dependency_expectations: tuple[CorpusDependencyExpectation, ...] = ()
    regression: CorpusRegressionDefinition | None = None
