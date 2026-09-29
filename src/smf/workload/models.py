"""Canonical workload graph models.

These models represent discovered evidence. They are not a customer-authored
questionnaire and intentionally allow unresolved or partially known facts.
"""

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Confidence(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class EvidenceMethod(StrEnum):
    STATIC_ANALYSIS = "static_analysis"
    FILESYSTEM = "filesystem"
    RUNTIME_METADATA = "runtime_metadata"
    SCHEDULER_METADATA = "scheduler_metadata"
    DATA_SYSTEM = "data_system"
    AI_INFERENCE = "ai_inference"
    HUMAN_CONFIRMATION = "human_confirmation"


class ArtifactKind(StrEnum):
    SAS_PROGRAM = "sas_program"
    SAS_MACRO = "sas_macro"
    SAS_INCLUDE = "sas_include"
    FORMAT_CATALOG = "format_catalog"
    CONFIGURATION = "configuration"
    SHELL_SCRIPT = "shell_script"
    SCHEDULER_JOB = "scheduler_job"
    OTHER = "other"


class DatasetKind(StrEnum):
    SAS_DATASET = "sas_dataset"
    DATABASE_TABLE = "database_table"
    FILE = "file"
    API = "api"
    EXTERNAL_FEED = "external_feed"
    INTERMEDIATE = "intermediate"
    UNKNOWN = "unknown"


class ExternalDependencyKind(StrEnum):
    DATABASE_CONNECTION = "database_connection"
    FILESYSTEM = "filesystem"
    EXECUTABLE = "executable"
    ENVIRONMENT_VARIABLE = "environment_variable"
    UNRESOLVED_CONNECTION = "unresolved_connection"


class ConsumerResolution(StrEnum):
    """How completely downstream consumers are known for an output."""

    UNRESOLVED = "unresolved"
    PARTIAL = "partial"
    CONFIRMED = "confirmed"


class RelationshipKind(StrEnum):
    INCLUDES = "includes"
    CALLS = "calls"
    READS = "reads"
    WRITES = "writes"
    PRODUCES = "produces"
    CONSUMES = "consumes"
    TRIGGERS = "triggers"
    DEPENDS_ON = "depends_on"
    PRECEDES = "precedes"
    CONSUMED_BY = "consumed_by"


class DependencyNodeKind(StrEnum):
    ARTIFACT = "artifact"
    DATASET = "dataset"
    EXTERNAL_DEPENDENCY = "external_dependency"


class DependencyDomain(StrEnum):
    CODE = "code"
    DATA = "data"
    SCHEDULER = "scheduler"
    RUNTIME_LAUNCH = "runtime_launch"
    EXTERNAL = "external"


class DependencyResolutionReason(StrEnum):
    DYNAMIC = "dynamic"
    AMBIGUOUS = "ambiguous"
    MISSING = "missing"
    EXTERNAL = "external"
    RECURSIVE = "recursive"
    CYCLIC = "cyclic"
    RUNTIME_DEPENDENT = "runtime_dependent"
    UNSUPPORTED = "unsupported"
    LIMIT_EXCEEDED = "limit_exceeded"


class CodeDependencyResolutionKind(StrEnum):
    """Closed set of static code-reference outcomes."""

    RESOLVED = "resolved"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    DYNAMIC = "dynamic"
    RECURSIVE = "recursive"
    CYCLIC = "cyclic"
    RUNTIME_DEPENDENT = "runtime_dependent"
    BOUNDARY_ESCAPE = "boundary_escape"
    UNSUPPORTED = "unsupported"
    LIMIT_EXCEEDED = "limit_exceeded"


class CodeDependencyBlockerReason(StrEnum):
    """Why static code closure cannot authorize ordering or completeness."""

    NO_ELIGIBLE_SUBJECT = "no_eligible_subject"
    INVALID_EVIDENCE = "invalid_evidence"
    DUPLICATE_IDENTITY = "duplicate_identity"
    UNRESOLVED_DEPENDENCY = "unresolved_dependency"


class IncludeResolutionKind(StrEnum):
    """Fail-closed outcomes produced by the governed static include resolver."""

    RESOLVED = "resolved"
    DYNAMIC = "dynamic"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    BOUNDARY_ESCAPE = "boundary_escape"
    CYCLIC = "cyclic"
    UNSUPPORTED = "unsupported"
    LIMIT_EXCEEDED = "limit_exceeded"


class DatasetIdentityResolution(StrEnum):
    """Qualification state for a statically observed dataset identity."""

    RESOLVED = "resolved"
    PROVISIONAL = "provisional"
    UNRESOLVED = "unresolved"


class DataProducerResolution(StrEnum):
    """Producer resolution for one qualified dataset in static discovery."""

    OBSERVED = "observed"
    MISSING = "missing"
    CONFLICTING = "conflicting"
    UNRESOLVED = "unresolved"


class DataLineageBlockerReason(StrEnum):
    NO_ELIGIBLE_ACCESS = "no_eligible_access"
    INVALID_EVIDENCE = "invalid_evidence"
    UNRESOLVED_IDENTITY = "unresolved_identity"
    MISSING_PRODUCER = "missing_producer"
    CONFLICTING_PRODUCERS = "conflicting_producers"


class TopologyNodeKind(StrEnum):
    WORKLOAD_BOUNDARY = "workload_boundary"
    DATASET = "dataset"
    EXTERNAL_DEPENDENCY = "external_dependency"
    EXTERNAL_ARTIFACT = "external_artifact"


class ModernizationDisposition(StrEnum):
    RETIRE = "retire"
    CONSOLIDATE = "consolidate"
    REPLACE = "replace"
    RE_ENGINEER = "re_engineer"
    CONVERT = "convert"
    PRESERVE = "preserve"


class DispositionDecisionStatus(StrEnum):
    UNRESOLVED = "unresolved"
    PROPOSED = "proposed"
    CONFIRMED = "confirmed"


class DispositionInputSource(StrEnum):
    DISCOVERY = "discovery"
    ASSESSMENT = "assessment"
    HUMAN = "human"


class TargetExecutionBehavior(StrEnum):
    UNKNOWN = "unknown"
    SCHEDULED = "scheduled"
    SCRIPT_DRIVEN = "script_driven"


class TargetDataBehavior(StrEnum):
    READS_DATA = "reads_data"
    WRITES_DATA = "writes_data"
    PRODUCES_OUTPUT = "produces_output"
    USES_INTERMEDIATE = "uses_intermediate"


class DatabricksTargetPattern(StrEnum):
    """Stable logical Databricks target patterns, not deployment configuration."""

    WORKFLOW_JOB = "workflow_job"
    BATCH_SPARK = "batch_spark"
    INCREMENTAL_PIPELINE = "incremental_pipeline"
    DELTA_TABLE = "delta_table"


class WorkloadStatus(StrEnum):
    DISCOVERED = "discovered"
    BOUNDARY_PROPOSED = "boundary_proposed"
    CONFIRMED = "confirmed"


class MacroConstructFamily(StrEnum):
    SAS_MACRO_PROCESSOR = "sas_macro_processor"
    SAS_PROC_FORMAT = "sas_proc_format"
    TARGET_TEMPLATE = "target_template"


class MacroArtifactType(StrEnum):
    SAS_MACRO_DEFINITION = "sas_macro_definition"
    PROC_FORMAT_DEFINITION = "proc_format_definition"
    TARGET_TEMPLATE_DEFINITION = "target_template_definition"


class MacroObservationKind(StrEnum):
    DEFINITION = "definition"
    LITERAL_INVOCATION = "literal_invocation"
    DYNAMIC_INVOCATION = "dynamic_invocation"
    VARIABLE_DEFINITION = "variable_definition"
    VARIABLE_REFERENCE = "variable_reference"
    INCLUDE_REFERENCE = "include_reference"
    INTRINSIC_OPERATION = "intrinsic_operation"
    QUOTING_OPERATION = "quoting_operation"
    PROC_FORMAT_DEFINITION = "proc_format_definition"
    TARGET_TEMPLATE = "target_template"


class MacroResolutionKind(StrEnum):
    UNIQUE_STATIC_DEFINITION = "unique_static_definition"
    INTRINSIC_SYSTEM = "intrinsic_system"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    DYNAMIC = "dynamic"
    RECURSIVE = "recursive"
    CYCLIC = "cyclic"
    RUNTIME_DEPENDENT = "runtime_dependent"
    UNSUPPORTED = "unsupported"
    LIMIT_EXCEEDED = "limit_exceeded"


class MacroRelationshipKind(StrEnum):
    SAS_MACRO_CALL = "sas_macro_call"
    SAS_MACRO_VARIABLE_REFERENCE = "sas_macro_variable_reference"
    SAS_INCLUDE_REFERENCE = "sas_include_reference"
    SAS_FORMAT_REFERENCE = "sas_format_reference"
    TARGET_TEMPLATE_CALL = "target_template_call"


@dataclass(frozen=True)
class MacroSourceLocation:
    source_artifact_id: str
    source_checksum: str
    byte_start: int
    byte_end: int
    line: int
    column: int
    span_digest: str


@dataclass(frozen=True)
class MacroLogicalArtifact:
    logical_artifact_id: str
    artifact_type: MacroArtifactType
    construct_family: MacroConstructFamily
    normalized_identity: str
    location: MacroSourceLocation


@dataclass(frozen=True)
class MacroObservation:
    observation_id: str
    kind: MacroObservationKind
    construct_family: MacroConstructFamily
    normalized_identity: str
    location: MacroSourceLocation
    logical_artifact_id: str | None = None


@dataclass(frozen=True)
class MacroResolution:
    resolution_id: str
    observation_id: str
    relationship_kind: MacroRelationshipKind
    kind: MacroResolutionKind
    candidate_definition_ids: tuple[str, ...] = ()
    target_definition_id: str | None = None
    target_artifact_id: str | None = None
    blocker_reason: str | None = None


@dataclass(frozen=True)
class MacroBlocker:
    blocker_id: str
    reason: MacroResolutionKind
    observation_id: str | None = None
    source_artifact_id: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class MacroAnalysis:
    analysis_id: str
    discovery_id: str
    workload_id: str
    strategy_id: str
    strategy_version: str
    strategy_digest: str
    strategy_snapshot: dict[str, Any]
    expansion_mode: str
    complete: bool
    source_inventory: tuple[dict[str, str], ...] = ()
    logical_artifacts: tuple[MacroLogicalArtifact, ...] = ()
    observations: tuple[MacroObservation, ...] = ()
    resolutions: tuple[MacroResolution, ...] = ()
    blockers: tuple[MacroBlocker, ...] = ()
    limits_applied: dict[str, int | None] = field(default_factory=dict)


@dataclass(frozen=True)
class DataAccessObservation:
    """One literal READS/WRITES occurrence bound to acquired source bytes."""

    access_id: str
    role: RelationshipKind
    artifact_id: str
    artifact_checksum: str
    source_path: str
    normalized_reference: str
    dataset_id: str
    identity_resolution: DatasetIdentityResolution
    line: int
    column: int
    byte_start: int
    byte_end: int
    source_checksum: str
    span_digest: str
    policy_digest: str
    relationship_id: str


@dataclass(frozen=True)
class DatasetLineageResolution:
    """All static producer candidates and consumers for one dataset identity."""

    resolution_id: str
    dataset_id: str
    dataset_name: str
    identity_resolution: DatasetIdentityResolution
    producer_resolution: DataProducerResolution
    candidate_producer_access_ids: tuple[str, ...] = ()
    candidate_producer_artifact_ids: tuple[str, ...] = ()
    consumer_access_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DataLineageBlocker:
    blocker_id: str
    reason: DataLineageBlockerReason
    dataset_id: str | None = None
    access_id: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class DataLineageAnalysis:
    """Versioned, non-authorizing static data-lineage evidence envelope."""

    analysis_id: str
    workload_id: str
    strategy_id: str
    strategy_version: str
    policy_digest: str
    source_closure_digest: str
    artifact_revisions: tuple[tuple[str, str], ...] = ()
    access_ids: tuple[str, ...] = ()
    resolved_edge_ids: tuple[str, ...] = ()
    accesses: tuple[DataAccessObservation, ...] = ()
    dataset_resolutions: tuple[DatasetLineageResolution, ...] = ()
    blockers: tuple[DataLineageBlocker, ...] = ()
    complete: bool = False
    claim: str = "static_discovery_only"


@dataclass(frozen=True)
class CodeDependencyInventoryEntry:
    """One immutable, acquisition-backed artifact revision in the source closure."""

    artifact_id: str
    kind: ArtifactKind
    logical_path: str
    checksum: str
    size_bytes: int
    acquisition_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CodeDependencyOccurrence:
    """One source-located include or macro-call observation and its outcome."""

    occurrence_id: str
    source_artifact_id: str
    source_checksum: str
    relationship_kind: RelationshipKind
    reference: str
    resolution: CodeDependencyResolutionKind
    line: int
    column: int
    byte_start: int
    byte_end: int
    span_digest: str
    policy_digest: str
    target_artifact_id: str | None = None
    target_checksum: str | None = None
    definition_id: str | None = None
    candidate_artifact_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CodeDependencyGroup:
    """A deterministic strongly connected code component in prerequisite order."""

    group_id: str
    artifact_ids: tuple[str, ...]
    prerequisite_group_ids: tuple[str, ...] = ()
    sequence_rank: int = 0
    cyclic: bool = False


@dataclass(frozen=True)
class CodeDependencyBlocker:
    blocker_id: str
    reason: CodeDependencyBlockerReason
    occurrence_id: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class CodeDependencyAnalysis:
    """Versioned, non-authorizing static code-closure evidence envelope."""

    analysis_id: str
    workload_id: str
    analyzer_id: str
    analyzer_version: str
    policy_digest: str
    source_closure_digest: str
    include_policy_digest: str
    macro_strategy_digest: str
    inventory: tuple[CodeDependencyInventoryEntry, ...] = ()
    occurrences: tuple[CodeDependencyOccurrence, ...] = ()
    ordering_groups: tuple[CodeDependencyGroup, ...] = ()
    blockers: tuple[CodeDependencyBlocker, ...] = ()
    analysis_complete: bool = False
    ordering_eligible: bool = False
    claim: str = "static_discovery_only"
    generated: bool = False
    executed: bool = False
    validated: bool = False
    parity_passed: bool = False
    certified: bool = False
    human_approved: bool = False


@dataclass(frozen=True)
class DiscoveryEvidence:
    evidence_id: str
    method: EvidenceMethod
    source: str
    confidence: Confidence
    locator: str | None = None
    observed_value: str | None = None
    confirmed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    kind: ArtifactKind
    name: str
    logical_path: str | None = None
    checksum: str | None = None
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Dataset:
    dataset_id: str
    kind: DatasetKind
    name: str
    location: str | None = None
    system: str | None = None
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExternalDependency:
    dependency_id: str
    kind: ExternalDependencyKind
    name: str
    location: str | None = None
    system: str | None = None
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Output:
    """A produced dataset/file and the downstream consumers observed so far."""

    output_id: str
    dataset_id: str
    producer_ids: tuple[str, ...] = ()
    consumer_ids: tuple[str, ...] = ()
    consumer_resolution: ConsumerResolution = ConsumerResolution.UNRESOLVED
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkloadBoundary:
    """An evidence-backed proposal for artifacts that form one workload system."""

    boundary_id: str
    name: str
    artifact_ids: tuple[str, ...] = ()
    dataset_ids: tuple[str, ...] = ()
    external_dependency_ids: tuple[str, ...] = ()
    output_ids: tuple[str, ...] = ()
    confidence: Confidence = Confidence.UNKNOWN
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DispositionCandidate:
    """A possible modernization path, never an autonomous business decision."""

    candidate_id: str
    disposition: ModernizationDisposition
    rationale: str
    confidence: Confidence = Confidence.UNKNOWN
    source: DispositionInputSource = DispositionInputSource.DISCOVERY
    evidence: tuple[DiscoveryEvidence, ...] = ()
    blocker_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModernizationDispositionInput:
    """Decision input for one workload boundary.

    Discovery can populate context and candidate evidence, but selection remains
    explicitly unresolved until a governed assessment or human decision supplies it.
    """

    disposition_input_id: str
    boundary_id: str
    candidates: tuple[DispositionCandidate, ...] = ()
    selected_disposition: ModernizationDisposition | None = None
    decision_status: DispositionDecisionStatus = DispositionDecisionStatus.UNRESOLVED
    rationale: str | None = None
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LogicSimilarityFinding:
    """Evidence-backed similarity between artifacts in different workload boundaries."""

    finding_id: str
    left_boundary_id: str
    right_boundary_id: str
    left_artifact_id: str
    right_artifact_id: str
    exact_source_match: bool = False
    structural_signature_match: bool = False
    confidence: Confidence = Confidence.UNKNOWN
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetStatePatternInput:
    """Normalized evidence contract consumed by later target-pattern recommendation logic.

    This model describes what is known about a workload boundary. It deliberately
    does not select a Databricks or other target architecture pattern.
    """

    pattern_input_id: str
    boundary_id: str
    disposition_input_id: str | None = None
    execution_behaviors: tuple[TargetExecutionBehavior, ...] = ()
    data_behaviors: tuple[TargetDataBehavior, ...] = ()
    dataset_ids: tuple[str, ...] = ()
    external_dependency_ids: tuple[str, ...] = ()
    output_ids: tuple[str, ...] = ()
    relationship_kinds: tuple[RelationshipKind, ...] = ()
    selected_disposition: ModernizationDisposition | None = None
    disposition_status: DispositionDecisionStatus = DispositionDecisionStatus.UNRESOLVED
    constraint_ids: tuple[str, ...] = ()
    unresolved_items: tuple[str, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MigrationWaveGroup:
    """Evidence-backed migration cohort and dependency-order proposal.

    A wave group is planning evidence, not a committed calendar wave. Boundaries may
    be grouped because they are dependency-coupled or share migration-affinity
    constraints. Final wave assignment remains a governed planning decision.
    """

    wave_group_id: str
    boundary_ids: tuple[str, ...] = ()
    predecessor_group_ids: tuple[str, ...] = ()
    sequence_rank: int = 0
    coupling_reasons: tuple[str, ...] = ()
    unresolved_items: tuple[str, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BatchIncrementalOpportunity:
    """Evidence that a batch workload may merit incremental-design assessment."""

    opportunity_id: str
    boundary_id: str
    confidence: Confidence = Confidence.UNKNOWN
    signal_ids: tuple[str, ...] = ()
    blocker_ids: tuple[str, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IntermediateArtifactEliminationOpportunity:
    """Evidence that an intermediate dataset may be removable in a target design."""

    opportunity_id: str
    boundary_id: str
    dataset_id: str
    producer_ids: tuple[str, ...] = ()
    consumer_ids: tuple[str, ...] = ()
    confidence: Confidence = Confidence.UNKNOWN
    signal_ids: tuple[str, ...] = ()
    blocker_ids: tuple[str, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DatabricksPatternMapping:
    """Evidence-backed target-pattern candidate for a workload boundary.

    A mapping is planning evidence only. It never proves target feasibility, selects
    a concrete Databricks service configuration, or overrides governed disposition.
    """

    mapping_id: str
    boundary_id: str
    pattern: DatabricksTargetPattern
    confidence: Confidence = Confidence.UNKNOWN
    signal_ids: tuple[str, ...] = ()
    blocker_ids: tuple[str, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModernizationRationaleEvidence:
    """Traceable rationale and evidence record for one modernization boundary."""

    record_id: str
    boundary_id: str
    disposition_input_id: str | None = None
    selected_disposition: ModernizationDisposition | None = None
    decision_status: DispositionDecisionStatus = DispositionDecisionStatus.UNRESOLVED
    decision_rationale: str | None = None
    candidate_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    related_record_ids: tuple[str, ...] = ()
    blocker_ids: tuple[str, ...] = ()
    unresolved_items: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetStateBoundaryPlan:
    """Normalized target-state planning record for one workload boundary.

    The record assembles governed decisions and planning candidates without
    inventing missing decisions or treating candidates as selected architecture.
    """

    boundary_id: str
    disposition: ModernizationDisposition | None = None
    disposition_status: DispositionDecisionStatus = DispositionDecisionStatus.UNRESOLVED
    databricks_pattern_mapping_ids: tuple[str, ...] = ()
    migration_wave_group_id: str | None = None
    incremental_opportunity_ids: tuple[str, ...] = ()
    intermediate_elimination_opportunity_ids: tuple[str, ...] = ()
    unresolved_items: tuple[str, ...] = ()
    blocker_ids: tuple[str, ...] = ()
    rationale_record_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetStateWorkloadManifest:
    """Portable target-state planning manifest assembled from canonical evidence."""

    manifest_id: str
    workload_id: str
    boundary_plans: tuple[TargetStateBoundaryPlan, ...] = ()
    unresolved_items: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Relationship:
    relationship_id: str
    source_id: str
    kind: RelationshipKind
    target_id: str
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DependencyNode:
    """An existing canonical entity exposed in the dependency projection."""

    node_id: str
    kind: DependencyNodeKind
    entity_id: str
    label: str
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DependencyEdge:
    """A direct edge projected from one or more canonical relationships."""

    edge_id: str
    source_id: str
    kind: RelationshipKind
    target_id: str
    relationship_ids: tuple[str, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    dataset_ids: tuple[str, ...] = ()
    dataset_names: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UnresolvedDependency:
    """An observed dependency reference for which no target is asserted."""

    unresolved_id: str
    source_id: str
    domain: DependencyDomain
    reference: str
    reason: DependencyResolutionReason
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DependencyGraph:
    """Regenerable, artifact-level projection of canonical discovery facts."""

    graph_id: str
    nodes: tuple[DependencyNode, ...] = ()
    edges: tuple[DependencyEdge, ...] = ()
    unresolved: tuple[UnresolvedDependency, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TopologyNode:
    """A navigable node in the current-state workload topology."""

    node_id: str
    kind: TopologyNodeKind
    entity_id: str
    label: str
    boundary_id: str | None = None
    confidence: Confidence = Confidence.UNKNOWN
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TopologyEdge:
    """An evidence-backed edge projected from canonical relationships."""

    edge_id: str
    source_id: str
    kind: RelationshipKind
    target_id: str
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkloadTopology:
    """Current-state topology projection for a discovered estate."""

    topology_id: str
    nodes: tuple[TopologyNode, ...] = ()
    edges: tuple[TopologyEdge, ...] = ()
    evidence: tuple[DiscoveryEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Workload:
    workload_id: str
    name: str
    status: WorkloadStatus = WorkloadStatus.DISCOVERED
    artifacts: tuple[Artifact, ...] = ()
    datasets: tuple[Dataset, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    macro_analysis: MacroAnalysis | None = None
    code_dependency_analysis: CodeDependencyAnalysis | None = None
    data_lineage_analysis: DataLineageAnalysis | None = None
    external_dependencies: tuple[ExternalDependency, ...] = ()
    dependency_graph: DependencyGraph | None = None
    outputs: tuple[Output, ...] = ()
    boundaries: tuple[WorkloadBoundary, ...] = ()
    topology: WorkloadTopology | None = None
    disposition_inputs: tuple[ModernizationDispositionInput, ...] = ()
    target_state_pattern_inputs: tuple[TargetStatePatternInput, ...] = ()
    migration_wave_groups: tuple[MigrationWaveGroup, ...] = ()
    logic_similarity_findings: tuple[LogicSimilarityFinding, ...] = ()
    batch_incremental_opportunities: tuple[BatchIncrementalOpportunity, ...] = ()
    intermediate_artifact_elimination_opportunities: tuple[
        IntermediateArtifactEliminationOpportunity, ...
    ] = ()
    databricks_pattern_mappings: tuple[DatabricksPatternMapping, ...] = ()
    target_state_manifest: TargetStateWorkloadManifest | None = None
    modernization_rationale_evidence: tuple[ModernizationRationaleEvidence, ...] = ()
    owner: str | None = None
    business_domain: str | None = None
    criticality: str | None = None
    cadence: str | None = None
    sla: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Local import avoids coupling the sanitizer to model declaration order.
        from smf.workload.sanitization import sanitize_workload_fields

        sanitize_workload_fields(self)

    def to_dict(self) -> dict[str, Any]:
        # Construction is the canonical discovery boundary.  Re-apply the same
        # rule while producing durable output so shallowly frozen dataclasses
        # cannot be made unsafe by later mutation of a nested metadata mapping.
        from smf.workload.sanitization import sanitize_discovery_value

        sanitized = sanitize_discovery_value(asdict(self))
        assert isinstance(sanitized, dict)
        return sanitized
