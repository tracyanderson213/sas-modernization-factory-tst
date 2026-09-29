"""Domain models for deterministic workload readiness qualification."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class ReadinessClassification(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    UNSUPPORTED = "UNSUPPORTED"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    MISSING = "missing"


class PrerequisiteState(StrEnum):
    PASS = "pass"
    DENIED = "denied"
    PENDING = "pending"
    MISSING = "missing"
    EXPIRED = "expired"
    CONFLICTING = "conflicting"


class BlockerCategory(StrEnum):
    DISCOVERY = "discovery"
    DEPENDENCY = "dependency"
    ASSESSMENT = "assessment"
    UNSUPPORTED_CONSTRUCT = "unsupported_construct"
    DATASET_MAPPING = "dataset_mapping"
    BASELINE = "baseline"
    RUNTIME = "runtime"
    ENVIRONMENT = "environment"
    HUMAN_APPROVAL = "human_approval"
    EVIDENCE_INTEGRITY = "evidence_integrity"


@dataclass(frozen=True)
class ReadinessPolicy:
    policy_id: str
    policy_version: str
    policy_digest: str
    classification_precedence: tuple[ReadinessClassification, ...]
    supported_artifact_kinds: tuple[str, ...]
    unresolved_dependencies: dict[str, ReadinessClassification]
    required_environment_checks: tuple[str, ...]
    required_runtime_checks: tuple[str, ...]
    prerequisite_binding: dict[str, str] | None
    prerequisites: tuple[dict[str, Any], ...]
    evidence_authorities: dict[str, tuple[str, ...]]
    evidence_acquisition_sources: dict[str, tuple[str, ...]]
    evidence_key_ids: dict[str, tuple[str, ...]]
    verification_keys: dict[str, str]
    required_baseline_authorities: tuple[str, ...]
    require_source_execution_id: bool
    trusted_baseline_acquisition_policies: tuple[dict[str, Any], ...]
    require_input_mappings: bool
    require_output_mappings: bool
    human_review_complexities: tuple[str, ...]
    human_review_risk_factors: tuple[str, ...]
    max_evidence_age_seconds: int | None
    owners: dict[str, str]
    next_actions: dict[str, str]


@dataclass(frozen=True)
class ReadinessRequest:
    workload: dict[str, Any]
    evidence: tuple[dict[str, Any], ...]
    run_id: str
    attempt_id: str
    boundary_id: str | None = None
    result_root: Path | None = None
    result_artifacts: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class ReadinessCheck:
    check_id: str
    category: BlockerCategory
    status: CheckStatus
    classification: ReadinessClassification | None
    subject_id: str
    evidence_ids: tuple[str, ...] = ()
    diagnostic: str = ""


@dataclass(frozen=True)
class PrerequisiteChecklistEntry:
    prerequisite_id: str
    domain: str
    evidence_kind: str
    subject_id: str
    state: PrerequisiteState
    owner_role: str
    requirement_refs: tuple[str, ...]
    owner_assignment_ref: str | None
    evidence_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    result_uris: tuple[str, ...]
    result_digests: tuple[str, ...]
    observed_at: str | None
    valid_until: str | None
    blocker_reason_code: str | None
    next_action: str


@dataclass(frozen=True)
class ReadinessBlocker:
    blocker_id: str
    category: BlockerCategory
    classification: ReadinessClassification
    owner: str
    subject_id: str
    evidence_ids: tuple[str, ...]
    diagnostic: str


@dataclass(frozen=True)
class MissingEvidence:
    evidence_kind: str
    subject_id: str
    reason: str


@dataclass(frozen=True)
class NextAction:
    category: BlockerCategory
    owner: str
    action: str


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    kind: str
    subject_id: str
    status: str
    evidence_digest: str
    source_checksum: str | None = None
    target_dataset_id: str | None = None
    target_catalog: str | None = None
    target_schema: str | None = None
    mapping_digest: str | None = None
    authority: str | None = None
    source_execution_id: str | None = None
    acquisition_source: str | None = None
    execution_id: str | None = None
    decision_id: str | None = None
    approver_id: str | None = None
    observed_at: str | None = None
    attestation_key_id: str | None = None
    workload_digest: str | None = None
    qualified_boundary_id: str | None = None
    snapshot_uri: str | None = None
    artifact_uri: str | None = None
    artifact_digest: str | None = None
    schema_digest: str | None = None
    qualification_subject_digest: str | None = None
    approved_run_id: str | None = None
    approved_attempt_id: str | None = None
    approved_boundary_id: str | None = None
    approved_workload_digest: str | None = None
    client_id: str | None = None
    deployment_id: str | None = None
    environment_id: str | None = None
    prerequisite_id: str | None = None
    configuration_digest: str | None = None
    evidence_run_id: str | None = None
    evidence_attempt_id: str | None = None
    result_uri: str | None = None
    result_digest: str | None = None
    valid_until: str | None = None
    owner_assignment_ref: str | None = None
    reason_code: str | None = None
    workload_revision_id: str | None = None
    baseline_result_id: str | None = None
    acquisition_id: str | None = None
    acquisition_mode: str | None = None
    acquisition_policy_digest: str | None = None
    execution_receipt_digest: str | None = None
    input_snapshot_digest: str | None = None
    runtime_configuration_digest: str | None = None
    output_id: str | None = None


@dataclass(frozen=True)
class ReadinessResult:
    schema_version: str
    result_id: str
    workload_id: str
    boundary_id: str | None
    run_id: str
    attempt_id: str
    policy_id: str
    policy_version: str
    policy_digest: str
    input_digest: str
    workload_digest: str
    qualification_input: dict[str, Any]
    policy_snapshot: dict[str, Any]
    evidence_references: tuple[EvidenceReference, ...]
    classification: ReadinessClassification
    checks: tuple[ReadinessCheck, ...]
    prerequisite_checklist: tuple[PrerequisiteChecklistEntry, ...]
    blockers: tuple[ReadinessBlocker, ...]
    missing_evidence: tuple[MissingEvidence, ...]
    next_actions: tuple[NextAction, ...]
    evidence_ids: tuple[str, ...]
    evaluated_at: str
    valid_until: str | None
    elapsed_ms: int
    terminal_disposition: str
    content_digest: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        payload = json.loads(json.dumps(asdict(self)))
        assert isinstance(payload, dict)
        return payload
