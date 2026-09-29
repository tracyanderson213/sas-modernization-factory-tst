"""Immutable inputs for architecture review packet assembly."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArchitectureReviewRequest:
    repo_root: Path
    factory_config: Path
    threat_model: Path
    requirements: Path
    source: Path
    discovery_manifest: Path
    workload_id: str
    subject_id: str
    boundary_id: str
    run_id: str
    attempt_id: str
    assessed_revision: str
    readiness_manifest: Path | None = None
    discovery_namespace: str = "default"
    security_policy: Path | None = None
    security_bindings: Path | None = None
    activation_evidence: Path | None = None
    disclosure_evidence: Path | None = None
    recipient_class: str | None = None
    disclosure_policy_revision: str | None = None
    retention_policy_ref: str | None = None
