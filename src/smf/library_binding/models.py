"""Immutable contracts for bounded SAS library binding resolution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class BindingState(StrEnum):
    LITERAL = "literal"
    RUNTIME_OBSERVED = "runtime_observed"
    DYNAMIC = "dynamic"
    AMBIGUOUS = "ambiguous"
    CLEARED = "cleared"
    UNRESOLVED = "unresolved"


class BindingBlocker(StrEnum):
    MISSING_MACRO = "missing_macro"
    DYNAMIC_EXPRESSION = "dynamic_expression"
    UNSUPPORTED_FORM = "unsupported_form"
    REASSIGNED = "reassigned"
    CLEARED = "cleared"
    RUNTIME_EVIDENCE_REQUIRED = "runtime_evidence_required"
    RUNTIME_EVIDENCE_INVALID = "runtime_evidence_invalid"


@dataclass(frozen=True)
class SourceDocument:
    artifact_id: str
    logical_path: str
    content: bytes
    sha256: str


@dataclass(frozen=True)
class RuntimeBindingEvidence:
    evidence_id: str
    client_id: str
    workload_id: str
    source_closure_digest: str
    policy_digest: str
    run_id: str
    attempt_id: str
    libref: str
    selected_occurrence_id: str
    observed_paths: tuple[str, ...]
    provider_id: str
    provider_version: str
    observed_at: str
    authority: str
    key_id: str
    evidence_digest: str
    signature: str


@dataclass(frozen=True)
class BindingPolicy:
    policy_id: str
    policy_version: str
    client_id: str
    allowed_runtime_providers: tuple[tuple[str, str], ...] = ()
    trusted_runtime_authorities: tuple[str, ...] = ()
    verification_keys: tuple[tuple[str, str], ...] = ()
    max_evidence_age_seconds: int = 3600
    future_skew_seconds: int = 60


@dataclass(frozen=True)
class BindingRequest:
    workload_id: str
    source_closure_digest: str
    documents: tuple[SourceDocument, ...]
    policy: BindingPolicy
    runtime_evidence: tuple[RuntimeBindingEvidence, ...]
    run_id: str
    attempt_id: str
    evaluated_at: str
