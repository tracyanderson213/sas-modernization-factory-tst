"""Deterministic scheduler and runtime-launch dependency discovery.

WLD-06 extracts execution ordering and launch relationships from scheduler
configuration and shell wrappers already present in a discovered workload. It
records unresolved dynamic targets instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Any

from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    Confidence,
    DiscoveryEvidence,
    EvidenceMethod,
    Relationship,
    RelationshipKind,
    Workload,
)
from smf.workload.sanitization import sanitize_discovery_value

_JIL_JOB_RE = re.compile(r"^\s*insert_job\s*:\s*(?P<name>[^\s]+)(?P<rest>.*)$", re.IGNORECASE)
_JIL_COMMAND_RE = re.compile(r"^\s*command\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_JIL_CONDITION_RE = re.compile(r"^\s*condition\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_JIL_MACHINE_RE = re.compile(r"^\s*machine\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_JIL_START_RE = re.compile(r"^\s*start_times\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_JIL_DAYS_RE = re.compile(r"^\s*days_of_week\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_JIL_JOB_TYPE_RE = re.compile(r"\bjob_type\s*:\s*(?P<value>[^\s]+)", re.IGNORECASE)
_CONDITION_JOB_RE = re.compile(
    r"\b(?:s|f|d|n|t|e|success|failure|done|notrunning)\s*\(\s*(?P<name>[A-Za-z0-9_.:-]+)",
    re.IGNORECASE,
)
_SAS_SYSIN_RE = re.compile(
    r"\bsas\b[^\n;|&]*?\s-sysin\s+(?P<target>\"[^\"]+\"|'[^']+'|[^\s;|&]+)",
    re.IGNORECASE,
)
_SCRIPT_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:(?:exec|bash|sh|ksh)\s+)?"
    r"(?P<target>(?:\.?\.?/|/)?[^\s;|&]+\.(?:sh|bash|ksh))\b",
    re.IGNORECASE,
)
_DYNAMIC_RE = re.compile(r"[$%{}]")
_CRON_RE = re.compile(r"^\s*(?P<schedule>(?:\S+\s+){4}\S+)\s+(?P<command>.+?)\s*$")


def _redact_command(command: str) -> str:
    """Apply the canonical persistence sanitizer to scheduler commands."""

    redacted = sanitize_discovery_value(command)
    assert isinstance(redacted, str)
    return redacted


def _clean_token(value: str) -> str:
    value = value.strip().strip("\"'")
    return value.rstrip(",)")


def _artifact_indexes(workload: Workload) -> tuple[dict[str, Artifact], dict[str, list[Artifact]]]:
    by_path: dict[str, Artifact] = {}
    by_name: dict[str, list[Artifact]] = {}
    for artifact in workload.artifacts:
        if artifact.logical_path:
            path = artifact.logical_path.replace("\\", "/").removeprefix("./")
            by_path[path] = artifact
        by_name.setdefault(artifact.name, []).append(artifact)
    return by_path, by_name


def _resolve_artifact(
    target: str,
    by_path: dict[str, Artifact],
    by_name: dict[str, list[Artifact]],
) -> tuple[Artifact | None, str]:
    cleaned = _clean_token(target).replace("\\", "/")
    if _DYNAMIC_RE.search(cleaned):
        return None, "dynamic"

    if cleaned.startswith("/"):
        return None, "unresolved"

    # Relative runtime targets resolve from the process working directory, not
    # from the scheduler definition or wrapper file location. Until discovery
    # has explicit working-directory evidence, resolving ./ or ../ against the
    # definition file would invent a dependency edge.
    if any(part in {".", ".."} for part in cleaned.split("/")):
        return None, "unresolved"

    exact = by_path.get(cleaned)
    if exact is not None:
        return exact, "resolved"

    # A qualified path that did not match inventory is unresolved. Falling
    # back to its basename could fabricate an edge to a different artifact.
    if "/" in cleaned:
        return None, "unresolved"

    name = PurePosixPath(cleaned).name
    matches = by_name.get(name, [])
    if len(matches) == 1:
        return matches[0], "resolved_by_unique_name"
    if len(matches) > 1:
        return None, "ambiguous"
    return None, "unresolved"


def _relationship(
    workload: Workload,
    *,
    source_id: str,
    kind: RelationshipKind,
    target_id: str,
    evidence: tuple[DiscoveryEvidence, ...],
    metadata: dict[str, Any] | None = None,
) -> Relationship:
    identity = {
        "workload": workload.workload_id,
        "source": source_id,
        "kind": kind.value,
        "target": target_id,
    }
    dependency_domain = (metadata or {}).get("dependency_domain")
    if isinstance(dependency_domain, str):
        identity["dependency_domain"] = dependency_domain
    return Relationship(
        relationship_id=stable_id("REL", identity),
        source_id=source_id,
        kind=kind,
        target_id=target_id,
        evidence=evidence,
        metadata=metadata or {},
    )


def _evidence(
    *,
    method: EvidenceMethod,
    source: str,
    line_number: int,
    observed_value: str,
    metadata: dict[str, Any] | None = None,
) -> DiscoveryEvidence:
    locator = f"line {line_number}"
    safe_source = sanitize_discovery_value(source)
    safe_observed_value = sanitize_discovery_value(observed_value)
    safe_metadata = sanitize_discovery_value(metadata or {})
    identity = {
        "method": method.value,
        "source": safe_source,
        "locator": locator,
        "observed_value": safe_observed_value,
    }
    return DiscoveryEvidence(
        evidence_id=stable_id("EV", identity),
        method=method,
        source=safe_source,
        confidence=Confidence.HIGH,
        locator=locator,
        observed_value=safe_observed_value,
        metadata=safe_metadata,
    )


def _merge_evidence(
    *groups: tuple[DiscoveryEvidence, ...],
) -> tuple[DiscoveryEvidence, ...]:
    merged = {item.evidence_id: item for group in groups for item in group}
    return tuple(merged[key] for key in sorted(merged))


def _invocations(command: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for match in _SAS_SYSIN_RE.finditer(command):
        finding = ("sas_sysin", _clean_token(match.group("target")))
        if finding not in seen:
            findings.append(finding)
            seen.add(finding)

    for match in _SCRIPT_RE.finditer(command):
        finding = ("script", _clean_token(match.group("target")))
        if finding not in seen:
            findings.append(finding)
            seen.add(finding)

    return findings


def _add_launch_relationships(
    workload: Workload,
    relationships: dict[str, Relationship],
    *,
    source_id: str,
    source_label: str,
    line_number: int,
    command: str,
    method: EvidenceMethod,
    by_path: dict[str, Artifact],
    by_name: dict[str, list[Artifact]],
) -> list[dict[str, Any]]:
    metadata_findings: list[dict[str, Any]] = []
    for invocation_kind, target in _invocations(command):
        resolved, resolution = _resolve_artifact(target, by_path, by_name)
        finding: dict[str, Any] = {
            "kind": invocation_kind,
            "target": target,
            "resolution": resolution,
            "line": line_number,
            "evidence_method": method.value,
            "source": source_label,
            # The dependency observation is the launch target. Persisting the
            # complete command can copy unrelated credentials into metadata
            # and, for unresolved launches, graph evidence.
            "observed_value": target,
        }
        if resolved is not None:
            finding["target_artifact_id"] = resolved.artifact_id
            evidence = _evidence(
                method=method,
                source=source_label,
                line_number=line_number,
                observed_value=target,
                metadata={"invocation_kind": invocation_kind, "target": target},
            )
            relationship = _relationship(
                workload,
                source_id=source_id,
                kind=RelationshipKind.TRIGGERS,
                target_id=resolved.artifact_id,
                evidence=(evidence,),
                metadata={
                    "dependency_domain": "runtime_launch",
                    "invocation_kind": invocation_kind,
                    "resolution": resolution,
                },
            )
            existing = relationships.get(relationship.relationship_id)
            if existing is not None:
                merged_evidence = {
                    item.evidence_id: item for item in (*existing.evidence, *relationship.evidence)
                }
                relationship = replace(
                    relationship,
                    evidence=tuple(merged_evidence[key] for key in sorted(merged_evidence)),
                )
            relationships[relationship.relationship_id] = relationship
        metadata_findings.append(finding)
    return metadata_findings


def _parse_jil_blocks(text: str) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _JIL_JOB_RE.match(line)
        if match:
            if current is not None:
                jobs.append(current)
            rest = match.group("rest")
            type_match = _JIL_JOB_TYPE_RE.search(rest)
            current = {
                "name": match.group("name"),
                "line": line_number,
                "job_type": type_match.group("value") if type_match else None,
            }
            continue
        if current is None:
            continue

        for key, regex in (
            ("command", _JIL_COMMAND_RE),
            ("condition", _JIL_CONDITION_RE),
            ("machine", _JIL_MACHINE_RE),
            ("start_times", _JIL_START_RE),
            ("days_of_week", _JIL_DAYS_RE),
        ):
            field_match = regex.match(line)
            if field_match:
                current[key] = field_match.group("value").strip()
                current[f"{key}_line"] = line_number
                break

    if current is not None:
        jobs.append(current)
    return jobs


def _scheduler_job_artifact(
    workload: Workload,
    *,
    name: str,
    source_path: str,
    line_number: int,
    metadata: dict[str, Any],
    referenced_only: bool = False,
) -> Artifact:
    logical_path = f"{source_path}#{name}"
    evidence = _evidence(
        method=EvidenceMethod.SCHEDULER_METADATA,
        source=source_path,
        line_number=line_number,
        observed_value=name,
        metadata={"referenced_only": referenced_only},
    )
    identity = {
        "workload": workload.workload_id,
        "kind": ArtifactKind.SCHEDULER_JOB.value,
        "name": name,
        "logical_path": logical_path,
    }
    return Artifact(
        artifact_id=stable_id("ART", identity),
        kind=ArtifactKind.SCHEDULER_JOB,
        name=name,
        logical_path=logical_path,
        evidence=(evidence,),
        metadata={
            "scheduler_format": "autosys_jil",
            "definition_status": "referenced_only" if referenced_only else "defined",
            **metadata,
        },
    )


def _discover_jil(
    workload: Workload,
    artifacts: dict[str, Artifact],
    relationships: dict[str, Relationship],
    *,
    source_path: str,
    text: str,
    by_path: dict[str, Artifact],
    by_name: dict[str, list[Artifact]],
) -> None:
    jobs = _parse_jil_blocks(text)
    job_artifacts: dict[str, Artifact] = {}

    for job in jobs:
        metadata = {
            key: _redact_command(str(job[key])) if key == "command" else job[key]
            for key in (
                "job_type",
                "machine",
                "start_times",
                "days_of_week",
                "command",
                "condition",
            )
            if job.get(key) is not None
        }
        artifact = _scheduler_job_artifact(
            workload,
            name=str(job["name"]),
            source_path=source_path,
            line_number=int(job["line"]),
            metadata=metadata,
        )
        artifacts[artifact.artifact_id] = artifact
        job_artifacts[artifact.name] = artifact

    for job in jobs:
        job_artifact = job_artifacts[str(job["name"])]
        command = job.get("command")
        if isinstance(command, str):
            invocation_metadata = _add_launch_relationships(
                workload,
                relationships,
                source_id=job_artifact.artifact_id,
                source_label=source_path,
                line_number=int(job.get("command_line", job["line"])),
                command=command,
                method=EvidenceMethod.SCHEDULER_METADATA,
                by_path=by_path,
                by_name=by_name,
            )
            if invocation_metadata:
                job_artifact = replace(
                    job_artifact,
                    metadata={
                        **job_artifact.metadata,
                        "runtime_invocations": invocation_metadata,
                    },
                )
                artifacts[job_artifact.artifact_id] = job_artifact
                job_artifacts[job_artifact.name] = job_artifact

        condition = job.get("condition")
        if not isinstance(condition, str):
            continue
        condition_line = int(job.get("condition_line", job["line"]))
        for match in _CONDITION_JOB_RE.finditer(condition):
            upstream_name = match.group("name")
            upstream = job_artifacts.get(upstream_name)
            if upstream is None:
                upstream = _scheduler_job_artifact(
                    workload,
                    name=upstream_name,
                    source_path=source_path,
                    line_number=condition_line,
                    metadata={},
                    referenced_only=True,
                )
                artifacts[upstream.artifact_id] = upstream
                job_artifacts[upstream_name] = upstream

            evidence = _evidence(
                method=EvidenceMethod.SCHEDULER_METADATA,
                source=source_path,
                line_number=condition_line,
                observed_value=condition,
                metadata={"upstream_job": upstream_name},
            )
            depends = _relationship(
                workload,
                source_id=job_artifact.artifact_id,
                kind=RelationshipKind.DEPENDS_ON,
                target_id=upstream.artifact_id,
                evidence=(evidence,),
                metadata={"dependency_domain": "scheduler", "condition": condition},
            )
            precedes = _relationship(
                workload,
                source_id=upstream.artifact_id,
                kind=RelationshipKind.PRECEDES,
                target_id=job_artifact.artifact_id,
                evidence=(evidence,),
                metadata={"dependency_domain": "scheduler", "condition": condition},
            )
            relationships[depends.relationship_id] = depends
            relationships[precedes.relationship_id] = precedes


def _discover_cron(
    workload: Workload,
    artifacts: dict[str, Artifact],
    relationships: dict[str, Relationship],
    *,
    source_path: str,
    text: str,
    by_path: dict[str, Artifact],
    by_name: dict[str, list[Artifact]],
) -> None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" in stripped.split(maxsplit=1)[0]:
            continue
        match = _CRON_RE.match(line)
        if not match:
            continue
        schedule = match.group("schedule")
        command = match.group("command")
        name = f"cron:{source_path}:{line_number}"
        evidence = _evidence(
            method=EvidenceMethod.SCHEDULER_METADATA,
            source=source_path,
            line_number=line_number,
            observed_value=f"{schedule} {_redact_command(command)}",
            metadata={"schedule": schedule},
        )
        identity = {
            "workload": workload.workload_id,
            "kind": ArtifactKind.SCHEDULER_JOB.value,
            "name": name,
            "logical_path": f"{source_path}#line-{line_number}",
        }
        job = Artifact(
            artifact_id=stable_id("ART", identity),
            kind=ArtifactKind.SCHEDULER_JOB,
            name=name,
            logical_path=f"{source_path}#line-{line_number}",
            evidence=(evidence,),
            metadata={
                "scheduler_format": "cron",
                "schedule": schedule,
                "command": _redact_command(command),
            },
        )
        artifacts[job.artifact_id] = job
        invocation_metadata = _add_launch_relationships(
            workload,
            relationships,
            source_id=job.artifact_id,
            source_label=source_path,
            line_number=line_number,
            command=command,
            method=EvidenceMethod.SCHEDULER_METADATA,
            by_path=by_path,
            by_name=by_name,
        )
        if invocation_metadata:
            artifacts[job.artifact_id] = replace(
                job,
                metadata={**job.metadata, "runtime_invocations": invocation_metadata},
            )


def _reconcile_scheduler_job_references(
    workload: Workload,
    artifacts: dict[str, Artifact],
    relationships: dict[str, Relationship],
) -> None:
    """Resolve file-local JIL placeholders against unique workload definitions."""

    definitions_by_name: dict[str, list[Artifact]] = {}
    referenced_only: list[Artifact] = []
    for artifact in artifacts.values():
        if artifact.kind is not ArtifactKind.SCHEDULER_JOB:
            continue
        if artifact.metadata.get("definition_status") == "defined":
            definitions_by_name.setdefault(artifact.name, []).append(artifact)
        elif artifact.metadata.get("definition_status") == "referenced_only":
            referenced_only.append(artifact)

    replacements: dict[str, str] = {}
    for placeholder in referenced_only:
        definitions = definitions_by_name.get(placeholder.name, [])
        if len(definitions) != 1:
            continue
        canonical = artifacts[definitions[0].artifact_id]
        artifacts[canonical.artifact_id] = replace(
            canonical,
            evidence=_merge_evidence(canonical.evidence, placeholder.evidence),
        )
        replacements[placeholder.artifact_id] = canonical.artifact_id
        del artifacts[placeholder.artifact_id]

    if not replacements:
        return

    reconciled: dict[str, Relationship] = {}
    for relationship in sorted(relationships.values(), key=lambda item: item.relationship_id):
        source_id = replacements.get(relationship.source_id, relationship.source_id)
        target_id = replacements.get(relationship.target_id, relationship.target_id)
        updated = _relationship(
            workload,
            source_id=source_id,
            kind=relationship.kind,
            target_id=target_id,
            evidence=relationship.evidence,
            metadata=relationship.metadata,
        )
        existing = reconciled.get(updated.relationship_id)
        if existing is not None:
            updated = replace(
                updated,
                evidence=_merge_evidence(existing.evidence, updated.evidence),
                metadata={**existing.metadata, **updated.metadata},
            )
        reconciled[updated.relationship_id] = updated

    relationships.clear()
    relationships.update(reconciled)


def derive_scheduler_runtime_dependencies(
    workload: Workload,
    source_text_by_path: dict[str, str],
) -> Workload:
    """Enrich a workload with deterministic scheduler and launch dependencies."""

    artifacts = {item.artifact_id: item for item in workload.artifacts}
    relationships = {item.relationship_id: item for item in workload.relationships}
    by_path, by_name = _artifact_indexes(workload)

    for artifact in workload.artifacts:
        if not artifact.logical_path:
            continue
        source_text = source_text_by_path.get(artifact.logical_path)
        if source_text is None:
            continue

        suffix = PurePosixPath(artifact.logical_path).suffix.lower()
        name = PurePosixPath(artifact.logical_path).name.lower()

        if artifact.kind is ArtifactKind.SHELL_SCRIPT:
            invocation_metadata: list[dict[str, Any]] = []
            for line_number, line in enumerate(source_text.splitlines(), start=1):
                if line.lstrip().startswith("#"):
                    continue
                invocation_metadata.extend(
                    _add_launch_relationships(
                        workload,
                        relationships,
                        source_id=artifact.artifact_id,
                        source_label=artifact.logical_path,
                        line_number=line_number,
                        command=line,
                        method=EvidenceMethod.STATIC_ANALYSIS,
                        by_path=by_path,
                        by_name=by_name,
                    )
                )
            if invocation_metadata:
                artifacts[artifact.artifact_id] = replace(
                    artifact,
                    metadata={**artifact.metadata, "runtime_invocations": invocation_metadata},
                )

        if suffix == ".jil":
            _discover_jil(
                workload,
                artifacts,
                relationships,
                source_path=artifact.logical_path,
                text=source_text,
                by_path=by_path,
                by_name=by_name,
            )
        elif suffix == ".cron" or name in {"crontab", "cron.tab"}:
            _discover_cron(
                workload,
                artifacts,
                relationships,
                source_path=artifact.logical_path,
                text=source_text,
                by_path=by_path,
                by_name=by_name,
            )

    _reconcile_scheduler_job_references(workload, artifacts, relationships)

    return replace(
        workload,
        artifacts=tuple(sorted(artifacts.values(), key=lambda item: item.artifact_id)),
        relationships=tuple(sorted(relationships.values(), key=lambda item: item.relationship_id)),
    )
