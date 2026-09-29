"""Read-only filesystem acquisition provider."""

import hashlib
from pathlib import Path

from smf.discovery.base import DiscoveryProvider, DiscoveryRequest
from smf.discovery.boundaries import derive_workload_boundaries
from smf.discovery.code_dependencies import derive_code_dependencies
from smf.discovery.code_dependency_analysis import derive_code_dependency_analysis
from smf.discovery.dependency_graph import derive_dependency_graph
from smf.discovery.downstream import derive_downstream_outputs
from smf.discovery.external_dependencies import add_external_dependencies_to_workload
from smf.discovery.include_reconciliation import reconcile_include_artifacts
from smf.discovery.lineage import derive_data_lineage
from smf.discovery.macro_strategy import analyze_macro_workload
from smf.discovery.sas_static import add_findings_to_workload, analyze_sas_source
from smf.discovery.scheduler_runtime import derive_scheduler_runtime_dependencies
from smf.discovery.topology import derive_current_state_topology
from smf.modernization.disposition import derive_modernization_disposition_inputs
from smf.modernization.target_state import derive_target_state_pattern_inputs
from smf.modernization.waves import derive_migration_wave_groups
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import ArtifactKind, Confidence, EvidenceMethod, Workload

_IGNORED_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
}

_SHELL_SUFFIXES = {".bash", ".ksh", ".sh"}
_CONFIGURATION_SUFFIXES = {
    ".cfg",
    ".conf",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".xml",
    ".yaml",
    ".yml",
}
_SCHEDULER_SUFFIXES = {".cron", ".jil"}


def _artifact_kind(path: Path) -> ArtifactKind:
    suffix = path.suffix.lower()
    name = path.name.lower()
    parts = {part.lower() for part in path.parts}

    if suffix == ".sas":
        if name in {"autoexec.sas", "config.sas"}:
            return ArtifactKind.CONFIGURATION
        if "macros" in parts or "macro" in parts:
            return ArtifactKind.SAS_MACRO
        if "includes" in parts or "include" in parts:
            return ArtifactKind.SAS_INCLUDE
        return ArtifactKind.SAS_PROGRAM

    if suffix in _SHELL_SUFFIXES:
        return ArtifactKind.SHELL_SCRIPT
    if suffix in _SCHEDULER_SUFFIXES or name in {"crontab", "cron.tab"}:
        return ArtifactKind.SCHEDULER_JOB
    if suffix in _CONFIGURATION_SUFFIXES:
        return ArtifactKind.CONFIGURATION

    return ArtifactKind.OTHER


class FilesystemDiscoveryProvider(DiscoveryProvider):
    """Inventory a readable source tree without modifying the source."""

    def discover(self, request: DiscoveryRequest) -> tuple[Workload, ...]:
        source = request.source.expanduser().resolve()
        if not source.exists():
            raise FileNotFoundError(f"Discovery source does not exist: {source}")

        root = source if source.is_dir() else source.parent
        name = request.logical_name or (source.name if source.is_dir() else source.stem)
        builder = WorkloadBuilder(
            name=name,
            namespace=request.namespace,
            metadata={
                "discovery_provider": "filesystem",
                "source_root": request.source_locator or str(source),
                "boundary_basis": "source_root",
                "boundary_confidence": "provisional",
            },
        )

        paths = [source] if source.is_file() else sorted(source.rglob("*"))
        source_text_by_path: dict[str, str] = {}
        source_bytes_by_path: dict[str, bytes] = {}
        for path in paths:
            if not path.is_file():
                continue
            if any(part in _IGNORED_NAMES for part in path.parts):
                continue

            logical_path = path.relative_to(root).as_posix()
            kind = _artifact_kind(path)
            confidence = Confidence.HIGH if kind is not ArtifactKind.OTHER else Confidence.LOW
            evidence = builder.evidence(
                method=EvidenceMethod.FILESYSTEM,
                source="filesystem_acquisition",
                confidence=confidence,
                locator=logical_path,
                observed_value=kind.value,
            )
            try:
                acquired_bytes = path.read_bytes()
                checksum = hashlib.sha256(acquired_bytes).hexdigest()
                source_bytes_by_path[logical_path] = acquired_bytes
            except OSError as exc:
                acquired_bytes = None
                checksum = None
                evidence = builder.evidence(
                    method=EvidenceMethod.FILESYSTEM,
                    source="filesystem_acquisition",
                    confidence=Confidence.LOW,
                    locator=logical_path,
                    observed_value="unreadable",
                    metadata={"error": str(exc)},
                )

            stat = path.stat()
            metadata: dict[str, object] = {
                "size_bytes": stat.st_size,
                "modified_time_ns": stat.st_mtime_ns,
                "acquisition_boundary_safe": path.resolve().is_relative_to(root),
                "symlink_mediated": path.is_symlink(),
            }
            findings = None
            source_text = None
            if kind in {
                ArtifactKind.SAS_PROGRAM,
                ArtifactKind.SAS_MACRO,
                ArtifactKind.SAS_INCLUDE,
                ArtifactKind.CONFIGURATION,
                ArtifactKind.SHELL_SCRIPT,
                ArtifactKind.SCHEDULER_JOB,
            }:
                try:
                    if acquired_bytes is None:
                        raise OSError("source bytes unavailable")
                    source_text = acquired_bytes.decode("utf-8", errors="strict")
                    source_text_by_path[logical_path] = source_text
                except (OSError, UnicodeDecodeError) as exc:
                    metadata["source_text_error"] = str(exc)

            if path.suffix.lower() == ".sas" and source_text is not None:
                findings = analyze_sas_source(source_text)
                metadata["sas_static"] = findings.metadata()

            artifact = builder.add_artifact(
                kind=kind,
                name=path.name,
                logical_path=logical_path,
                checksum=checksum,
                evidence=(evidence,),
                metadata=metadata,
            )
            if findings is not None:
                add_findings_to_workload(builder, artifact, findings, source_text=source_text)
            if source_text is not None:
                add_external_dependencies_to_workload(
                    builder, artifact, source_text, sas_findings=findings
                )

        workload = reconcile_include_artifacts(builder.build())
        artifact_bytes = {
            artifact.artifact_id: source_bytes_by_path[artifact.logical_path]
            for artifact in workload.artifacts
            if artifact.logical_path in source_bytes_by_path
        }
        workload = analyze_macro_workload(workload, artifact_bytes)
        workload = derive_scheduler_runtime_dependencies(workload, source_text_by_path)
        workload = derive_code_dependencies(workload)
        workload = derive_code_dependency_analysis(workload)
        workload = derive_data_lineage(workload, artifact_bytes=artifact_bytes)
        workload = derive_downstream_outputs(workload)
        workload = derive_dependency_graph(workload)
        workload = derive_workload_boundaries(workload)
        workload = derive_current_state_topology(workload)
        workload = derive_modernization_disposition_inputs(workload)
        workload = derive_target_state_pattern_inputs(workload)
        return (derive_migration_wave_groups(workload),)
