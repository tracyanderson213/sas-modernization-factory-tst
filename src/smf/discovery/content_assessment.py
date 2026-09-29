"""SAS 9.4 Content Assessment acquisition provider.

The provider consumes the documented CSV preview output when available. The
initial implementation focuses on Inventory objects.csv and preserves the raw
row as source metadata so later discovery increments can enrich the graph.
"""

import csv
from pathlib import Path

from smf.discovery.base import DiscoveryProvider, DiscoveryRequest
from smf.discovery.dependency_graph import derive_dependency_graph
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import ArtifactKind, Confidence, EvidenceMethod, Workload

_OBJECTS_FILE = "objects.csv"
_AUXILIARY_FILES = {"deployments.csv", "licenses.csv", "servers.csv"}


def find_objects_csv(source: Path) -> Path | None:
    source = source.expanduser().resolve()
    if source.is_file():
        return source if source.name.lower() == _OBJECTS_FILE else None

    direct = source / _OBJECTS_FILE
    if direct.is_file():
        return direct

    matches = sorted(
        path for path in source.rglob("*") if path.is_file() and path.name.lower() == _OBJECTS_FILE
    )
    return matches[0] if matches else None


def is_content_assessment_source(source: Path) -> bool:
    return find_objects_csv(source) is not None


def _normalized(row: dict[str, str]) -> dict[str, str]:
    return {
        str(key).strip().lower().replace(" ", "_"): (value or "").strip()
        for key, value in row.items()
        if key is not None
    }


def _first(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = row.get(name, "")
        if value:
            return value
    return ""


def _kind_for_object(type_name: str, name: str, path: str) -> ArtifactKind:
    haystack = " ".join((type_name, name, path)).lower()

    if "stored process" in haystack:
        return ArtifactKind.SAS_PROGRAM
    if "enterprise guide" in haystack:
        return ArtifactKind.SAS_PROGRAM
    if "data integration" in haystack or "job" in type_name.lower():
        return ArtifactKind.SCHEDULER_JOB
    if "macro" in haystack:
        return ArtifactKind.SAS_MACRO
    if "autoexec" in haystack or "config" in haystack:
        return ArtifactKind.CONFIGURATION
    if name.lower().endswith(".sas") or path.lower().endswith(".sas"):
        return ArtifactKind.SAS_PROGRAM
    if name.lower().endswith((".sh", ".bash", ".ksh")):
        return ArtifactKind.SHELL_SCRIPT

    return ArtifactKind.OTHER


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return [_normalized(row) for row in csv.DictReader(stream)]


def _load_auxiliary_metadata(directory: Path) -> dict[str, list[dict[str, str]]]:
    metadata: dict[str, list[dict[str, str]]] = {}
    by_name = {path.name.lower(): path for path in directory.iterdir() if path.is_file()}
    for name in sorted(_AUXILIARY_FILES):
        path = by_name.get(name)
        if path is not None:
            metadata[name.removesuffix(".csv")] = _read_csv(path)
    return metadata


class SasContentAssessmentDiscoveryProvider(DiscoveryProvider):
    """Normalize SAS 9.4 Content Assessment Inventory preview CSV evidence."""

    def discover(self, request: DiscoveryRequest) -> tuple[Workload, ...]:
        objects_csv = find_objects_csv(request.source)
        if objects_csv is None:
            raise ValueError(
                f"No SAS Content Assessment inventory objects.csv was found under {request.source}"
            )

        rows = _read_csv(objects_csv)
        auxiliary = _load_auxiliary_metadata(objects_csv.parent)
        builder = WorkloadBuilder(
            name=f"{objects_csv.parent.name}-sas9-inventory",
            namespace=request.namespace,
            metadata={
                "discovery_provider": "sas-content-assessment",
                "content_assessment_objects_csv": str(objects_csv),
                "boundary_basis": "assessment_inventory",
                "boundary_confidence": "provisional",
                "assessment_metadata": auxiliary,
            },
        )

        for index, row in enumerate(rows, start=2):
            name = _first(row, "name", "object_name") or f"assessment-object-{index}"
            type_name = _first(row, "typename", "type_name", "type")
            path = _first(row, "path", "location")
            storage_type = _first(row, "storagetype", "storage_type")
            logical_path = path or name
            kind = _kind_for_object(type_name, name, path)
            confidence = Confidence.HIGH if kind is not ArtifactKind.OTHER else Confidence.MEDIUM
            evidence = builder.evidence(
                method=EvidenceMethod.RUNTIME_METADATA,
                source="SAS 9 Content Assessment Inventory",
                confidence=confidence,
                locator=f"{objects_csv.name}:{index}",
                observed_value=type_name or storage_type or name,
                metadata={
                    "assessment_file": objects_csv.name,
                    "storage_type": storage_type,
                },
            )
            builder.add_artifact(
                kind=kind,
                name=name,
                logical_path=logical_path,
                evidence=(evidence,),
                metadata={
                    "sas_type_name": type_name,
                    "storage_type": storage_type,
                    "assessment_row": row,
                },
            )

        return (derive_dependency_graph(builder.build()),)
