"""Deterministic SAS data-source and output characterization.

WLD-04 enriches literal data references discovered by the SAS static analyzer.
It classifies endpoints from observable LIBNAME and source syntax without
attempting to connect to external systems or resolve dynamic macro values.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from smf.discovery.sas_lexical import iter_unquoted_matches, quoted_string_spans
from smf.workload.identity import stable_id
from smf.workload.models import DatasetIdentityResolution, DatasetKind
from smf.workload.sanitization import REDACTED, is_secret_field_name

_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_LIBNAME_RE = re.compile(rf"\blibname\s+({_IDENTIFIER})\s+([^;]+);", re.IGNORECASE)
_QUOTED_RE = re.compile(r"^(['\"])(.*?)\1(?:\s|$)")
_ENGINE_RE = re.compile(rf"^({_IDENTIFIER})(?:\s|$)")
_OPTION_RE = re.compile(rf"\b({_IDENTIFIER})\s*=\s*(?:(['\"])(.*?)\2|([^\s;]+))", re.IGNORECASE)

_DB_ENGINES = {
    "db2",
    "greenplm",
    "hadoop",
    "impala",
    "jdbc",
    "mysql",
    "netezza",
    "odbc",
    "oledb",
    "oracle",
    "postgres",
    "redshift",
    "snowflake",
    "sqlsvr",
    "teradata",
}

LINEAGE_STRATEGY_ID = "smf-sas-static-data-lineage"
LINEAGE_STRATEGY_VERSION = "1.0"
LINEAGE_POLICY = {
    "strategy_id": LINEAGE_STRATEGY_ID,
    "strategy_version": LINEAGE_STRATEGY_VERSION,
    "identity": "qualified_literal_dataset_with_per_artifact_library_binding",
    "producer_selection": "unique_observed_writer_only",
    "runtime_order_inference": False,
    "dynamic_reference_resolution": False,
}
LINEAGE_POLICY_DIGEST = hashlib.sha256(
    json.dumps(LINEAGE_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()


def dataset_access_id(
    *,
    workload_id: str,
    artifact_id: str,
    artifact_checksum: str,
    role: str,
    normalized_reference: str,
    byte_start: int,
    byte_end: int,
    line: int,
    column: int,
    source_checksum: str,
    span_digest: str,
    dataset_kind: str,
    dataset_system: str | None,
    dataset_location: str | None,
    identity_resolution: str,
    scope_discriminator: str | None,
) -> str:
    """Return the canonical identity for one acquired source occurrence."""

    return stable_id(
        "DACC",
        {
            "workload": workload_id,
            "artifact": artifact_id,
            "artifact_checksum": artifact_checksum,
            "role": role,
            "reference": normalized_reference,
            "line": line,
            "column": column,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "source_checksum": source_checksum,
            "span_digest": span_digest,
            "dataset_identity": {
                "kind": dataset_kind,
                "name": normalized_reference,
                "system": dataset_system,
                "location": dataset_location,
                "resolution": identity_resolution,
                "scope": scope_discriminator,
            },
            "policy": LINEAGE_POLICY_DIGEST,
        },
    )


class EndpointResolution(StrEnum):
    RESOLVED = "resolved"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class LibraryBinding:
    libref: str
    engine: str | None
    location: str | None
    options: dict[str, str] = field(default_factory=dict)
    line: int = 1
    resolution: EndpointResolution = EndpointResolution.PARTIAL


@dataclass(frozen=True)
class DatasetCharacterization:
    kind: DatasetKind
    system: str | None
    normalized_name: str
    identity_resolution: DatasetIdentityResolution
    scope_discriminator: str | None = None
    location: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_options(body: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in _OPTION_RE.finditer(body):
        key = match.group(1).lower()
        value = match.group(3) or match.group(4) or ""
        values[key] = REDACTED if is_secret_field_name(key) else value
    return values


def discover_library_bindings(text: str) -> dict[str, LibraryBinding]:
    """Discover literal LIBNAME bindings while redacting credential-like options."""

    bindings: dict[str, LibraryBinding] = {}
    quote_spans = quoted_string_spans(text)
    for match in iter_unquoted_matches(_LIBNAME_RE, text, quote_spans):
        libref = match.group(1).lower()
        body = match.group(2).strip()
        quoted = _QUOTED_RE.match(body)
        engine: str | None = None
        location: str | None = None
        resolution = EndpointResolution.PARTIAL

        if quoted is not None:
            engine = "base"
            location = quoted.group(2)
            resolution = EndpointResolution.RESOLVED
        else:
            engine_match = _ENGINE_RE.match(body)
            if engine_match is not None:
                engine = engine_match.group(1).lower()
                if engine in {"clear", "list"}:
                    continue
                if engine in _DB_ENGINES:
                    resolution = EndpointResolution.PARTIAL

        bindings[libref] = LibraryBinding(
            libref=libref,
            engine=engine,
            location=location,
            options=_safe_options(body),
            line=_line_number(text, match.start()),
            resolution=resolution,
        )
    return bindings


def characterize_dataset(
    name: str,
    bindings: dict[str, LibraryBinding],
    *,
    scope_discriminator: str = "discovered_workload",
) -> DatasetCharacterization:
    """Classify a literal SAS dataset reference using discovered library evidence."""

    normalized = name.lower()
    if "." not in normalized:
        return DatasetCharacterization(
            kind=DatasetKind.INTERMEDIATE,
            system="work",
            normalized_name=f"work.{normalized}",
            identity_resolution=DatasetIdentityResolution.PROVISIONAL,
            scope_discriminator=scope_discriminator,
            metadata={
                "libref": "work",
                "member": normalized,
                "resolution": DatasetIdentityResolution.PROVISIONAL.value,
                "scope_discriminator": scope_discriminator,
            },
        )

    libref, member = normalized.split(".", 1)
    if libref == "work":
        return DatasetCharacterization(
            kind=DatasetKind.INTERMEDIATE,
            system="work",
            normalized_name=f"work.{member}",
            identity_resolution=DatasetIdentityResolution.PROVISIONAL,
            scope_discriminator=scope_discriminator,
            metadata={
                "libref": "work",
                "member": member,
                "resolution": DatasetIdentityResolution.PROVISIONAL.value,
                "scope_discriminator": scope_discriminator,
            },
        )

    binding = bindings.get(libref)
    if binding is None:
        return DatasetCharacterization(
            kind=DatasetKind.SAS_DATASET,
            system=libref,
            normalized_name=normalized,
            identity_resolution=DatasetIdentityResolution.UNRESOLVED,
            scope_discriminator=scope_discriminator,
            metadata={
                "libref": libref,
                "member": member,
                "resolution": DatasetIdentityResolution.UNRESOLVED.value,
                "scope_discriminator": scope_discriminator,
            },
        )

    metadata: dict[str, object] = {
        "libref": libref,
        "member": member,
        "engine": binding.engine,
        "library_location": binding.location,
        "connection_options": binding.options,
        "resolution": binding.resolution.value,
    }
    if binding.engine in _DB_ENGINES:
        return DatasetCharacterization(
            kind=DatasetKind.DATABASE_TABLE,
            system=binding.engine,
            normalized_name=normalized,
            identity_resolution=DatasetIdentityResolution.UNRESOLVED,
            scope_discriminator=scope_discriminator,
            location=f"{libref}.{member}",
            metadata={
                **metadata,
                "resolution": DatasetIdentityResolution.UNRESOLVED.value,
                "scope_discriminator": scope_discriminator,
            },
        )

    identity_resolution = (
        DatasetIdentityResolution.RESOLVED
        if binding.resolution is EndpointResolution.RESOLVED and binding.location
        else DatasetIdentityResolution.UNRESOLVED
    )
    return DatasetCharacterization(
        kind=DatasetKind.SAS_DATASET,
        system=libref,
        normalized_name=normalized,
        identity_resolution=identity_resolution,
        scope_discriminator=None
        if identity_resolution is DatasetIdentityResolution.RESOLVED
        else scope_discriminator,
        location=f"{binding.location}/{member}" if binding.location else None,
        metadata={
            **metadata,
            "resolution": identity_resolution.value,
            **(
                {"scope_discriminator": scope_discriminator}
                if identity_resolution is DatasetIdentityResolution.UNRESOLVED
                else {}
            ),
        },
    )
