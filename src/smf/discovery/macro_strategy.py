"""Versioned, fail-closed SAS macro discovery and static-resolution evidence.

This module does not execute or emulate the SAS macro processor. A unique static
definition is dependency evidence only; it is not an expansion or equivalence claim.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import re
from dataclasses import dataclass, replace
from typing import Any, cast

from smf.discovery.sas_lexical import iter_unquoted_matches, quoted_string_spans
from smf.discovery.sas_static import (
    _macro_literal_spans,
    _strip_comments,
    is_sas_system_macro_operation,
    scan_sas_include_references,
)
from smf.workload.identity import stable_id
from smf.workload.models import (
    ArtifactKind,
    MacroAnalysis,
    MacroArtifactType,
    MacroBlocker,
    MacroConstructFamily,
    MacroLogicalArtifact,
    MacroObservation,
    MacroObservationKind,
    MacroRelationshipKind,
    MacroResolution,
    MacroResolutionKind,
    MacroSourceLocation,
    RelationshipKind,
    Workload,
)

STRATEGY_ID = "smf-sas-macro-discovery"
STRATEGY_VERSION = "1.0"
_LIMITS: dict[str, int | None] = {
    "max_source_bytes": 2_000_000,
    "max_observations_per_artifact": 10_000,
    "max_observations_per_workload": 50_000,
    "max_macro_nesting_depth": 64,
    "max_include_traversal_nodes": 5_000,
    "max_graph_edges": 50_000,
    "expansion_recursion_limit": None,
    "expansion_output_bytes": None,
}

_SNAPSHOT: dict[str, Any] = {
    "strategy_id": STRATEGY_ID,
    "strategy_version": STRATEGY_VERSION,
    "sas_release_baseline": "SAS 9.4 macro language catalog",
    "expansion_mode": "none",
    "supported": {
        "definitions": ["literal %macro NAME ... %mend occurrences"],
        "invocations": ["direct literal %NAME calls"],
        "variables": ["parameters", "%let", "%global", "%local", "&NAME references"],
        "includes": ["literal single-quoted and double-quoted %include paths"],
        "quoting": {
            "protected": ["%nrstr", "%nrbquote", "%nrquote", "single-quoted SAS text"],
            "detected_only": ["%bquote", "%quote", "%str", "%superq", "%unquote"],
        },
    },
    "intrinsic_policy": (
        "cataloged SAS intrinsic, statement, reserved, SYS-prefixed, and supplied "
        "autocall operations are intrinsic_system unless an inventoried user definition exists"
    ),
    "definition_visibility": (
        "calling artifact plus transitive uniquely resolved literal include closure; "
        "unreferenced workload files and inferred autocall paths are not visible"
    ),
    "unsupported": [
        "autocall and stored compiled macro search paths",
        "CALL EXECUTE and runtime-generated macro source",
        "indirect ampersand rescanning and computed macro calls",
        "macro-generated definitions, includes, and dataset names",
        "runtime symbol-table and environment-dependent values",
        "semantic activation by detected-only macro quoting",
        "executable expansion or expanded-source claims",
    ],
    "limits": _LIMITS,
}


def strategy_snapshot() -> dict[str, Any]:
    """Return an isolated canonical copy; callers cannot override the built-in policy."""

    return cast(dict[str, Any], json.loads(json.dumps(_SNAPSHOT, sort_keys=True)))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


STRATEGY_DIGEST = hashlib.sha256(_canonical(_SNAPSHOT)).hexdigest()

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_DEF_RE = re.compile(rf"%macro\s+({_IDENT})\b", re.IGNORECASE)
_MEND_RE = re.compile(r"%mend\b", re.IGNORECASE)
_CALL_RE = re.compile(rf"%({_IDENT})(?![A-Za-z0-9_])(?!(?:\s*):)", re.IGNORECASE)
_DYNAMIC_CALL_RE = re.compile(r"%\s*(&+[A-Za-z_][A-Za-z0-9_]*\.?)", re.IGNORECASE)
_VAR_RE = re.compile(rf"&+({_IDENT})\.?", re.IGNORECASE)
_VAR_DEF_RE = re.compile(rf"%(?:let|global|local)\s+({_IDENT})\b", re.IGNORECASE)
_INCLUDE_RE = re.compile(r"%include\s+((['\"])(.*?)\2|[^;\r\n]+)", re.IGNORECASE)
_QUOTE_RE = re.compile(
    r"%(nrbquote|nrquote|nrstr|bquote|quote|str|superq|unquote)\b", re.IGNORECASE
)
_PROC_FORMAT_RE = re.compile(r"\bproc\s+format\b", re.IGNORECASE)
_FORMAT_DEF_RE = re.compile(rf"\bvalue\s+([\$]?{_IDENT})\b", re.IGNORECASE)
_TARGET_TEMPLATE_RE = re.compile(r"(?:\{\{|\{%)[\s\S]*?(?:\}\}|%\})")
_CONTROL_NAMES = {
    "abort",
    "do",
    "else",
    "end",
    "global",
    "goto",
    "if",
    "include",
    "let",
    "local",
    "macro",
    "mend",
    "put",
    "return",
    "then",
    "to",
    "until",
    "while",
}
_RUNTIME_OPERATIONS = {"qsysfunc", "resolve", "symput", "symputx", "sysfunc", "sysget"}


@dataclass(frozen=True)
class _DefinitionRange:
    definition_id: str
    artifact_id: str
    start: int
    end: int


def _macro_graph_properties(
    adjacency: dict[str, set[str]], max_depth: int
) -> tuple[dict[str, int], set[int], dict[int, int]]:
    """Classify cycles and bounded DAG depth without Python recursion.

    The returned longest-path values are capped at ``max_depth + 1`` because
    callers only need to know whether the governed nesting limit was crossed.
    """

    nodes = sorted({*adjacency, *(target for targets in adjacency.values() for target in targets)})
    forward = {node: tuple(sorted(adjacency.get(node, ()))) for node in nodes}
    reverse: dict[str, list[str]] = {node: [] for node in nodes}
    for source, targets in forward.items():
        for target in targets:
            reverse[target].append(source)
    for sources in reverse.values():
        sources.sort()

    finish_order: list[str] = []
    visited: set[str] = set()
    for start in nodes:
        if start in visited:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            stack.extend((target, False) for target in reversed(forward[node]))

    component_by_node: dict[str, int] = {}
    component_sizes: dict[int, int] = {}
    for start in reversed(finish_order):
        if start in component_by_node:
            continue
        component = len(component_sizes)
        size = 0
        pending = [start]
        component_by_node[start] = component
        while pending:
            node = pending.pop()
            size += 1
            for source in reversed(reverse[node]):
                if source not in component_by_node:
                    component_by_node[source] = component
                    pending.append(source)
        component_sizes[component] = size

    cyclic_components = {component for component, size in component_sizes.items() if size > 1}
    component_adjacency: dict[int, set[int]] = {component: set() for component in component_sizes}
    indegree = {component: 0 for component in component_sizes}
    for source, targets in forward.items():
        source_component = component_by_node[source]
        for target in targets:
            target_component = component_by_node[target]
            if (
                source_component != target_component
                and target_component not in component_adjacency[source_component]
            ):
                component_adjacency[source_component].add(target_component)
                indegree[target_component] += 1

    ready = [component for component, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    topological: list[int] = []
    while ready:
        component = heapq.heappop(ready)
        topological.append(component)
        for downstream_component in sorted(component_adjacency[component]):
            indegree[downstream_component] -= 1
            if indegree[downstream_component] == 0:
                heapq.heappush(ready, downstream_component)

    longest_from_component = {component: 0 for component in component_sizes}
    for component in reversed(topological):
        if component_adjacency[component]:
            longest_from_component[component] = min(
                max_depth + 1,
                1
                + max(longest_from_component[target] for target in component_adjacency[component]),
            )
    return component_by_node, cyclic_components, longest_from_component


def _inactive(offset: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= offset < end for start, end in spans)


def _location(
    artifact_id: str, checksum: str, source: bytes, text: str, start: int, end: int
) -> MacroSourceLocation:
    byte_start = len(text[:start].encode("utf-8"))
    byte_end = len(text[:end].encode("utf-8"))
    line_start = text.rfind("\n", 0, start) + 1
    return MacroSourceLocation(
        source_artifact_id=artifact_id,
        source_checksum=checksum,
        byte_start=byte_start,
        byte_end=byte_end,
        line=text.count("\n", 0, start) + 1,
        column=start - line_start + 1,
        span_digest=hashlib.sha256(source[byte_start:byte_end]).hexdigest(),
    )


def _observation(
    *,
    workload_id: str,
    artifact_id: str,
    checksum: str,
    source: bytes,
    text: str,
    start: int,
    end: int,
    kind: MacroObservationKind,
    identity: str,
    family: MacroConstructFamily = MacroConstructFamily.SAS_MACRO_PROCESSOR,
    logical_artifact_id: str | None = None,
) -> MacroObservation:
    location = _location(artifact_id, checksum, source, text, start, end)
    normalized = identity.casefold()
    observation_id = stable_id(
        "MOBS",
        {
            "workload": workload_id,
            "artifact": artifact_id,
            "checksum": checksum,
            "byte_start": location.byte_start,
            "byte_end": location.byte_end,
            "kind": kind.value,
            "identity": normalized,
            "strategy": STRATEGY_DIGEST,
        },
    )
    return MacroObservation(
        observation_id=observation_id,
        kind=kind,
        construct_family=family,
        normalized_identity=normalized,
        location=location,
        logical_artifact_id=logical_artifact_id,
    )


def _resolution(
    observation: MacroObservation,
    relationship: MacroRelationshipKind,
    kind: MacroResolutionKind,
    *,
    candidates: tuple[str, ...] = (),
    target_definition_id: str | None = None,
    target_artifact_id: str | None = None,
    blocker_reason: str | None = None,
) -> MacroResolution:
    identity = {
        "observation": observation.observation_id,
        "relationship": relationship.value,
        "kind": kind.value,
        "candidates": candidates,
        "target_definition": target_definition_id,
        "target_artifact": target_artifact_id,
        "strategy": STRATEGY_DIGEST,
    }
    return MacroResolution(
        resolution_id=stable_id("MRES", identity),
        observation_id=observation.observation_id,
        relationship_kind=relationship,
        kind=kind,
        candidate_definition_ids=candidates,
        target_definition_id=target_definition_id,
        target_artifact_id=target_artifact_id,
        blocker_reason=blocker_reason,
    )


def _blocker(
    reason: MacroResolutionKind,
    *,
    observation_id: str | None = None,
    artifact_id: str | None = None,
    detail: str,
) -> MacroBlocker:
    identity = {
        "reason": reason.value,
        "observation": observation_id,
        "artifact": artifact_id,
        "detail": detail,
        "strategy": STRATEGY_DIGEST,
    }
    return MacroBlocker(
        blocker_id=stable_id("MBLK", identity),
        reason=reason,
        observation_id=observation_id,
        source_artifact_id=artifact_id,
        detail=detail,
    )


def analyze_macro_workload(
    workload: Workload, source_bytes_by_artifact: dict[str, bytes]
) -> Workload:
    """Attach deterministic macro evidence derived from exact acquired bytes."""

    observations: list[MacroObservation] = []
    logical_artifacts: list[MacroLogicalArtifact] = []
    blockers: list[MacroBlocker] = []
    definition_ranges: list[_DefinitionRange] = []
    inventory: list[dict[str, str]] = []
    scan_complete = True
    sas_kinds = {
        ArtifactKind.SAS_PROGRAM,
        ArtifactKind.SAS_MACRO,
        ArtifactKind.SAS_INCLUDE,
        ArtifactKind.CONFIGURATION,
    }

    for artifact in sorted(workload.artifacts, key=lambda item: item.artifact_id):
        if artifact.kind not in sas_kinds or not (artifact.logical_path or "").lower().endswith(
            ".sas"
        ):
            continue
        if artifact.checksum:
            inventory.append(
                {"source_artifact_id": artifact.artifact_id, "source_checksum": artifact.checksum}
            )
        source = source_bytes_by_artifact.get(artifact.artifact_id)
        if source is None or artifact.checksum is None:
            scan_complete = False
            blockers.append(
                _blocker(
                    MacroResolutionKind.UNSUPPORTED,
                    artifact_id=artifact.artifact_id,
                    detail="governed_source_bytes_or_checksum_unavailable",
                )
            )
            continue
        actual_checksum = hashlib.sha256(source).hexdigest()
        if actual_checksum != artifact.checksum:
            scan_complete = False
            blockers.append(
                _blocker(
                    MacroResolutionKind.UNSUPPORTED,
                    artifact_id=artifact.artifact_id,
                    detail="source_checksum_mismatch",
                )
            )
            continue
        if len(source) > int(_LIMITS["max_source_bytes"] or 0):
            scan_complete = False
            blockers.append(
                _blocker(
                    MacroResolutionKind.LIMIT_EXCEEDED,
                    artifact_id=artifact.artifact_id,
                    detail="max_source_bytes",
                )
            )
            continue
        try:
            text = source.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            scan_complete = False
            blockers.append(
                _blocker(
                    MacroResolutionKind.UNSUPPORTED,
                    artifact_id=artifact.artifact_id,
                    detail="unsupported_utf8_encoding",
                )
            )
            continue

        masked = _strip_comments(text)
        quote_spans = quoted_string_spans(masked)
        single_spans = tuple(span for span in quote_spans if masked[span[0]] == "'")
        protected_spans = tuple(
            sorted((*single_spans, *_macro_literal_spans(masked, single_spans)))
        )
        definition_matches = list(
            iter_unquoted_matches(_DEF_RE, masked, (*quote_spans, *protected_spans))
        )
        mend_matches = list(
            iter_unquoted_matches(_MEND_RE, masked, (*quote_spans, *protected_spans))
        )

        for index, match in enumerate(definition_matches):
            name = match.group(1).casefold()
            location = _location(
                artifact.artifact_id, artifact.checksum, source, text, match.start(), match.end()
            )
            definition_id = stable_id(
                "MDEF",
                {
                    "workload": workload.workload_id,
                    "artifact": artifact.artifact_id,
                    "checksum": artifact.checksum,
                    "byte_start": location.byte_start,
                    "byte_end": location.byte_end,
                    "identity": name,
                    "strategy": STRATEGY_DIGEST,
                },
            )
            logical_artifacts.append(
                MacroLogicalArtifact(
                    logical_artifact_id=definition_id,
                    artifact_type=MacroArtifactType.SAS_MACRO_DEFINITION,
                    construct_family=MacroConstructFamily.SAS_MACRO_PROCESSOR,
                    normalized_identity=name,
                    location=location,
                )
            )
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=match.start(),
                    end=match.end(),
                    kind=MacroObservationKind.DEFINITION,
                    identity=name,
                    logical_artifact_id=definition_id,
                )
            )
            next_definition = (
                definition_matches[index + 1].start()
                if index + 1 < len(definition_matches)
                else len(text)
            )
            mend = next(
                (item for item in mend_matches if match.end() <= item.start() < next_definition),
                None,
            )
            definition_ranges.append(
                _DefinitionRange(
                    definition_id,
                    artifact.artifact_id,
                    location.byte_start,
                    len(text[: (mend.end() if mend else next_definition)].encode("utf-8")),
                )
            )
            if mend is None:
                scan_complete = False
                blockers.append(
                    _blocker(
                        MacroResolutionKind.UNSUPPORTED,
                        observation_id=observations[-1].observation_id,
                        artifact_id=artifact.artifact_id,
                        detail="unterminated_macro_definition",
                    )
                )
            header_end = masked.find(";", match.end())
            header_end = len(masked) if header_end < 0 else header_end
            header = masked[match.end() : header_end]
            if header.lstrip().startswith("("):
                header_offset = match.end()
                for parameter in re.finditer(
                    rf"(?:^|,)\s*({_IDENT})\s*(?==|,|\)|$)", header.lstrip()[1:]
                ):
                    # Locate the captured parameter in the original header without
                    # persisting its potentially sensitive default value.
                    parameter_name = parameter.group(1)
                    relative = header.casefold().find(parameter_name.casefold())
                    if relative >= 0:
                        observations.append(
                            _observation(
                                workload_id=workload.workload_id,
                                artifact_id=artifact.artifact_id,
                                checksum=artifact.checksum,
                                source=source,
                                text=text,
                                start=header_offset + relative,
                                end=header_offset + relative + len(parameter_name),
                                kind=MacroObservationKind.VARIABLE_DEFINITION,
                                identity=parameter_name,
                            )
                        )

        for match in iter_unquoted_matches(_QUOTE_RE, masked, single_spans):
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=match.start(),
                    end=match.end(),
                    kind=MacroObservationKind.QUOTING_OPERATION,
                    identity=match.group(1),
                )
            )

        definition_starts = {item.start() for item in definition_matches}
        for match in iter_unquoted_matches(_CALL_RE, masked, protected_spans):
            name = match.group(1).casefold()
            if match.start() in definition_starts or name in _CONTROL_NAMES:
                continue
            kind = (
                MacroObservationKind.INTRINSIC_OPERATION
                if is_sas_system_macro_operation(name)
                else MacroObservationKind.LITERAL_INVOCATION
            )
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=match.start(),
                    end=match.end(),
                    kind=kind,
                    identity=name,
                )
            )
        for match in iter_unquoted_matches(_DYNAMIC_CALL_RE, masked, protected_spans):
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=match.start(),
                    end=match.end(),
                    kind=MacroObservationKind.DYNAMIC_INVOCATION,
                    identity=match.group(1),
                )
            )
        for match in iter_unquoted_matches(_VAR_DEF_RE, masked, protected_spans):
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=match.start(1),
                    end=match.end(1),
                    kind=MacroObservationKind.VARIABLE_DEFINITION,
                    identity=match.group(1),
                )
            )
        for match in iter_unquoted_matches(_VAR_RE, masked, protected_spans):
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=match.start(),
                    end=match.end(),
                    kind=MacroObservationKind.VARIABLE_REFERENCE,
                    identity=match.group(1),
                )
            )
        for include_reference in scan_sas_include_references(text):
            # Translate the byte-bound shared observation back to character offsets
            # only for the common MacroSourceLocation constructor.
            start = len(source[: include_reference.byte_start].decode("utf-8"))
            end = len(source[: include_reference.byte_end].decode("utf-8"))
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=start,
                    end=end,
                    kind=MacroObservationKind.INCLUDE_REFERENCE,
                    identity=include_reference.value,
                )
            )
        if any(iter_unquoted_matches(_PROC_FORMAT_RE, masked, quote_spans)):
            for match in iter_unquoted_matches(_FORMAT_DEF_RE, masked, quote_spans):
                location = _location(
                    artifact.artifact_id,
                    artifact.checksum,
                    source,
                    text,
                    match.start(),
                    match.end(),
                )
                format_id = stable_id(
                    "MFMT",
                    {
                        "workload": workload.workload_id,
                        "artifact": artifact.artifact_id,
                        "checksum": artifact.checksum,
                        "byte_start": location.byte_start,
                        "byte_end": location.byte_end,
                        "identity": match.group(1).casefold(),
                        "strategy": STRATEGY_DIGEST,
                    },
                )
                logical_artifacts.append(
                    MacroLogicalArtifact(
                        logical_artifact_id=format_id,
                        artifact_type=MacroArtifactType.PROC_FORMAT_DEFINITION,
                        construct_family=MacroConstructFamily.SAS_PROC_FORMAT,
                        normalized_identity=match.group(1).casefold(),
                        location=location,
                    )
                )
                observations.append(
                    _observation(
                        workload_id=workload.workload_id,
                        artifact_id=artifact.artifact_id,
                        checksum=artifact.checksum,
                        source=source,
                        text=text,
                        start=match.start(),
                        end=match.end(),
                        kind=MacroObservationKind.PROC_FORMAT_DEFINITION,
                        identity=match.group(1),
                        family=MacroConstructFamily.SAS_PROC_FORMAT,
                        logical_artifact_id=format_id,
                    )
                )
        for match in iter_unquoted_matches(_TARGET_TEMPLATE_RE, masked, quote_spans):
            location = _location(
                artifact.artifact_id,
                artifact.checksum,
                source,
                text,
                match.start(),
                match.end(),
            )
            template_id = stable_id(
                "MTPL",
                {
                    "workload": workload.workload_id,
                    "artifact": artifact.artifact_id,
                    "checksum": artifact.checksum,
                    "byte_start": location.byte_start,
                    "byte_end": location.byte_end,
                    "strategy": STRATEGY_DIGEST,
                },
            )
            logical_artifacts.append(
                MacroLogicalArtifact(
                    logical_artifact_id=template_id,
                    artifact_type=MacroArtifactType.TARGET_TEMPLATE_DEFINITION,
                    construct_family=MacroConstructFamily.TARGET_TEMPLATE,
                    normalized_identity="template-expression",
                    location=location,
                )
            )
            observations.append(
                _observation(
                    workload_id=workload.workload_id,
                    artifact_id=artifact.artifact_id,
                    checksum=artifact.checksum,
                    source=source,
                    text=text,
                    start=match.start(),
                    end=match.end(),
                    kind=MacroObservationKind.TARGET_TEMPLATE,
                    identity="template-expression",
                    family=MacroConstructFamily.TARGET_TEMPLATE,
                    logical_artifact_id=template_id,
                )
            )

        artifact_count = sum(
            item.location.source_artifact_id == artifact.artifact_id for item in observations
        )
        if artifact_count > int(_LIMITS["max_observations_per_artifact"] or 0):
            scan_complete = False
            observations = [
                item
                for item in observations
                if item.location.source_artifact_id != artifact.artifact_id
            ]
            logical_artifacts = [
                item
                for item in logical_artifacts
                if item.location.source_artifact_id != artifact.artifact_id
            ]
            definition_ranges = [
                item for item in definition_ranges if item.artifact_id != artifact.artifact_id
            ]
            blockers.append(
                _blocker(
                    MacroResolutionKind.LIMIT_EXCEEDED,
                    artifact_id=artifact.artifact_id,
                    detail="max_observations_per_artifact",
                )
            )

    if len(observations) > int(_LIMITS["max_observations_per_workload"] or 0):
        scan_complete = False
        observations = []
        logical_artifacts = []
        definition_ranges = []
        blockers.append(
            _blocker(MacroResolutionKind.LIMIT_EXCEEDED, detail="max_observations_per_workload")
        )

    definitions_by_name: dict[str, list[MacroLogicalArtifact]] = {}
    for logical_item in logical_artifacts:
        if logical_item.artifact_type is MacroArtifactType.SAS_MACRO_DEFINITION:
            definitions_by_name.setdefault(logical_item.normalized_identity, []).append(
                logical_item
            )

    include_adjacency: dict[str, set[str]] = {}
    physical_artifact_ids = {
        item.artifact_id for item in workload.artifacts if item.checksum is not None
    }
    for relationship in workload.relationships:
        if (
            relationship.kind is RelationshipKind.INCLUDES
            and relationship.metadata.get("include_resolution") == "resolved"
            and relationship.target_id in physical_artifact_ids
        ):
            include_adjacency.setdefault(relationship.source_id, set()).add(relationship.target_id)

    visibility_cache: dict[str, set[str]] = {}

    def visible_artifacts(source_artifact_id: str) -> set[str]:
        cached = visibility_cache.get(source_artifact_id)
        if cached is not None:
            return cached
        visible: set[str] = set()
        pending = [source_artifact_id]
        while pending:
            current = pending.pop()
            if current in visible:
                continue
            visible.add(current)
            if len(visible) > int(_LIMITS["max_include_traversal_nodes"] or 0):
                blockers.append(
                    _blocker(
                        MacroResolutionKind.LIMIT_EXCEEDED,
                        artifact_id=source_artifact_id,
                        detail="max_include_traversal_nodes",
                    )
                )
                break
            pending.extend(sorted(include_adjacency.get(current, ()), reverse=True))
        visibility_cache[source_artifact_id] = visible
        return visible

    resolutions: list[MacroResolution] = []
    call_owners: dict[str, str] = {}
    artifact_by_id = {item.artifact_id: item for item in workload.artifacts}
    for observation in observations:
        if observation.kind in {
            MacroObservationKind.LITERAL_INVOCATION,
            MacroObservationKind.INTRINSIC_OPERATION,
        }:
            candidates = tuple(
                sorted(
                    item.logical_artifact_id
                    for item in definitions_by_name.get(observation.normalized_identity, ())
                    if item.location.source_artifact_id
                    in visible_artifacts(observation.location.source_artifact_id)
                )
            )
            if len(candidates) == 1:
                resolution = _resolution(
                    observation,
                    MacroRelationshipKind.SAS_MACRO_CALL,
                    MacroResolutionKind.UNIQUE_STATIC_DEFINITION,
                    candidates=candidates,
                    target_definition_id=candidates[0],
                )
            elif len(candidates) > 1:
                resolution = _resolution(
                    observation,
                    MacroRelationshipKind.SAS_MACRO_CALL,
                    MacroResolutionKind.AMBIGUOUS,
                    candidates=candidates,
                    blocker_reason="multiple_visible_definition_occurrences",
                )
            elif is_sas_system_macro_operation(observation.normalized_identity):
                system_kind = (
                    MacroResolutionKind.RUNTIME_DEPENDENT
                    if observation.normalized_identity in _RUNTIME_OPERATIONS
                    else MacroResolutionKind.INTRINSIC_SYSTEM
                )
                resolution = _resolution(
                    observation,
                    MacroRelationshipKind.SAS_MACRO_CALL,
                    system_kind,
                    blocker_reason=(
                        "runtime_environment_required"
                        if system_kind is MacroResolutionKind.RUNTIME_DEPENDENT
                        else None
                    ),
                )
            else:
                resolution = _resolution(
                    observation,
                    MacroRelationshipKind.SAS_MACRO_CALL,
                    MacroResolutionKind.MISSING,
                    blocker_reason="no_inventoried_definition_occurrence",
                )
            resolutions.append(resolution)
            owner = next(
                (
                    item.definition_id
                    for item in definition_ranges
                    if item.artifact_id == observation.location.source_artifact_id
                    and item.start <= observation.location.byte_start < item.end
                ),
                None,
            )
            if owner:
                call_owners[resolution.resolution_id] = owner
        elif observation.kind is MacroObservationKind.DYNAMIC_INVOCATION:
            resolutions.append(
                _resolution(
                    observation,
                    MacroRelationshipKind.SAS_MACRO_CALL,
                    MacroResolutionKind.DYNAMIC,
                    blocker_reason="computed_macro_invocation",
                )
            )
        elif observation.kind is MacroObservationKind.VARIABLE_REFERENCE:
            resolutions.append(
                _resolution(
                    observation,
                    MacroRelationshipKind.SAS_MACRO_VARIABLE_REFERENCE,
                    MacroResolutionKind.RUNTIME_DEPENDENT,
                    blocker_reason="macro_symbol_table_semantics_not_executed",
                )
            )
        elif observation.kind is MacroObservationKind.QUOTING_OPERATION:
            detected_only = observation.normalized_identity in {
                "bquote",
                "quote",
                "str",
                "superq",
                "unquote",
            }
            resolutions.append(
                _resolution(
                    observation,
                    MacroRelationshipKind.SAS_MACRO_CALL,
                    (
                        MacroResolutionKind.UNSUPPORTED
                        if detected_only
                        else MacroResolutionKind.INTRINSIC_SYSTEM
                    ),
                    blocker_reason=(
                        "macro_quoting_semantics_detected_not_executed" if detected_only else None
                    ),
                )
            )
        elif observation.kind is MacroObservationKind.INCLUDE_REFERENCE:
            raw_identity = observation.normalized_identity
            include_kind: MacroResolutionKind
            reason: str | None
            target_artifact_id: str | None
            resolution_id: object
            relationships = [
                item
                for item in workload.relationships
                if item.source_id == observation.location.source_artifact_id
                and item.kind is RelationshipKind.INCLUDES
                and any(
                    ev.observed_value
                    and ev.observed_value.casefold() == raw_identity
                    and ev.metadata.get("byte_start") == observation.location.byte_start
                    and ev.metadata.get("byte_end") == observation.location.byte_end
                    for ev in item.evidence
                )
            ]
            if len(relationships) != 1:
                include_kind, reason = (
                    MacroResolutionKind.AMBIGUOUS,
                    "include_observation_relationship_mismatch",
                )
                target_artifact_id = None
                resolution_id = None
            else:
                relationship = relationships[0]
                state = relationship.metadata.get("include_resolution")
                mapping = {
                    "resolved": (MacroResolutionKind.UNIQUE_STATIC_DEFINITION, None),
                    "dynamic": (MacroResolutionKind.DYNAMIC, "macro_generated_include"),
                    "missing": (MacroResolutionKind.MISSING, "include_target_not_in_inventory"),
                    "ambiguous": (MacroResolutionKind.AMBIGUOUS, "multiple_include_targets"),
                    "boundary_escape": (MacroResolutionKind.UNSUPPORTED, "include_boundary_escape"),
                    "cyclic": (MacroResolutionKind.CYCLIC, "cyclic_include_graph"),
                    "unsupported": (MacroResolutionKind.UNSUPPORTED, "unsupported_include"),
                    "limit_exceeded": (
                        MacroResolutionKind.LIMIT_EXCEEDED,
                        "include_limit_exceeded",
                    ),
                }
                if state not in mapping:
                    raise ValueError(f"Unsupported include resolution: {state!r}")
                include_kind, reason = mapping[str(state)]
                target_artifact_id = (
                    relationship.target_id
                    if include_kind
                    in {MacroResolutionKind.UNIQUE_STATIC_DEFINITION, MacroResolutionKind.CYCLIC}
                    and relationship.target_id in artifact_by_id
                    else None
                )
                resolution_id = relationship.metadata.get("include_resolution_id")
            resolution = _resolution(
                observation,
                MacroRelationshipKind.SAS_INCLUDE_REFERENCE,
                include_kind,
                target_artifact_id=target_artifact_id,
                blocker_reason=reason,
            )
            if isinstance(resolution_id, str):
                resolution = replace(resolution, resolution_id=resolution_id)
            resolutions.append(resolution)

    adjacency: dict[str, set[str]] = {}
    for resolved_item in resolutions:
        owner = call_owners.get(resolved_item.resolution_id)
        if (
            owner
            and resolved_item.kind is MacroResolutionKind.UNIQUE_STATIC_DEFINITION
            and resolved_item.target_definition_id
        ):
            adjacency.setdefault(owner, set()).add(resolved_item.target_definition_id)
    graph_edge_count = sum(len(targets) for targets in adjacency.values())
    graph_edge_limit_exceeded = graph_edge_count > int(_LIMITS["max_graph_edges"] or 0)
    if graph_edge_limit_exceeded:
        blockers.append(_blocker(MacroResolutionKind.LIMIT_EXCEEDED, detail="max_graph_edges"))
        component_by_node: dict[str, int] = {}
        cyclic_components: set[int] = set()
        longest_from_component: dict[int, int] = {}
    else:
        component_by_node, cyclic_components, longest_from_component = _macro_graph_properties(
            adjacency, int(_LIMITS["max_macro_nesting_depth"] or 0)
        )

    classified: list[MacroResolution] = []
    for resolved_item in resolutions:
        owner = call_owners.get(resolved_item.resolution_id)
        target = resolved_item.target_definition_id
        if owner and target and resolved_item.kind is MacroResolutionKind.UNIQUE_STATIC_DEFINITION:
            if graph_edge_limit_exceeded:
                resolved_item = replace(
                    resolved_item,
                    kind=MacroResolutionKind.LIMIT_EXCEEDED,
                    blocker_reason="max_graph_edges",
                )
            elif owner == target:
                resolved_item = replace(
                    resolved_item,
                    kind=MacroResolutionKind.RECURSIVE,
                    blocker_reason="direct_recursive_macro_call",
                )
            elif (
                component_by_node[owner] == component_by_node[target]
                and component_by_node[owner] in cyclic_components
            ):
                resolved_item = replace(
                    resolved_item,
                    kind=MacroResolutionKind.CYCLIC,
                    blocker_reason="cyclic_macro_call_graph",
                )
            elif 1 + longest_from_component[component_by_node[target]] > int(
                _LIMITS["max_macro_nesting_depth"] or 0
            ):
                resolved_item = replace(
                    resolved_item,
                    kind=MacroResolutionKind.LIMIT_EXCEEDED,
                    blocker_reason="max_macro_nesting_depth",
                )
        classified.append(resolved_item)
    resolutions = classified
    resolutions = [
        replace(
            item,
            resolution_id=stable_id(
                "MRES",
                {
                    "observation": item.observation_id,
                    "relationship": item.relationship_kind.value,
                    "kind": item.kind.value,
                    "candidates": item.candidate_definition_ids,
                    "target_definition": item.target_definition_id,
                    "target_artifact": item.target_artifact_id,
                    "strategy": STRATEGY_DIGEST,
                },
            ),
        )
        for item in resolutions
        if item.relationship_kind is not MacroRelationshipKind.SAS_INCLUDE_REFERENCE
    ] + [
        item
        for item in resolutions
        if item.relationship_kind is MacroRelationshipKind.SAS_INCLUDE_REFERENCE
    ]

    blocking_kinds = {
        MacroResolutionKind.AMBIGUOUS,
        MacroResolutionKind.CYCLIC,
        MacroResolutionKind.DYNAMIC,
        MacroResolutionKind.LIMIT_EXCEEDED,
        MacroResolutionKind.MISSING,
        MacroResolutionKind.RECURSIVE,
        MacroResolutionKind.RUNTIME_DEPENDENT,
        MacroResolutionKind.UNSUPPORTED,
    }
    observations_by_id = {item.observation_id: item for item in observations}
    for resolved_item in resolutions:
        if resolved_item.kind in blocking_kinds:
            observation = observations_by_id[resolved_item.observation_id]
            blockers.append(
                _blocker(
                    resolved_item.kind,
                    observation_id=resolved_item.observation_id,
                    artifact_id=observation.location.source_artifact_id,
                    detail=resolved_item.blocker_reason or resolved_item.kind.value,
                )
            )

    observations.sort(key=lambda item: item.observation_id)
    logical_artifacts.sort(key=lambda item: item.logical_artifact_id)
    resolutions.sort(key=lambda item: item.resolution_id)
    blockers = sorted(
        {item.blocker_id: item for item in blockers}.values(), key=lambda item: item.blocker_id
    )
    scan_complete = scan_complete and not any(
        item.reason is MacroResolutionKind.LIMIT_EXCEEDED for item in blockers
    )
    inventory.sort(key=lambda item: (item["source_artifact_id"], item["source_checksum"]))
    discovery_id = stable_id(
        "MDISC",
        {"workload": workload.workload_id, "inventory": inventory, "strategy": STRATEGY_DIGEST},
    )
    analysis_payload = {
        "discovery": discovery_id,
        "workload": workload.workload_id,
        "inventory": inventory,
        "strategy": STRATEGY_DIGEST,
        "limits": _LIMITS,
        "logical_artifacts": [item.logical_artifact_id for item in logical_artifacts],
        "observations": [item.observation_id for item in observations],
        "resolutions": [item.resolution_id for item in resolutions],
        "blockers": [item.blocker_id for item in blockers],
        "complete": scan_complete,
    }
    analysis = MacroAnalysis(
        analysis_id=stable_id("MAN", analysis_payload),
        discovery_id=discovery_id,
        workload_id=workload.workload_id,
        strategy_id=STRATEGY_ID,
        strategy_version=STRATEGY_VERSION,
        strategy_digest=STRATEGY_DIGEST,
        strategy_snapshot=strategy_snapshot(),
        expansion_mode="none",
        complete=scan_complete,
        source_inventory=tuple(inventory),
        logical_artifacts=tuple(logical_artifacts),
        observations=tuple(observations),
        resolutions=tuple(resolutions),
        blockers=tuple(blockers),
        limits_applied=dict(_LIMITS),
    )
    return replace(workload, macro_analysis=analysis)
