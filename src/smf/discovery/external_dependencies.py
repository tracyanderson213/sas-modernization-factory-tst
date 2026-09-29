"""Deterministic external dependency and connection inventory.

WLD-07 turns observable connection declarations and runtime prerequisites into
canonical workload dependencies. It never stores credential values, connects to
external systems, or invents a target when evidence is unresolved.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from smf.discovery.sas_data import EndpointResolution, LibraryBinding, discover_library_bindings
from smf.discovery.sas_static import SasStaticFindings, analyze_sas_source
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    Confidence,
    EvidenceMethod,
    ExternalDependencyKind,
    RelationshipKind,
)

_SYSGET_RE = re.compile(r"%sysget\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", re.IGNORECASE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STATEMENT_COMMENT_RE = re.compile(r"(?m)^\s*\*[^;]*;")
_SHELL_ENV_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|([A-Za-z_][A-Za-z0-9_]*))")
_SHELL_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")

_SHELL_BUILTINS = {
    ":",
    ".",
    "break",
    "cd",
    "continue",
    "echo",
    "eval",
    "exec",
    "exit",
    "export",
    "false",
    "printf",
    "pwd",
    "read",
    "return",
    "set",
    "shift",
    "source",
    "test",
    "true",
    "unset",
    "wait",
}
_SAS_LAUNCHERS = {"sas", "sas.exe"}


@dataclass(frozen=True)
class ExternalFinding:
    kind: ExternalDependencyKind
    name: str
    line: int
    location: str | None = None
    system: str | None = None
    metadata: dict[str, object] | None = None


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _connection_location(binding: LibraryBinding) -> str | None:
    if binding.location:
        return binding.location
    for key in ("dsn", "server", "host", "database", "schema"):
        value = binding.options.get(key)
        if value and value != "<redacted>":
            return f"{key}={value}"
    return None


def _binding_finding(binding: LibraryBinding) -> ExternalFinding:
    system: str | None
    if binding.engine == "base":
        kind = ExternalDependencyKind.FILESYSTEM
        system = "filesystem"
    else:
        kind = ExternalDependencyKind.DATABASE_CONNECTION
        system = binding.engine
    return ExternalFinding(
        kind=kind,
        name=f"libref:{binding.libref}",
        line=binding.line,
        location=_connection_location(binding),
        system=system,
        metadata={
            "libref": binding.libref,
            "engine": binding.engine,
            "connection_options": binding.options,
            "resolution": binding.resolution.value,
        },
    )


def discover_sas_external_dependencies(
    text: str,
    findings: SasStaticFindings | None = None,
) -> tuple[ExternalFinding, ...]:
    """Discover SAS-declared connections, environment requirements, and unresolved librefs."""

    findings = findings or analyze_sas_source(text)
    bindings = discover_library_bindings(text)
    discovered: list[ExternalFinding] = [_binding_finding(binding) for binding in bindings.values()]

    macro_source = _BLOCK_COMMENT_RE.sub(lambda match: "\n" * match.group(0).count("\n"), text)
    macro_source = _STATEMENT_COMMENT_RE.sub("", macro_source)
    for match in _SYSGET_RE.finditer(macro_source):
        prefix = macro_source[: match.start()]
        if prefix.count("'") % 2 == 1:
            continue
        name = match.group(1)
        discovered.append(
            ExternalFinding(
                kind=ExternalDependencyKind.ENVIRONMENT_VARIABLE,
                name=name,
                line=_line_number(macro_source, match.start()),
                system="environment",
                metadata={"resolution": EndpointResolution.UNRESOLVED.value},
            )
        )

    referenced_librefs: dict[str, int] = {}
    for reference in (*findings.reads, *findings.writes):
        if "." not in reference.value:
            continue
        libref = reference.value.split(".", 1)[0].lower()
        if libref == "work" or libref in bindings:
            continue
        referenced_librefs.setdefault(libref, reference.line)

    for libref, line in referenced_librefs.items():
        discovered.append(
            ExternalFinding(
                kind=ExternalDependencyKind.UNRESOLVED_CONNECTION,
                name=f"libref:{libref}",
                line=line,
                system=libref,
                metadata={"libref": libref, "resolution": EndpointResolution.UNRESOLVED.value},
            )
        )

    return tuple(discovered)


def _shell_commands(text: str) -> tuple[ExternalFinding, ...]:
    findings: list[ExternalFinding] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            lexer = shlex.shlex(raw_line, posix=True, punctuation_chars=";&|")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError:
            continue

        at_command_start = True
        for token in tokens:
            if token in {";", "&&", "||", "|", "&"}:
                at_command_start = True
                continue
            if not at_command_start:
                continue
            if "=" in token and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
                continue
            at_command_start = False
            command = token.rsplit("/", 1)[-1]
            if command in _SHELL_BUILTINS or command.lower() in _SAS_LAUNCHERS:
                continue
            if command.startswith("$"):
                continue
            findings.append(
                ExternalFinding(
                    kind=ExternalDependencyKind.EXECUTABLE,
                    name=command,
                    line=line_number,
                    location=token if "/" in token else None,
                    system="executable",
                    metadata={"resolution": EndpointResolution.PARTIAL.value},
                )
            )
    return tuple(findings)


def _shell_env_matches(text: str) -> tuple[tuple[str, int], ...]:
    values: list[tuple[str, int]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        in_single = False
        in_double = False
        escaped = False
        comment_at: int | None = None
        single_spans: list[tuple[int, int]] = []
        single_start: int | None = None
        for index, char in enumerate(raw_line):
            if escaped:
                escaped = False
                continue
            if char == "\\" and not in_single:
                escaped = True
                continue
            if char == "'" and not in_double:
                if in_single:
                    assert single_start is not None
                    single_spans.append((single_start, index + 1))
                    single_start = None
                else:
                    single_start = index
                in_single = not in_single
                continue
            if char == '"' and not in_single:
                in_double = not in_double
                continue
            if char == "#" and not in_single and not in_double:
                comment_at = index
                break
        searchable = raw_line if comment_at is None else raw_line[:comment_at]
        for match in _SHELL_ENV_RE.finditer(searchable):
            if any(start <= match.start() < end for start, end in single_spans):
                continue
            name = match.group(1) or match.group(2)
            values.append((name, line_number))
    return tuple(values)


def discover_shell_external_dependencies(text: str) -> tuple[ExternalFinding, ...]:
    """Discover shell environment-variable references and external commands."""

    locally_assigned = {
        match.group(1)
        for line in text.splitlines()
        if (match := _SHELL_ASSIGNMENT_RE.match(line)) is not None
    }
    findings: list[ExternalFinding] = list(_shell_commands(text))
    for name, line_number in _shell_env_matches(text):
        if name in locally_assigned:
            continue
        findings.append(
            ExternalFinding(
                kind=ExternalDependencyKind.ENVIRONMENT_VARIABLE,
                name=name,
                line=line_number,
                system="environment",
                metadata={"resolution": EndpointResolution.UNRESOLVED.value},
            )
        )
    return tuple(findings)


def add_external_dependencies_to_workload(
    builder: WorkloadBuilder,
    artifact: Artifact,
    source_text: str,
    *,
    sas_findings: SasStaticFindings | None = None,
) -> None:
    """Normalize discovered external prerequisites into the canonical workload graph."""

    if artifact.logical_path is None:
        return
    if artifact.logical_path.lower().endswith(".sas"):
        findings = discover_sas_external_dependencies(source_text, sas_findings)
    elif artifact.kind is ArtifactKind.SHELL_SCRIPT:
        findings = discover_shell_external_dependencies(source_text)
    else:
        return

    for finding in findings:
        metadata = dict(finding.metadata or {})
        evidence = builder.evidence(
            method=EvidenceMethod.STATIC_ANALYSIS,
            source=artifact.logical_path,
            confidence=(
                Confidence.HIGH
                if finding.kind
                in {ExternalDependencyKind.DATABASE_CONNECTION, ExternalDependencyKind.FILESYSTEM}
                else Confidence.MEDIUM
            ),
            locator=f"{artifact.logical_path}:{finding.line}",
            observed_value=finding.name,
            metadata={"external_dependency_kind": finding.kind.value},
        )
        dependency = builder.add_external_dependency(
            kind=finding.kind,
            name=finding.name,
            location=finding.location,
            system=finding.system,
            evidence=(evidence,),
            metadata=metadata,
        )
        builder.add_relationship(
            source_id=artifact.artifact_id,
            kind=RelationshipKind.DEPENDS_ON,
            target_id=dependency.dependency_id,
            evidence=(evidence,),
            metadata={"dependency_scope": "external"},
        )
