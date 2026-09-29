"""Deterministic SAS source reference discovery.

This module intentionally focuses on references that can be observed directly in
source text. It does not attempt macro expansion, SAS execution, or AI-based
inference. Dynamic references are preserved as unresolved findings instead of
being guessed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from smf.discovery.sas_data import (
    LINEAGE_POLICY_DIGEST,
    characterize_dataset,
    dataset_access_id,
    discover_library_bindings,
)
from smf.discovery.sas_lexical import iter_unquoted_matches, quoted_string_spans
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    Confidence,
    DatasetKind,
    DiscoveryEvidence,
    EvidenceMethod,
    RelationshipKind,
)

_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_DATASET = rf"(?:{_IDENTIFIER}\.)?{_IDENTIFIER}"

_LIBNAME_RE = re.compile(rf"\blibname\s+({_IDENTIFIER})\b([^;]*);", re.IGNORECASE)
_DATA_RE = re.compile(r"\bdata\s+([^;]+);", re.IGNORECASE)
_SET_RE = re.compile(r"\bset\s+([^;]+);", re.IGNORECASE)
_MERGE_RE = re.compile(r"\bmerge\s+([^;]+);", re.IGNORECASE)
_BY_RE = re.compile(r"(?im)(?:^|;)\s*by\s+([^;]+);")
_INFILE_RE = re.compile(r"\binfile\s+(['\"])(.*?)\1", re.IGNORECASE)
_FILE_RE = re.compile(r"\bfile\s+(['\"])(.*?)\1", re.IGNORECASE)
_INCLUDE_RE = re.compile(r"%include\s+(['\"])(.*?)\1", re.IGNORECASE)
_MACRO_DEF_RE = re.compile(rf"%macro\s+({_IDENTIFIER})\b", re.IGNORECASE)
_MACRO_CALL_RE = re.compile(
    rf"%({_IDENTIFIER})(?![A-Za-z0-9_])(?!(?:\s*):)",
    re.IGNORECASE,
)
_DYNAMIC_MACRO_CALL_RE = re.compile(r"%\s*(&[A-Za-z_][A-Za-z0-9_]*\.?)", re.IGNORECASE)
_MACRO_VAR_RE = re.compile(rf"&({_IDENTIFIER})\.?", re.IGNORECASE)
_SQL_CREATE_RE = re.compile(rf"\bcreate\s+table\s+({_DATASET})\b", re.IGNORECASE)
_SQL_INSERT_RE = re.compile(rf"\binsert\s+into\s+({_DATASET})\b", re.IGNORECASE)
_SQL_UPDATE_RE = re.compile(rf"\bupdate\s+({_DATASET})\b", re.IGNORECASE)
_SQL_FROM_JOIN_RE = re.compile(rf"\b(?:from|join)\s+({_DATASET})\b", re.IGNORECASE)
_PROC_DATA_RE = re.compile(
    rf"\bproc\s+({_IDENTIFIER})\b([^;]*?)\bdata\s*=\s*({_DATASET})",
    re.IGNORECASE,
)
_PROC_OUT_RE = re.compile(
    rf"\bproc\s+{_IDENTIFIER}\b([^;]*?)\bout\s*=\s*({_DATASET})",
    re.IGNORECASE,
)
_PROC_STATEMENT_RE = re.compile(rf"\bproc\s+{_IDENTIFIER}\b([^;]*);", re.IGNORECASE)
_PROC_DATASET_OPTION_RE = re.compile(r"\b(?:data|out)\s*=\s*([^\s;]+)", re.IGNORECASE)

_RESERVED_DATA_TOKENS = {
    "_null_",
    "view",
}
_SAS_INTRINSIC_MACROS = {
    "abort",
    "bquote",
    "cmpres",
    "copy",
    "datatyp",
    "display",
    "do",
    "else",
    "end",
    "eval",
    "global",
    "goto",
    "if",
    "include",
    "index",
    "inputn",
    "kindex",
    "kscan",
    "ksubstr",
    "kupcase",
    "label",
    "length",
    "let",
    "list",
    "local",
    "lowcase",
    "macro",
    "mend",
    "nrbquote",
    "nrcmpres",
    "nrquote",
    "nrstr",
    "qkscan",
    "put",
    "qscan",
    "qsubstr",
    "qsysfunc",
    "quote",
    "return",
    "scan",
    "str",
    "substr",
    "superq",
    "sysevalf",
    "sysexec",
    "sysfunc",
    "sysget",
    "syslput",
    "sysmacdelete",
    "sysmacexec",
    "sysmacexist",
    "sysmexecdepth",
    "sysmexecname",
    "sysmget",
    "symdel",
    "symexist",
    "symglobl",
    "symlocal",
    "symnext",
    "symput",
    "symputx",
    "symq",
    "symvar",
    "then",
    "to",
    "trim",
    "unquote",
    "until",
    "upcase",
    "while",
}
_SAS_MACRO_STATEMENTS = {
    "abort",
    "copy",
    "display",
    "do",
    "else",
    "end",
    "global",
    "goto",
    "if",
    "include",
    "label",
    "let",
    "list",
    "local",
    "macro",
    "mend",
    "put",
    "return",
    "sysexec",
    "syslput",
    "sysmacdelete",
    "symdel",
    "then",
    "to",
    "until",
    "while",
}

# AD-02 SAS 9.4 system macro classification.
# These are language/runtime elements, not cross-program user macro dependencies.
_SAS_94_MACRO_FUNCTIONS = {
    "bquote",
    "eval",
    "index",
    "kcmpres",
    "kindex",
    "kleft",
    "klength",
    "kscan",
    "ksubstr",
    "kupcase",
    "length",
    "nrbquote",
    "nrquote",
    "nrstr",
    "qkleft",
    "qkcmpres",
    "qkscan",
    "qksubstr",
    "qkupcase",
    "qscan",
    "qsubstr",
    "qsysfunc",
    "quote",
    "qupcase",
    "scan",
    "str",
    "substr",
    "superq",
    "symexist",
    "symglobl",
    "symlocal",
    "sysevalf",
    "sysfunc",
    "sysget",
    "sysmacexec",
    "sysmacexist",
    "sysmexecdepth",
    "sysmexecname",
    "sysprod",
    "unquote",
    "upcase",
}
_SAS_94_SUPPLIED_AUTOCALL_MACROS = {
    "cmpres",
    "compstor",
    "datatyp",
    "left",
    "lowcase",
    "qcmpres",
    "qleft",
    "qlowcase",
    "qtrim",
    "sysrc",
    "trim",
    "verify",
    "klowcase",
    "kverify",
    "ktrim",
    "qklowcase",
    "qktrim",
}
_SAS_94_MACRO_STATEMENTS_COMPLETE = {
    "abort",
    "copy",
    "display",
    "do",
    "else",
    "end",
    "global",
    "goto",
    "if",
    "input",
    "label",
    "let",
    "local",
    "macro",
    "mend",
    "put",
    "return",
    "symdel",
    "syscall",
    "sysexec",
    "syslput",
    "sysrput",
    "sysmstoreclear",
    "then",
    "to",
    "until",
    "while",
    "window",
    "include",
    "list",
    "run",
}
_SAS_94_MACRO_RESERVED_WORDS = {
    "abend",
    "abort",
    "act",
    "activate",
    "bquote",
    "by",
    "clear",
    "close",
    "cms",
    "comandr",
    "copy",
    "deact",
    "del",
    "delete",
    "display",
    "dmidsplay",
    "dmisplit",
    "do",
    "edit",
    "else",
    "end",
    "eval",
    "file",
    "global",
    "go",
    "goto",
    "if",
    "inc",
    "include",
    "infile",
    "input",
    "kcmpres",
    "kindex",
    "kleft",
    "klength",
    "kscan",
    "ksubstr",
    "ktrim",
    "kupcase",
    "length",
    "let",
    "list",
    "listm",
    "local",
    "macro",
    "mend",
    "metasym",
    "nrbquote",
    "nrquote",
    "nrstr",
    "on",
    "open",
    "pause",
    "put",
    "qkcmpres",
    "qkleft",
    "qkscan",
    "qksubstr",
    "qktrim",
    "qkupcase",
    "qscan",
    "qsubstr",
    "qsysfunc",
    "quote",
    "qupcase",
    "resolve",
    "return",
    "run",
    "save",
    "scan",
    "stop",
    "str",
    "substr",
    "superq",
    "symdel",
    "symexist",
    "symglobl",
    "symlocal",
    "syscall",
    "sysevalf",
    "sysexec",
    "sysfunc",
    "sysget",
    "sysrput",
    "then",
    "to",
    "tso",
    "unquote",
    "unstr",
    "until",
    "upcase",
    "while",
    "window",
}
_SAS_INTRINSIC_MACROS.update(_SAS_94_MACRO_FUNCTIONS)
_SAS_INTRINSIC_MACROS.update(_SAS_94_SUPPLIED_AUTOCALL_MACROS)
_SAS_INTRINSIC_MACROS.update(_SAS_94_MACRO_STATEMENTS_COMPLETE)
_SAS_INTRINSIC_MACROS.update(_SAS_94_MACRO_RESERVED_WORDS)
_SAS_MACRO_STATEMENTS.update(_SAS_94_MACRO_STATEMENTS_COMPLETE)


def is_sas_system_macro_operation(name: str) -> bool:
    """Return whether a macro token is supplied or reserved by SAS 9.4.

    The explicit catalog covers the Base and NLS macro functions, macro
    statements, percent-prefixed SAS statements, and supplied autocall macros.
    SAS also reserves the ``SYS`` prefix for macro-language elements, so future
    and product-specific system operations do not become fabricated estate gaps.
    """

    normalized = name.casefold()
    return normalized in _SAS_INTRINSIC_MACROS or normalized.startswith("sys")


@dataclass(frozen=True)
class SasReference:
    """One deterministic source reference with source-line evidence."""

    value: str
    line: int
    relationship_kind: RelationshipKind | None = None
    column: int | None = None
    byte_start: int | None = None
    byte_end: int | None = None
    source_checksum: str | None = None
    span_digest: str | None = None


@dataclass(frozen=True)
class SasIncludeReference:
    """A literal include observation bound to exact UTF-8 source bytes."""

    value: str
    line: int
    column: int
    byte_start: int
    byte_end: int
    source_checksum: str
    span_digest: str


@dataclass(frozen=True)
class SasStaticFindings:
    """Static facts found in one SAS source artifact."""

    reads: tuple[SasReference, ...] = ()
    writes: tuple[SasReference, ...] = ()
    input_files: tuple[SasReference, ...] = ()
    output_files: tuple[SasReference, ...] = ()
    includes: tuple[SasIncludeReference, ...] = ()
    libraries: tuple[SasReference, ...] = ()
    by_variables: tuple[str, ...] = ()
    macro_definitions: tuple[str, ...] = ()
    macro_invocations: tuple[str, ...] = ()
    macro_definition_references: tuple[SasReference, ...] = ()
    macro_invocation_references: tuple[SasReference, ...] = ()
    dynamic_macro_invocations: tuple[SasReference, ...] = ()
    macro_variables: tuple[str, ...] = ()
    dynamic_dataset_references: tuple[str, ...] = ()
    dynamic_dataset_reference_details: tuple[SasReference, ...] = ()

    def metadata(self) -> dict[str, object]:
        return {
            "libraries": sorted({item.value for item in self.libraries}),
            "by_variables": sorted(set(self.by_variables)),
            "macro_definitions": sorted(set(self.macro_definitions)),
            "macro_invocations": sorted(set(self.macro_invocations)),
            "macro_definition_references": [
                {"value": item.value, "line": item.line}
                for item in self.macro_definition_references
            ],
            "macro_invocation_references": [
                {"value": item.value, "line": item.line}
                for item in self.macro_invocation_references
            ],
            "dynamic_macro_invocations": [
                {"value": item.value, "line": item.line} for item in self.dynamic_macro_invocations
            ],
            "macro_variables": sorted(set(self.macro_variables)),
            "dynamic_dataset_references": sorted(set(self.dynamic_dataset_references)),
            "dynamic_dataset_reference_details": [
                {
                    "value": item.value,
                    "line": item.line,
                    **(
                        {"relationship_kind": item.relationship_kind.value}
                        if item.relationship_kind is not None
                        else {}
                    ),
                }
                for item in self.dynamic_dataset_reference_details
            ],
        }


def _strip_comments(text: str) -> str:
    """Blank SAS comments while preserving source positions.

    An asterisk comment begins at the start of a SAS *statement*, not merely at
    the start of a physical line.  Consequently ``data x; * comment; run;``
    contains a comment, while ``value = left * right;`` does not.  Scanning also
    keeps comment markers inside quoted strings as source text.
    """

    chars = list(text)
    length = len(text)
    index = 0
    statement_start = True

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] not in {"\r", "\n"}:
                chars[position] = " "

    while index < length:
        char = text[index]

        if char in {"'", '"'}:
            quote = char
            statement_start = False
            index += 1
            while index < length:
                if text[index] != quote:
                    index += 1
                    continue
                if index + 1 < length and text[index + 1] == quote:
                    index += 2
                    continue
                index += 1
                break
            continue

        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            blank(index, end)
            index = end
            continue

        is_statement_comment = char == "*" and statement_start
        is_macro_comment = text.startswith("%*", index)
        if is_statement_comment or is_macro_comment:
            end = text.find(";", index + (2 if is_macro_comment else 1))
            end = length if end < 0 else end + 1
            blank(index, end)
            index = end
            statement_start = True
            continue

        if char == ";":
            statement_start = True
        elif not char.isspace():
            statement_start = False
        index += 1

    return "".join(chars)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_sas_include_references(text: str) -> tuple[SasIncludeReference, ...]:
    """Find supported quoted ``%include`` statements once, preserving byte evidence.

    Comments and SAS-looking quoted text are excluded while macro variables inside
    an active quoted include remain visible to the resolver as dynamic references.
    """

    source = _strip_comments(text)
    quote_spans = quoted_string_spans(source)
    raw = text.encode("utf-8")
    source_checksum = hashlib.sha256(raw).hexdigest()
    references: list[SasIncludeReference] = []
    for match in iter_unquoted_matches(_INCLUDE_RE, source, quote_spans):
        byte_start = len(text[: match.start()].encode("utf-8"))
        byte_end = len(text[: match.end()].encode("utf-8"))
        line_start = text.rfind("\n", 0, match.start()) + 1
        references.append(
            SasIncludeReference(
                value=match.group(2),
                line=_line_number(text, match.start()),
                column=match.start() - line_start + 1,
                byte_start=byte_start,
                byte_end=byte_end,
                source_checksum=source_checksum,
                span_digest=hashlib.sha256(raw[byte_start:byte_end]).hexdigest(),
            )
        )
    return tuple(references)


def _normalize_dataset(value: str) -> str:
    return value.strip().rstrip(";, ").lower()


def _strip_dataset_options(statement: str) -> str:
    """Blank balanced parenthesized dataset options, including nested filters."""

    chars = list(statement)
    index = 0
    while index < len(statement):
        if statement[index] != "(":
            index += 1
            continue
        start = index
        depth = 1
        index += 1
        quote: str | None = None
        while index < len(statement) and depth:
            char = statement[index]
            if quote is not None:
                if char == quote:
                    if index + 1 < len(statement) and statement[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            index += 1
        for position in range(start, index):
            chars[position] = " "
    return "".join(chars)


def _dataset_tokens(statement: str) -> tuple[str, ...]:
    cleaned = _strip_dataset_options(statement)
    tokens: list[str] = []
    for raw in re.split(r"[\s,]+", cleaned.strip()):
        candidate = raw.strip().rstrip(";")
        if not candidate:
            continue
        if candidate.lower() in _RESERVED_DATA_TOKENS:
            continue
        if candidate.startswith("&"):
            continue
        if re.fullmatch(_DATASET, candidate, re.IGNORECASE):
            tokens.append(_normalize_dataset(candidate))
    return tuple(tokens)


def _dataset_token_matches(statement: str) -> tuple[tuple[str, int, int], ...]:
    """Return literal dataset tokens and their character spans in a statement."""

    cleaned = _strip_dataset_options(statement)
    matches: list[tuple[str, int, int]] = []
    token_re = re.compile(rf"(?<![A-Za-z0-9_.&])({_DATASET})(?![A-Za-z0-9_.])", re.IGNORECASE)
    for match in token_re.finditer(cleaned):
        candidate = match.group(1)
        if candidate.lower() in _RESERVED_DATA_TOKENS:
            continue
        matches.append((_normalize_dataset(candidate), match.start(1), match.end(1)))
    return tuple(matches)


def _source_reference(
    text: str,
    start: int,
    end: int,
    value: str,
    relationship_kind: RelationshipKind | None = None,
) -> SasReference:
    raw = text.encode("utf-8")
    byte_start = len(text[:start].encode("utf-8"))
    byte_end = len(text[:end].encode("utf-8"))
    line_start = text.rfind("\n", 0, start) + 1
    return SasReference(
        value=value,
        line=_line_number(text, start),
        relationship_kind=relationship_kind,
        column=start - line_start + 1,
        byte_start=byte_start,
        byte_end=byte_end,
        source_checksum=hashlib.sha256(raw).hexdigest(),
        span_digest=hashlib.sha256(raw[byte_start:byte_end]).hexdigest(),
    )


def _dynamic_dataset_refs(statement: str) -> tuple[str, ...]:
    # Macro variables in dataset options (for example ``obs=&limit`` or
    # ``where=(id=&id)``) affect how a literal dataset is accessed; they are
    # not part of the dataset's identity.  Keep dynamic findings scoped to the
    # same option-free token stream used by ``_dataset_tokens``.
    option_free = _strip_dataset_options(statement)
    values = re.findall(r"&[A-Za-z_][A-Za-z0-9_]*\.?", option_free)
    return tuple(value.lower() for value in values)


def _macro_literal_spans(
    text: str,
    inactive_spans: tuple[tuple[int, int], ...] = (),
) -> tuple[tuple[int, int], ...]:
    """Return payload spans whose macro triggers are quoted as literal text.

    ``%NRSTR`` is the compile-time macro-quoting function that masks percent
    signs and ampersands.  A small balanced-parenthesis scan is sufficient to
    prevent its payload from being reported as definitions, invocations, or
    dynamic references while preserving offsets for source evidence.
    """

    starts = re.compile(r"%nrstr\s*\(", re.IGNORECASE)
    spans: list[tuple[int, int]] = []
    for match in starts.finditer(text):
        if any(start <= match.start() < end for start, end in (*inactive_spans, *spans)):
            continue
        payload_start = match.end()
        index = payload_start
        depth = 1
        quote: str | None = None
        while index < len(text) and depth:
            char = text[index]
            if quote is not None:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            index += 1
        payload_end = index - 1 if depth == 0 else len(text)
        spans.append((payload_start, payload_end))
    return tuple(spans)


def analyze_sas_source(text: str) -> SasStaticFindings:
    """Extract high-confidence, literal SAS references from source text."""

    source = _strip_comments(text)
    quote_spans = quoted_string_spans(source)
    # SAS macro triggers resolve inside double-quoted strings, but not inside
    # single-quoted strings or %NRSTR payloads. Other SAS statement scanners
    # still exclude both kinds of ordinary quoted strings.
    single_quote_spans = tuple(span for span in quote_spans if source[span[0]] == "'")
    macro_literal_spans = _macro_literal_spans(source, single_quote_spans)
    macro_trigger_spans = tuple(sorted((*single_quote_spans, *macro_literal_spans)))
    macro_definition_spans = tuple(sorted((*quote_spans, *macro_literal_spans)))
    reads: list[SasReference] = []
    writes: list[SasReference] = []
    input_files: list[SasReference] = []
    output_files: list[SasReference] = []
    includes: list[SasIncludeReference] = []
    libraries: list[SasReference] = []
    by_variables: list[str] = []
    dynamic_refs: list[SasReference] = []

    for match in iter_unquoted_matches(_LIBNAME_RE, source, quote_spans):
        libraries.append(SasReference(match.group(1).lower(), _line_number(source, match.start())))

    for pattern, destination, relationship_kind in (
        (_DATA_RE, writes, RelationshipKind.WRITES),
        (_SET_RE, reads, RelationshipKind.READS),
        (_MERGE_RE, reads, RelationshipKind.READS),
    ):
        for match in iter_unquoted_matches(pattern, source, quote_spans):
            statement = match.group(1)
            line = _line_number(source, match.start())
            dynamic_refs.extend(
                SasReference(value, line, relationship_kind)
                for value in _dynamic_dataset_refs(statement)
            )
            for dataset, token_start, token_end in _dataset_token_matches(statement):
                destination.append(
                    _source_reference(
                        text,
                        match.start(1) + token_start,
                        match.start(1) + token_end,
                        dataset,
                        relationship_kind,
                    )
                )

    for match in iter_unquoted_matches(_BY_RE, source, quote_spans):
        for value in re.split(r"[\s,]+", match.group(1).strip()):
            if re.fullmatch(_IDENTIFIER, value, re.IGNORECASE):
                by_variables.append(value.lower())

    for pattern, destination in ((_INFILE_RE, input_files), (_FILE_RE, output_files)):
        for match in iter_unquoted_matches(pattern, source, quote_spans):
            destination.append(
                _source_reference(text, match.start(2), match.end(2), match.group(2))
            )

    includes.extend(scan_sas_include_references(text))

    for match in iter_unquoted_matches(_PROC_DATA_RE, source, quote_spans):
        reference = _source_reference(
            text,
            match.start(3),
            match.end(3),
            _normalize_dataset(match.group(3)),
            RelationshipKind.READS,
        )
        if match.group(1).lower() == "delete":
            writes.append(replace(reference, relationship_kind=RelationshipKind.WRITES))
        else:
            reads.append(reference)

    for match in iter_unquoted_matches(_PROC_OUT_RE, source, quote_spans):
        writes.append(
            _source_reference(
                text,
                match.start(2),
                match.end(2),
                _normalize_dataset(match.group(2)),
                RelationshipKind.WRITES,
            )
        )

    # Literal PROC option scanners deliberately accept only valid SAS dataset
    # names. Preserve macro-driven DATA=/OUT= values separately so they become
    # typed unresolved graph observations instead of silently disappearing.
    for statement_match in iter_unquoted_matches(_PROC_STATEMENT_RE, source, quote_spans):
        statement = statement_match.group(1)
        for option_match in _PROC_DATASET_OPTION_RE.finditer(statement):
            line = _line_number(source, statement_match.start(1) + option_match.start())
            relationship_kind = (
                RelationshipKind.WRITES
                if option_match.group(0).lstrip().lower().startswith("out")
                else RelationshipKind.READS
            )
            dynamic_refs.extend(
                SasReference(value, line, relationship_kind)
                for value in _dynamic_dataset_refs(option_match.group(1))
            )

    for match in iter_unquoted_matches(_SQL_CREATE_RE, source, quote_spans):
        writes.append(
            _source_reference(
                text,
                match.start(1),
                match.end(1),
                _normalize_dataset(match.group(1)),
                RelationshipKind.WRITES,
            )
        )
    for pattern in (_SQL_INSERT_RE, _SQL_UPDATE_RE):
        for match in iter_unquoted_matches(pattern, source, quote_spans):
            writes.append(
                _source_reference(
                    text,
                    match.start(1),
                    match.end(1),
                    _normalize_dataset(match.group(1)),
                    RelationshipKind.WRITES,
                )
            )
    for match in iter_unquoted_matches(_SQL_FROM_JOIN_RE, source, quote_spans):
        reads.append(
            _source_reference(
                text,
                match.start(1),
                match.end(1),
                _normalize_dataset(match.group(1)),
                RelationshipKind.READS,
            )
        )

    dynamic_sql_re = re.compile(
        r"\b(?P<operation>create\s+table|insert\s+into|update|from|join)\s+"
        r"(?P<reference>&[A-Za-z_][A-Za-z0-9_]*\.?)",
        re.IGNORECASE,
    )
    for match in iter_unquoted_matches(dynamic_sql_re, source, quote_spans):
        relationship_kind = (
            RelationshipKind.READS
            if match.group("operation").lower() in {"from", "join"}
            else RelationshipKind.WRITES
        )
        dynamic_refs.append(
            SasReference(
                match.group("reference").lower(),
                _line_number(source, match.start()),
                relationship_kind,
            )
        )

    macro_definition_references = tuple(
        SasReference(match.group(1).lower(), _line_number(source, match.start()))
        for match in iter_unquoted_matches(_MACRO_DEF_RE, source, macro_definition_spans)
    )
    # Keep every syntactic invocation for estate-wide definition reconciliation.
    # A user-defined macro may intentionally share a name with a SAS intrinsic.
    macro_invocation_references = tuple(
        SasReference(match.group(1).lower(), _line_number(source, match.start()))
        for match in iter_unquoted_matches(_MACRO_CALL_RE, source, macro_trigger_spans)
        if match.group(1).lower() not in _SAS_MACRO_STATEMENTS
    )
    dynamic_macro_invocations = tuple(
        SasReference(match.group(1).lower(), _line_number(source, match.start()))
        for match in iter_unquoted_matches(_DYNAMIC_MACRO_CALL_RE, source, macro_trigger_spans)
    )
    macro_definitions = tuple(sorted({item.value for item in macro_definition_references}))
    macro_invocations = tuple(
        sorted(
            {
                item.value
                for item in macro_invocation_references
                if not is_sas_system_macro_operation(item.value)
            }
        )
    )
    macro_variables = tuple(
        sorted(
            {
                match.group(1).lower()
                for match in iter_unquoted_matches(_MACRO_VAR_RE, source, macro_trigger_spans)
            }
        )
    )

    return SasStaticFindings(
        reads=tuple(reads),
        writes=tuple(writes),
        input_files=tuple(input_files),
        output_files=tuple(output_files),
        includes=tuple(includes),
        libraries=tuple(libraries),
        by_variables=tuple(sorted(set(by_variables))),
        macro_definitions=macro_definitions,
        macro_invocations=macro_invocations,
        macro_definition_references=macro_definition_references,
        macro_invocation_references=macro_invocation_references,
        dynamic_macro_invocations=dynamic_macro_invocations,
        macro_variables=macro_variables,
        dynamic_dataset_references=tuple(sorted({item.value for item in dynamic_refs})),
        dynamic_dataset_reference_details=tuple(dynamic_refs),
    )


def add_findings_to_workload(
    builder: WorkloadBuilder,
    artifact: Artifact,
    findings: SasStaticFindings,
    *,
    source_text: str | None = None,
) -> None:
    """Normalize SAS findings into canonical datasets and relationships."""

    def evidence(
        reference: SasReference | SasIncludeReference,
        observed: str,
        *,
        access_metadata: dict[str, object] | None = None,
    ) -> DiscoveryEvidence:
        locator = artifact.logical_path or artifact.name
        return builder.evidence(
            method=EvidenceMethod.STATIC_ANALYSIS,
            source=locator,
            confidence=Confidence.HIGH,
            locator=f"{locator}:{reference.line}",
            observed_value=observed,
            metadata={
                "line": reference.line,
                **(
                    {
                        "column": reference.column,
                        "byte_start": reference.byte_start,
                        "byte_end": reference.byte_end,
                        "source_checksum": reference.source_checksum,
                        "span_digest": reference.span_digest,
                    }
                    if isinstance(reference, SasIncludeReference)
                    or (isinstance(reference, SasReference) and reference.byte_start is not None)
                    else {}
                ),
                **(access_metadata or {}),
            },
        )

    bindings = discover_library_bindings(source_text or "")

    for kind, references in (
        (RelationshipKind.READS, findings.reads),
        (RelationshipKind.WRITES, findings.writes),
    ):
        for reference in references:
            normalized_reference = reference.value.lower()
            is_work_scoped = "." not in normalized_reference or normalized_reference.startswith(
                "work."
            )
            characterization = characterize_dataset(
                reference.value,
                bindings,
                scope_discriminator=(
                    builder.workload_id if is_work_scoped else artifact.artifact_id
                ),
            )
            assert artifact.checksum is not None
            assert reference.byte_start is not None
            assert reference.byte_end is not None
            assert reference.source_checksum is not None
            assert reference.span_digest is not None
            assert reference.column is not None
            access_id = dataset_access_id(
                workload_id=builder.workload_id,
                artifact_id=artifact.artifact_id,
                artifact_checksum=artifact.checksum,
                role=kind.value,
                normalized_reference=characterization.normalized_name,
                line=reference.line,
                column=reference.column,
                byte_start=reference.byte_start,
                byte_end=reference.byte_end,
                source_checksum=reference.source_checksum,
                span_digest=reference.span_digest,
                dataset_kind=characterization.kind.value,
                dataset_system=characterization.system,
                dataset_location=characterization.location,
                identity_resolution=characterization.identity_resolution.value,
                scope_discriminator=characterization.scope_discriminator,
            )
            ev = evidence(
                reference,
                reference.value,
                access_metadata={
                    "observation": "sas_dataset_access",
                    "access_id": access_id,
                    "artifact_id": artifact.artifact_id,
                    "artifact_checksum": artifact.checksum,
                    "role": kind.value,
                    "normalized_reference": characterization.normalized_name,
                    "identity_resolution": characterization.identity_resolution.value,
                    "lineage_policy_digest": LINEAGE_POLICY_DIGEST,
                },
            )
            dataset = builder.add_dataset(
                kind=characterization.kind,
                name=characterization.normalized_name,
                location=characterization.location,
                system=characterization.system,
                evidence=(ev,),
                metadata={
                    **characterization.metadata,
                    "canonical_dataset_name": characterization.normalized_name,
                },
            )
            builder.add_relationship(
                source_id=artifact.artifact_id,
                kind=kind,
                target_id=dataset.dataset_id,
                evidence=(ev,),
            )

    for kind, references in (
        (RelationshipKind.READS, findings.input_files),
        (RelationshipKind.WRITES, findings.output_files),
    ):
        for reference in references:
            normalized_path = reference.value.replace("\\", "/")
            is_absolute = PurePosixPath(normalized_path).is_absolute() or bool(
                re.match(r"^[A-Za-z]:/", normalized_path)
            )
            resolution = "resolved" if is_absolute else "provisional"
            source_parent = PurePosixPath(artifact.logical_path or artifact.name).parent.as_posix()
            scope_discriminator = None if is_absolute else f"source-directory:{source_parent}"
            assert artifact.checksum is not None
            assert reference.byte_start is not None
            assert reference.byte_end is not None
            assert reference.source_checksum is not None
            assert reference.span_digest is not None
            assert reference.column is not None
            access_id = dataset_access_id(
                workload_id=builder.workload_id,
                artifact_id=artifact.artifact_id,
                artifact_checksum=artifact.checksum,
                role=kind.value,
                normalized_reference=normalized_path,
                line=reference.line,
                column=reference.column,
                byte_start=reference.byte_start,
                byte_end=reference.byte_end,
                source_checksum=reference.source_checksum,
                span_digest=reference.span_digest,
                dataset_kind=DatasetKind.FILE.value,
                dataset_system=None,
                dataset_location=reference.value,
                identity_resolution=resolution,
                scope_discriminator=scope_discriminator,
            )
            ev = evidence(
                reference,
                reference.value,
                access_metadata={
                    "observation": "sas_dataset_access",
                    "access_id": access_id,
                    "artifact_id": artifact.artifact_id,
                    "artifact_checksum": artifact.checksum,
                    "role": kind.value,
                    "normalized_reference": normalized_path,
                    "identity_resolution": resolution,
                    "lineage_policy_digest": LINEAGE_POLICY_DIGEST,
                },
            )
            dataset = builder.add_dataset(
                kind=DatasetKind.FILE,
                name=PurePosixPath(normalized_path).name,
                location=reference.value,
                evidence=(ev,),
                metadata={
                    "canonical_dataset_name": normalized_path,
                    "resolution": resolution,
                    **(
                        {"scope_discriminator": scope_discriminator}
                        if scope_discriminator is not None
                        else {}
                    ),
                },
            )
            builder.add_relationship(
                source_id=artifact.artifact_id,
                kind=kind,
                target_id=dataset.dataset_id,
                evidence=(ev,),
            )

    for include_reference in findings.includes:
        ev = evidence(include_reference, include_reference.value)
        include = builder.add_artifact(
            kind=ArtifactKind.SAS_INCLUDE,
            name=PurePosixPath(include_reference.value.replace("\\", "/")).name,
            logical_path=include_reference.value,
            evidence=(ev,),
            metadata={"placeholder": True},
        )
        builder.add_relationship(
            source_id=artifact.artifact_id,
            kind=RelationshipKind.INCLUDES,
            target_id=include.artifact_id,
            evidence=(ev,),
        )
