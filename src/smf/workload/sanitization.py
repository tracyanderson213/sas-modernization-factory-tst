"""Canonical sanitization for credential-bearing discovery evidence.

Discovery adapters intentionally retain rich, provider-specific metadata.  This
module is the single boundary that makes those arbitrary nested values safe for
canonical persistence and all later derivations.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from enum import Enum
from typing import Any, cast

REDACTED = "<redacted>"

_SECRET_NAMES = {
    "password",
    "pass",
    "passwd",
    "pwd",
    "passphrase",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "client_secret",
    "shared_key",
    "shared_access_key",
    "shared_access_signature",
    "signature",
    "private_key",
    "credential",
    "credentials",
    "authorization",
    "authentication",
    "auth",
    "auth_config",
    "secret",
    "secret_value",
    "secret_key",
    "secret_file",
    "secret_access_key",
    "account_key",
    "access_key",
    "storage_key",
    "master_key",
    "signing_key",
    "subscription_key",
    "sas_token",
    "jwt",
    "jwt_token",
    "id_token",
    "pat",
    "personal_access_token",
    "secret_key_base",
    "sig",
}
_SECRET_SUFFIXES = tuple(f"_{name}" for name in _SECRET_NAMES)
_COMPACT_SECRET_NAMES = {name.replace("_", "") for name in _SECRET_NAMES}
_COMPACT_SECRET_SUFFIXES = tuple(
    name
    for name in _COMPACT_SECRET_NAMES
    if name not in {"auth", "pass", "pat", "pwd", "sig", "token", "secret"}
)
_SECRET_VALUE_SUFFIXES = ("_value",)
_KEY_PATTERN = (
    r"(?:"
    r"(?:[A-Za-z][A-Za-z0-9]*[_-])*"
    r"(?:password|pass|passwd|pwd|passphrase|token|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|client[_-]?secret|shared[_-]?key|"
    r"shared[_-]?access[_-]?(?:key|signature)|sharedaccess(?:key|signature)|"
    r"private[_-]?key|secret(?:[_-]?access)?[_-]?key|account[_-]?key|"
    r"access[_-]?key|storage[_-]?key|master[_-]?key|signing[_-]?key|"
    r"subscription[_-]?key|sas[_-]?token|jwt(?:[_-]?token)?|id[_-]?token|credentials?|"
    r"secret(?:[_-]?value)?|"
    r"personal[_-]?access[_-]?token|secret[_-]?key[_-]?base|pat|signature|sig)"
    # Opaque JSON/YAML/command strings also carry camelCase and compact names.
    # Require the whole name to end in a credential term so safe fields such as
    # tokenCount and accessTokenCount do not match.
    r"|(?:[A-Za-z][A-Za-z0-9]*)"
    r"(?:password|passwd|passphrase|token|apikey|accessToken|refreshToken|authToken|"
    r"clientSecret|sharedKey|sharedAccessKey|sharedAccessSignature|privateKey|"
    r"secretAccessKey|accountKey|accessKey|storageKey|masterKey|signingKey|"
    r"subscriptionKey|sasToken|jwtToken|idToken|credentials?|secretValue|secretKey|"
    r"personalAccessToken|secretKeyBase)"
    r")"
)

_SINGLE_QUOTED_PATTERN = r"'(?:\\.|[^'\\])*'"
_DOUBLE_QUOTED_PATTERN = r'"(?:\\.|[^"\\])*"'
_SHELL_WORD_PATTERN = (
    rf"(?:\\(?:\r?\n|[^\r\n])|{_SINGLE_QUOTED_PATTERN}|"
    rf"{_DOUBLE_QUOTED_PATTERN}|[^\s;&\\'\"])+"
)
_STRING_VALUE_PATTERN = rf"\{{[^}}]*\}}|{_SHELL_WORD_PATTERN}"
_CONNECTION_VALUE_PATTERN = r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|\{[^}]*\}|(?!['\"{])[^;]*"

# Shell launchers commonly quote an entire environment assignment so its value
# can contain whitespace (for example, env "DB_PASSWORD=two words" command).
# Handle that shape before the generic assignment rule, which intentionally
# treats whitespace as the boundary of an unquoted shell word.
_QUOTED_ASSIGNMENT_RE = re.compile(
    rf"(?P<prefix>(?<![\w-])(?P<quote>['\"])(?:--?)?{_KEY_PATTERN}\s*"
    rf"(?:=|:)\s*)(?P<value>(?:\\.|(?!(?P=quote))[\s\S])*)(?=(?P=quote))",
    re.IGNORECASE,
)

# A semicolon is an explicit value boundary in database and cloud connection
# strings.  Unlike shell assignments, an unquoted connection-string value may
# contain whitespace, so handle this form before the generic assignment rule.
_CONNECTION_ASSIGNMENT_RE = re.compile(
    rf"(?P<prefix>(?<![\w-])['\"]?(?:--?)?{_KEY_PATTERN}['\"]?\s*"
    rf"(?:=|:)\s*)(?P<value>{_CONNECTION_VALUE_PATTERN})(?=;)",
    re.IGNORECASE,
)

# The final value in a semicolon-delimited connection string need not itself
# have a trailing semicolon.  Once a preceding semicolon establishes this as a
# connection string, consume whitespace through the end instead of applying
# shell-assignment boundaries and leaking the remainder of the credential.
_TRAILING_CONNECTION_ASSIGNMENT_RE = re.compile(
    rf"(?P<prefix>(?<=;)\s*['\"]?(?:--?)?{_KEY_PATTERN}['\"]?\s*"
    rf"(?:=|:)\s*)(?P<value>{_CONNECTION_VALUE_PATTERN})$",
    re.IGNORECASE,
)

# Quoted values are kept syntactically quoted; unquoted assignment values stop
# at shell whitespace or a connection-string semicolon.
_ASSIGNMENT_RE = re.compile(
    rf"(?P<prefix>(?<![\w-])['\"]?(?:--?)?{_KEY_PATTERN}['\"]?\s*"
    rf"(?:=|:)\s*)(?P<value>{_STRING_VALUE_PATTERN})",
    re.IGNORECASE,
)
_OPTION_RE = re.compile(
    rf"(?P<prefix>(?<![\w-])--?{_KEY_PATTERN}\s+)"
    rf"(?P<value>{_STRING_VALUE_PATTERN})",
    re.IGNORECASE,
)
# SAS system options use ``-set NAME VALUE`` rather than conventional
# ``--name VALUE`` syntax. Scheduler definitions frequently carry database
# credentials this way, so sanitize the value before commands are persisted.
_SAS_SET_RE = re.compile(
    rf"(?P<prefix>(?<![\w-])-set\s+{_KEY_PATTERN}\s+)"
    rf"(?P<value>{_STRING_VALUE_PATTERN})",
    re.IGNORECASE,
)
# Header arguments in scheduler and runtime commands are normally quoted as a
# unit.  Redact everything after the authentication scheme through that quote,
# since schemes such as Digest carry multiple whitespace-delimited parameters.
# This must run before the single-shell-word fallback below.
_QUOTED_AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>(?P<quote>['\"])(?:authorization|authentication)\s*:\s*"
    r"(?:[A-Za-z][A-Za-z0-9+._~-]*\s+)?)"
    r"(?P<value>(?:\\.|(?!(?P=quote))[\s\S])+?)(?=(?P=quote))",
    re.IGNORECASE,
)
_AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:authorization|authentication)['\"]?\s*:\s*['\"]?"
    # Authentication schemes are extensible.  Preserve any scheme token for
    # diagnostic value, but never enumerate a small allow-list (Bearer/Basic)
    # that lets Token, ApiKey, Digest, or a vendor scheme expose its payload.
    rf"(?:[A-Za-z][A-Za-z0-9+._~-]*\s+)?)(?P<value>{_SHELL_WORD_PATTERN})",
    re.IGNORECASE,
)
_AUTH_OPTION_RE = re.compile(
    r"(?P<prefix>(?<![\w-])(?:--?)?(?:authorization|authentication|auth)"
    r"\s*(?:=|\s)\s*)"
    rf"(?P<value>(?:bearer|basic)\s+{_SHELL_WORD_PATTERN}|{_STRING_VALUE_PATTERN})",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(rf"(?P<prefix>\bbearer\s+)(?P<value>{_SHELL_WORD_PATTERN})", re.IGNORECASE)
_URI_USERINFO_RE = re.compile(
    r"(?P<prefix>\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/@:]*:)(?P<password>[^\s/@]+)(?=@)",
)
_ORACLE_THIN_USERINFO_RE = re.compile(
    r"(?P<prefix>\bjdbc:oracle:thin:[^\s/@:]+/)(?P<password>[^\s@]+)(?=@)",
    re.IGNORECASE,
)
_SCHEMELESS_USERINFO_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+:)"
    r"(?P<password>[^\s/@]+)"
    r"(?=@(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::\d+)?(?:[/\s'\"]|$))",
)
_USERINFO_OPTION_RE = re.compile(
    r"(?P<prefix>(?<!\S)(?:"
    r"-u(?:\s*|=)|--(?:proxy-)?user(?:\s+|=)"
    r")['\"]?[^:\s'\"]+:)"
    r"(?P<password>[^\s'\"]+)",
    re.IGNORECASE,
)


def is_secret_field_name(name: object) -> bool:
    """Return whether a structured field name conventionally holds a secret."""

    if not isinstance(name, str):
        return False
    # Split both ordinary camelCase and acronym transitions before lowering.
    # This recognizes githubToken and serviceAPIToken while keeping tokenCount
    # as the safe, delimiter-aware name token_count.
    delimited = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name.strip())
    delimited = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", delimited)
    normalized = re.sub(r"[^a-z0-9]+", "_", delimited.lower()).strip("_")
    compact = normalized.replace("_", "")
    value_stem = next(
        (
            normalized[: -len(suffix)]
            for suffix in _SECRET_VALUE_SUFFIXES
            if normalized.endswith(suffix)
        ),
        None,
    )
    return (
        normalized in _SECRET_NAMES
        or normalized.endswith(_SECRET_SUFFIXES)
        or compact in _COMPACT_SECRET_NAMES
        or any(compact.endswith(suffix) for suffix in _COMPACT_SECRET_SUFFIXES)
        or (
            value_stem is not None
            and (
                value_stem in _SECRET_NAMES
                or value_stem.endswith(_SECRET_SUFFIXES)
                or value_stem.replace("_", "") in _COMPACT_SECRET_NAMES
            )
        )
    )


def _replacement(match: re.Match[str]) -> str:
    value = match.group("value")
    if value.startswith(("'", '"')) and value[-1:] == value[0]:
        safe_value = f"{value[0]}{REDACTED}{value[0]}"
    else:
        safe_value = REDACTED
    return f"{match.group('prefix')}{safe_value}"


def _find_balanced_end(value: str, start: int) -> int | None:
    """Return the exclusive end of a balanced JSON-like object/array."""

    opener = value[start]
    closer = "}" if opener == "{" else "]"
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(value)):
        char = value[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _quoted_value_end(value: str, start: int) -> int | None:
    quote = value[start]
    escaped = False
    for index in range(start + 1, len(value)):
        char = value[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index + 1
    return None


def _is_shell_escaped(value: str, index: int) -> bool:
    """Return whether the character at ``index`` is escaped by an odd backslash run."""

    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and value[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _yaml_block_scalar_end(value: str, start: int) -> int | None:
    """Return the exclusive end of a YAML block scalar beginning at ``start``.

    This intentionally supports only the block-scalar surface needed for opaque
    discovery metadata. It does not attempt to parse YAML generally.
    """

    marker = re.match(
        r"(?P<style>[|>])(?P<header>(?:[+-]?[1-9]?|[1-9]?[+-]?))"
        r"(?=\s*(?:\r?\n|$))",
        value[start:],
    )
    if marker is None:
        return None

    marker_end = start + marker.end()
    newline = re.search(r"\r?\n", value[marker_end:])
    if newline is None:
        return len(value)
    content_start = marker_end + newline.end()

    # An explicit indentation indicator is relative to the indentation of the
    # scalar's key line. Without one, YAML derives indentation from the first
    # non-blank content line.
    header = marker.group("header")
    indent_match = re.search(r"[1-9]", header)
    explicit_indent = int(indent_match.group(0)) if indent_match is not None else None

    line_start = value.rfind("\n", 0, start) + 1
    key_line_prefix = value[line_start:start]
    parent_indent = len(key_line_prefix) - len(key_line_prefix.lstrip(" "))

    block_indent: int | None = None
    if explicit_indent is not None:
        block_indent = parent_indent + explicit_indent
    else:
        cursor = content_start
        while cursor < len(value):
            line_end = value.find("\n", cursor)
            if line_end == -1:
                line_end = len(value)
            line = value[cursor:line_end].rstrip("\r")
            if line.strip():
                block_indent = len(line) - len(line.lstrip(" "))
                break
            cursor = line_end + 1

    if block_indent is None:
        return len(value)

    cursor = content_start
    while cursor < len(value):
        line_end = value.find("\n", cursor)
        has_newline = line_end != -1
        if not has_newline:
            line_end = len(value)
        line = value[cursor:line_end].rstrip("\r")

        if line.strip():
            indent = len(line) - len(line.lstrip(" "))
            if indent < block_indent:
                if cursor > 0 and value[cursor - 1] == "\n":
                    return cursor - (2 if cursor > 1 and value[cursor - 2] == "\r" else 1)
                return cursor

        cursor = line_end + (1 if has_newline else 0)

    return len(value)


def _first_unescaped_delimiter(value: str, start: int, delimiters: set[str]) -> int | None:
    """Find the next shell delimiter that is not escaped."""

    for index in range(start, len(value)):
        if value[index] in delimiters and not _is_shell_escaped(value, index):
            return index
    return None


def _first_unescaped_shell_boundary(
    value: str,
    start: int,
    end: int,
    *,
    allow_launcher: bool = True,
) -> int | None:
    """Find a defensible boundary after an unquoted shell credential value."""

    index = start
    while index < end:
        if value[index].isspace() and not _is_shell_escaped(value, index):
            tail = value[index:end]
            if re.match(r"\s+--?[A-Za-z][A-Za-z0-9_-]*(?:\s|=|$)", tail):
                return index
            if allow_launcher and re.match(r"\s+[A-Za-z0-9_./-]+\s+--?[A-Za-z]", tail):
                return index
        index += 1
    return None


def _secret_assignment_end(value: str, start: int, separator: str) -> int:
    """Find a conservative end boundary for a secret-bearing assignment."""

    if start >= len(value):
        return start
    if value[start] in {'"', "'"}:
        return _quoted_value_end(value, start) or len(value)
    if value[start] in "{[":
        return _find_balanced_end(value, start) or len(value)

    if separator == ":":
        block_end = _yaml_block_scalar_end(value, start)
        if block_end is not None:
            return block_end
        newline = _first_unescaped_delimiter(value, start, {"\r", "\n"})
        return newline if newline is not None else len(value)

    delimiter = _first_unescaped_delimiter(value, start, {"\r", "\n", ";", "&"})
    segment_end = delimiter if delimiter is not None else len(value)
    shell_boundary = _first_unescaped_shell_boundary(value, start, segment_end)
    return shell_boundary if shell_boundary is not None else segment_end


def _redact_secret_assignments(value: str) -> str:
    """Redact assignments based on the field-name classifier, not a key regex list."""

    pattern = re.compile(
        r"(?<![\w-])(?P<key>[A-Za-z][A-Za-z0-9_.-]*)\s*(?P<sep>=|:)\s*",
        re.IGNORECASE,
    )
    output: list[str] = []
    cursor = 0
    while True:
        match = pattern.search(value, cursor)
        if match is None:
            output.append(value[cursor:])
            break
        key = match.group("key")
        normalized_key = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        if normalized_key in {"authorization", "authentication", "proxy_authorization"}:
            output.append(value[cursor : match.end()])
            cursor = match.end()
            continue
        if not is_secret_field_name(key):
            output.append(value[cursor : match.end()])
            cursor = match.end()
            continue
        output.append(value[cursor : match.end()])
        end = _secret_assignment_end(value, match.end(), match.group("sep"))
        output.append(REDACTED)
        cursor = end
    return "".join(output)


def _redact_secret_options(value: str) -> str:
    """Redact complete shell option values, including unquoted multi-token values."""

    pattern = re.compile(r"(?<![\w-])(?P<flag>--?)(?P<key>[A-Za-z][A-Za-z0-9_-]*)\s+")
    output: list[str] = []
    cursor = 0
    while True:
        match = pattern.search(value, cursor)
        if match is None:
            output.append(value[cursor:])
            break
        normalized_key = re.sub(r"[^a-z0-9]+", "_", match.group("key").lower()).strip("_")
        if normalized_key in {"authorization", "authentication", "auth"}:
            output.append(value[cursor : match.end()])
            cursor = match.end()
            continue
        if not is_secret_field_name(match.group("key")):
            output.append(value[cursor : match.end()])
            cursor = match.end()
            continue
        output.append(value[cursor : match.end()])
        end = _secret_assignment_end(value, match.end(), "=")
        output.append(REDACTED)
        cursor = end
    return "".join(output)


def _redact_auth_options(value: str) -> str:
    """Redact complete authentication option payloads while preserving a scheme token."""

    pattern = re.compile(
        r"(?<![\w-])(?P<prefix>(?:--?)?(?:proxy[-_])?(?:authorization|authentication|auth)"
        r"\s*(?:=|\s)\s*)",
        re.IGNORECASE,
    )
    output: list[str] = []
    cursor = 0
    while True:
        match = pattern.search(value, cursor)
        if match is None:
            output.append(value[cursor:])
            break

        output.append(value[cursor : match.end()])
        start = match.end()

        # A quoted authentication argument is one atomic shell value. Option-like
        # text inside the quote belongs to the credential payload and must never
        # be mistaken for the next independent shell option.
        if start < len(value) and value[start] in {'"', "'"}:
            quote = value[start]
            closing = _quoted_value_end(value, start)
            end = closing if closing is not None else len(value)
            payload_end = end - 1 if closing is not None else end
            payload = value[start + 1 : payload_end].strip()
            scheme = re.match(r"(?P<scheme>[A-Za-z][A-Za-z0-9+._~-]*)(?P<ws>\s+)", payload)
            output.append(quote)
            if scheme is not None:
                output.append(scheme.group("scheme") + scheme.group("ws") + REDACTED)
            else:
                output.append(REDACTED)
            if closing is not None:
                output.append(quote)
            cursor = end
            continue

        delimiter = _first_unescaped_delimiter(value, start, {"\r", "\n", ";", "&"})
        end = delimiter if delimiter is not None else len(value)

        # Authentication payloads may themselves contain command-looking
        # tokens (Digest parameters, Token/ApiKey schemes, vendor forms).
        # Preserve only a subsequent unescaped shell option.
        next_option = _first_unescaped_shell_boundary(
            value,
            start,
            end,
            allow_launcher=False,
        )
        if next_option is not None:
            end = next_option
        raw_payload = value[start:end]
        payload = raw_payload.strip()

        if not payload:
            cursor = end
            continue

        # HTTP-style authentication values are "scheme credentials".  If
        # multiple tokens are present, preserve only the leading scheme token
        # and redact everything after it.  A single token is treated entirely
        # as credential material and fails closed.
        scheme = re.match(r"(?P<scheme>[A-Za-z][A-Za-z0-9+._~-]*)(?P<ws>\s+)", payload)
        if scheme is not None:
            output.append(scheme.group("scheme") + scheme.group("ws") + REDACTED)
        else:
            output.append(REDACTED)
        cursor = end

    return "".join(output)


def _redact_auth_headers(value: str) -> str:
    """Redact complete Authorization-family payloads while preserving schemes."""

    pattern = re.compile(
        r"\b(?:proxy-)?(?:authorization|authentication)\s*:\s*",
        re.IGNORECASE,
    )
    output: list[str] = []
    cursor = 0
    while True:
        match = pattern.search(value, cursor)
        if match is None:
            output.append(value[cursor:])
            break
        output.append(value[cursor : match.end()])
        pos = match.end()
        outer_quote = (
            value[match.start() - 1]
            if match.start() > 0 and value[match.start() - 1] in {'"', "'"}
            else None
        )
        quote: str | None = None
        if pos < len(value) and value[pos] in {'"', "'"}:
            quote = value[pos]
            output.append(quote)
            pos += 1

        scheme = re.match(r"([A-Za-z][A-Za-z0-9+._~-]*)(\s+)", value[pos:])
        if scheme:
            output.append(scheme.group(1) + scheme.group(2))
            pos += scheme.end()

        if quote is not None:
            closing = _quoted_value_end(value, pos - 1)
            end = closing - 1 if closing is not None else len(value)
            output.append(REDACTED)
            if closing is not None:
                output.append(quote)
                cursor = closing
            else:
                cursor = end
            continue

        if outer_quote is not None:
            closing = value.find(outer_quote, pos)
            if closing != -1:
                output.append(REDACTED)
                cursor = closing
                continue

        end = len(value)
        for delimiter in ("\r", "\n"):
            found = value.find(delimiter, pos)
            if found != -1:
                end = min(end, found)
        output.append(REDACTED)
        cursor = end
    return "".join(output)


def _redact_uri_userinfo(value: str) -> str:
    """Redact URI passwords using the last @ in authority so @ inside passwords is safe."""

    pattern = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/]+")

    def replace_uri(match: re.Match[str]) -> str:
        authority = match.group(0)
        scheme_end = authority.find("://") + 3
        userinfo = authority[scheme_end:]
        at = userinfo.rfind("@")
        if at == -1:
            return authority
        colon = userinfo.find(":")
        if colon == -1 or colon > at:
            return authority
        safe = userinfo[: colon + 1] + REDACTED + userinfo[at:]
        return authority[:scheme_end] + safe

    return pattern.sub(replace_uri, value)


def _redact_sqlplus_userinfo(value: str) -> str:
    pattern = re.compile(
        r"(?P<prefix>\bsqlplus\s+[^\s/@]+/)(?P<password>[^\s@]+)(?=@)",
        re.IGNORECASE,
    )
    return pattern.sub(lambda match: f"{match.group('prefix')}{REDACTED}", value)


def _sanitize_parseable_json(value: str) -> str | None:
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        return None
    sanitized = sanitize_discovery_value(parsed)
    return json.dumps(sanitized, sort_keys=False)


def _sanitize_string(value: str) -> str:
    if value == REDACTED:
        return value
    parsed_json = _sanitize_parseable_json(value)
    if parsed_json is not None:
        return parsed_json
    sanitized = _redact_uri_userinfo(value)
    sanitized = _redact_sqlplus_userinfo(sanitized)
    sanitized = _redact_auth_headers(sanitized)
    sanitized = _redact_auth_options(sanitized)
    sanitized = _redact_secret_assignments(sanitized)
    sanitized = _redact_secret_options(sanitized)
    sanitized = _ORACLE_THIN_USERINFO_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}", sanitized
    )
    sanitized = _URI_USERINFO_RE.sub(lambda match: f"{match.group('prefix')}{REDACTED}", sanitized)
    sanitized = _SCHEMELESS_USERINFO_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}", sanitized
    )
    sanitized = _QUOTED_AUTH_HEADER_RE.sub(_replacement, sanitized)
    sanitized = _AUTH_HEADER_RE.sub(_replacement, sanitized)
    sanitized = _BEARER_RE.sub(_replacement, sanitized)
    sanitized = _USERINFO_OPTION_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}", sanitized
    )
    sanitized = _QUOTED_ASSIGNMENT_RE.sub(_replacement, sanitized)
    sanitized = _CONNECTION_ASSIGNMENT_RE.sub(_replacement, sanitized)
    sanitized = _TRAILING_CONNECTION_ASSIGNMENT_RE.sub(_replacement, sanitized)
    sanitized = _ASSIGNMENT_RE.sub(_replacement, sanitized)
    sanitized = _SAS_SET_RE.sub(_replacement, sanitized)
    return _OPTION_RE.sub(_replacement, sanitized)


def sanitize_discovery_value(value: Any, *, field_name: str | None = None) -> Any:
    """Return a recursively sanitized copy of a JSON-compatible discovery value.

    Unsupported values fail closed: silently carrying an opaque object through
    this boundary could allow a later serializer to expose data we never inspected.
    """

    if field_name is not None and isinstance(value, str):
        normalized_field = re.sub(r"[^a-z0-9]+", "_", field_name.lower()).strip("_")
        if normalized_field in {"authorization", "authentication", "proxy_authorization"}:
            synthetic = _redact_auth_headers(f"{field_name}: {value}")
            return synthetic.split(":", 1)[1].lstrip()
    if field_name is not None and is_secret_field_name(field_name):
        return REDACTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Enum):
        # Preserve ordinary canonical enum members when their string value is safe,
        # but do not let a secret-bearing StrEnum bypass string sanitization.
        if isinstance(value, str):
            sanitized_value = _sanitize_string(str(value))
            return value if sanitized_value == str(value) else sanitized_value
        return value
    if isinstance(value, str):
        return _sanitize_string(value)
    if is_dataclass(value) and not isinstance(value, type):
        updates = {
            item.name: sanitize_discovery_value(getattr(value, item.name), field_name=item.name)
            for item in fields(value)
        }
        return replace(value, **updates)
    if isinstance(value, Mapping):
        keys_by_case = {key.casefold(): key for key in value if isinstance(key, str)}
        label_key = next(
            (keys_by_case[name] for name in ("name", "key", "variable") if name in keys_by_case),
            None,
        )
        value_key = next(
            (keys_by_case[name] for name in ("value", "val") if name in keys_by_case),
            None,
        )
        named_secret = (
            label_key is not None
            and value_key is not None
            and is_secret_field_name(value[label_key])
        )
        sanitized: dict[Any, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str | int | float | bool):
                raise TypeError(f"unsupported discovery metadata key type: {type(key).__name__}")
            safe_key = _sanitize_string(key) if isinstance(key, str) else key
            if safe_key in sanitized and safe_key != key:
                raise TypeError("sanitization produced duplicate discovery metadata keys")
            if named_secret and key == value_key:
                sanitized[safe_key] = REDACTED
            else:
                sanitized[safe_key] = sanitize_discovery_value(
                    item, field_name=key if isinstance(key, str) else None
                )
        if type(value) is dict:
            return sanitized
        try:
            mapping_type = cast(Any, type(value))
            return mapping_type(sanitized)
        except TypeError as exc:
            raise TypeError(
                f"unsupported discovery metadata mapping type: {type(value).__name__}"
            ) from exc
    if isinstance(value, list):
        if len(value) == 2 and is_secret_field_name(value[0]):
            return [sanitize_discovery_value(value[0]), REDACTED]
        return [sanitize_discovery_value(item) for item in value]
    if isinstance(value, tuple):
        if len(value) == 2 and is_secret_field_name(value[0]):
            return (sanitize_discovery_value(value[0]), REDACTED)
        return tuple(sanitize_discovery_value(item) for item in value)
    raise TypeError(f"unsupported discovery metadata value type: {type(value).__name__}")


def sanitize_workload_fields(workload: Any) -> None:
    """Enforce sanitization on every field of a frozen canonical Workload."""

    for item in fields(workload):
        object.__setattr__(
            workload,
            item.name,
            sanitize_discovery_value(getattr(workload, item.name), field_name=item.name),
        )
