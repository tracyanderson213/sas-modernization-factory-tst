"""Small lexical helpers for deterministic SAS source scanning.

The discovery engine is intentionally not a full SAS parser, but regex matches
must still respect quoted-string boundaries. These helpers identify SAS quoted
string spans so higher-level scanners can ignore keywords that merely appear in
string values while still allowing statements such as INFILE, FILE, %INCLUDE,
and LIBNAME to capture their quoted arguments.
"""

from __future__ import annotations

import re
from collections.abc import Iterator


def quoted_string_spans(text: str) -> tuple[tuple[int, int], ...]:
    """Return half-open spans for single- and double-quoted SAS strings.

    SAS represents a quote inside a same-quoted string by doubling it. The
    scanner preserves that behavior and treats an unterminated quote as running
    through end-of-source so downstream discovery fails conservatively.
    """

    spans: list[tuple[int, int]] = []
    index = 0
    length = len(text)
    while index < length:
        quote = text[index]
        if quote not in {"'", '"'}:
            index += 1
            continue

        start = index
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
        spans.append((start, index))
    return tuple(spans)


def offset_is_quoted(offset: int, spans: tuple[tuple[int, int], ...]) -> bool:
    """Return whether an offset falls inside a quoted SAS string span."""

    return any(start <= offset < end for start, end in spans)


def iter_unquoted_matches(
    pattern: re.Pattern[str],
    text: str,
    spans: tuple[tuple[int, int], ...] | None = None,
) -> Iterator[re.Match[str]]:
    """Yield regex matches whose starting token is outside quoted strings."""

    quote_spans = spans if spans is not None else quoted_string_spans(text)
    for match in pattern.finditer(text):
        if not offset_is_quoted(match.start(), quote_spans):
            yield match
