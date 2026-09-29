"""Canonical semantic-result loading, registry discovery, and comparison."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, cast

import jsonschema

from smf.corpus.loader import load_corpus_manifest
from smf.corpus.models import CorpusManifest, CorpusSemanticColumn, CorpusSemanticOracle

_RESULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "schemas" / "corpus-semantic-result.schema.json"
)

CanonicalValue = str | bool | Mapping[str, str]
FormattedRow = tuple[str, ...]


@dataclass(frozen=True)
class CanonicalSemanticResult:
    """A normalized, engine-independent tabular result."""

    columns: tuple[CorpusSemanticColumn, ...]
    rows: tuple[tuple[CanonicalValue, ...], ...]
    formatted_rows: tuple[FormattedRow, ...] | None = None


@dataclass(frozen=True)
class SemanticMismatch:
    """One actionable difference between an actual result and an oracle."""

    path: str
    kind: str
    expected: object | None = None
    actual: object | None = None


@dataclass(frozen=True)
class SemanticComparison:
    """Structured semantic comparison outcome."""

    mismatches: tuple[SemanticMismatch, ...] = ()

    @property
    def matches(self) -> bool:
        return not self.mismatches


def _column_from_raw(raw: Mapping[str, Any]) -> CorpusSemanticColumn:
    return CorpusSemanticColumn(
        name=str(raw["name"]),
        logical_type=str(raw["logical_type"]),
        nullable=bool(raw["nullable"]),
        length=cast(int | None, raw.get("length")),
    )


def load_semantic_result(
    path: Path, *, oracle: CorpusSemanticOracle | None = None
) -> CanonicalSemanticResult:
    """Load and validate a canonical result, optionally against an oracle contract."""

    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    with _RESULT_SCHEMA_PATH.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    jsonschema.validate(instance=raw, schema=schema)
    payload = cast(dict[str, Any], raw)
    columns = tuple(
        _column_from_raw(item) for item in cast(list[dict[str, Any]], payload["columns"])
    )
    names = [item.name for item in columns]
    if len(names) != len(set(names)):
        raise ValueError(f"Canonical semantic result has duplicate columns: {path}")
    rows: list[tuple[CanonicalValue, ...]] = []
    for index, raw_row in enumerate(cast(list[list[CanonicalValue]], payload["rows"])):
        if len(raw_row) != len(columns):
            raise ValueError(
                f"Canonical semantic result row {index} has {len(raw_row)} values; "
                f"expected {len(columns)}"
            )
        row = tuple(raw_row)
        for column, value in zip(columns, row, strict=True):
            _validate_value(column, value, f"rows[{index}].{column.name}")
        rows.append(row)
    formatted_rows: tuple[FormattedRow, ...] | None = None
    raw_formatted_rows = cast(list[list[str]] | None, payload.get("formatted_rows"))
    if raw_formatted_rows is not None:
        if len(raw_formatted_rows) != len(rows):
            raise ValueError(
                f"Canonical semantic result has {len(raw_formatted_rows)} formatted rows; "
                f"expected {len(rows)}"
            )
        normalized_formatted_rows: list[FormattedRow] = []
        for index, formatted_raw_row in enumerate(raw_formatted_rows):
            if len(formatted_raw_row) != len(columns):
                raise ValueError(
                    f"Canonical semantic result formatted row {index} has "
                    f"{len(formatted_raw_row)} "
                    f"values; expected {len(columns)}"
                )
            normalized_formatted_rows.append(tuple(formatted_raw_row))
        formatted_rows = tuple(normalized_formatted_rows)
    result = CanonicalSemanticResult(
        columns=columns, rows=tuple(rows), formatted_rows=formatted_rows
    )
    if oracle is not None:
        expected_columns = tuple(
            (item.name, item.logical_type, item.nullable, item.length) for item in oracle.columns
        )
        actual_columns = tuple(
            (item.name, item.logical_type, item.nullable, item.length) for item in columns
        )
        if actual_columns != expected_columns:
            raise ValueError(f"Canonical semantic result schema does not match oracle: {path}")
        if oracle.authoritative_values in {"formatted", "both"} and formatted_rows is None:
            raise ValueError(
                f"Canonical semantic result lacks formatted_rows required by oracle: {path}"
            )
    return result


def _validate_value(column: CorpusSemanticColumn, value: CanonicalValue, path: str) -> None:
    if isinstance(value, Mapping):
        if "missing" in value:
            marker = value["missing"]
            if not column.nullable:
                raise ValueError(f"Non-nullable semantic value is missing at {path}")
            if column.logical_type == "character" and marker != "character":
                raise ValueError(f"Character missing value must use 'character' at {path}")
            if column.logical_type != "character" and marker == "character":
                raise ValueError(f"Numeric missing marker required at {path}")
            return
        if "number" in value and column.logical_type != "character":
            try:
                Decimal(value["number"])
            except InvalidOperation as exc:
                raise ValueError(f"Invalid canonical number at {path}") from exc
            return
        raise ValueError(f"Unsupported canonical value encoding at {path}")
    if column.logical_type == "character" and isinstance(value, str):
        if not value.strip():
            raise ValueError(
                f"Blank character value must use the canonical missing marker at {path}"
            )
        if column.length is not None and len(value) > column.length:
            raise ValueError(f"Character value exceeds declared length at {path}")
        return
    if column.logical_type == "boolean" and isinstance(value, bool):
        return
    raise ValueError(f"Value does not match logical type {column.logical_type} at {path}")


def _display_key(
    columns: tuple[CorpusSemanticColumn, ...],
    indexes: tuple[int, ...],
    row: tuple[CanonicalValue, ...],
) -> str:
    return ",".join(f"{columns[index].name}={_stable_value(row[index])}" for index in indexes)


def _stable_value(value: CanonicalValue) -> str:
    if isinstance(value, Mapping):
        return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))
    return json.dumps(value, separators=(",", ":"))


def _cell_equal(
    expected: CanonicalValue, actual: CanonicalValue, column: CorpusSemanticColumn
) -> bool:
    if (
        isinstance(expected, Mapping)
        and isinstance(actual, Mapping)
        and "number" in expected
        and "number" in actual
    ):
        left = Decimal(expected["number"])
        right = Decimal(actual["number"])
        difference = abs(left - right)
        limit = Decimal(str(column.absolute_tolerance)) + Decimal(
            str(column.relative_tolerance)
        ) * max(abs(left), abs(right))
        return difference <= limit
    return expected == actual


def _key_equal(
    expected: CanonicalSemanticResult,
    expected_index: int,
    actual: CanonicalSemanticResult,
    actual_index: int,
    oracle: CorpusSemanticOracle,
    indexes: tuple[int, ...],
) -> bool:
    """Compare key cells with the same authority and numeric policy as row cells."""

    if oracle.authoritative_values == "formatted":
        assert expected.formatted_rows is not None
        assert actual.formatted_rows is not None
        return all(
            expected.formatted_rows[expected_index][index]
            == actual.formatted_rows[actual_index][index]
            for index in indexes
        )
    return all(
        _cell_equal(
            expected.rows[expected_index][index],
            actual.rows[actual_index][index],
            oracle.columns[index],
        )
        for index in indexes
    )


def _duplicate_key_indexes(
    result: CanonicalSemanticResult,
    oracle: CorpusSemanticOracle,
    indexes: tuple[int, ...],
) -> tuple[int, ...]:
    """Return later rows whose key is semantically equal to an earlier row's key."""

    duplicates: list[int] = []
    for right_index in range(len(result.rows)):
        if any(
            _key_equal(result, left_index, result, right_index, oracle, indexes)
            for left_index in range(right_index)
        ):
            duplicates.append(right_index)
    return tuple(duplicates)


def _maximum_key_matching(
    expected: CanonicalSemanticResult,
    actual: CanonicalSemanticResult,
    oracle: CorpusSemanticOracle,
    indexes: tuple[int, ...],
) -> tuple[tuple[int | None, ...], tuple[int | None, ...]]:
    """Match keyed rows one-to-one using semantic cell equality for every key column."""

    adjacency = [
        [
            actual_index
            for actual_index in range(len(actual.rows))
            if _key_equal(expected, expected_index, actual, actual_index, oracle, indexes)
        ]
        for expected_index in range(len(expected.rows))
    ]
    actual_to_expected: list[int | None] = [None] * len(actual.rows)

    def augment(expected_index: int, seen: list[bool]) -> bool:
        for actual_index in adjacency[expected_index]:
            if seen[actual_index]:
                continue
            seen[actual_index] = True
            previous = actual_to_expected[actual_index]
            if previous is None or augment(previous, seen):
                actual_to_expected[actual_index] = expected_index
                return True
        return False

    for expected_index in range(len(expected.rows)):
        augment(expected_index, [False] * len(actual.rows))

    expected_to_actual: list[int | None] = [None] * len(expected.rows)
    for actual_index, matched_expected_index in enumerate(actual_to_expected):
        if matched_expected_index is not None:
            expected_to_actual[matched_expected_index] = actual_index
    return tuple(expected_to_actual), tuple(actual_to_expected)


def _compare_rows(
    expected: tuple[CanonicalValue, ...],
    actual: tuple[CanonicalValue, ...],
    oracle: CorpusSemanticOracle,
    base_path: str,
) -> list[SemanticMismatch]:
    return [
        SemanticMismatch(
            path=f"{base_path}.{column.name}",
            kind="cell-value",
            expected=expected[index],
            actual=actual[index],
        )
        for index, column in enumerate(oracle.columns)
        if not _cell_equal(expected[index], actual[index], column)
    ]


def _compare_formatted_rows(
    expected: FormattedRow,
    actual: FormattedRow,
    oracle: CorpusSemanticOracle,
    base_path: str,
) -> list[SemanticMismatch]:
    return [
        SemanticMismatch(
            path=f"{base_path}.{column.name}.formatted",
            kind="formatted-value",
            expected=expected[index],
            actual=actual[index],
        )
        for index, column in enumerate(oracle.columns)
        if expected[index] != actual[index]
    ]


def _rows_equal_for_authority(
    expected: CanonicalSemanticResult,
    expected_index: int,
    actual: CanonicalSemanticResult,
    actual_index: int,
    oracle: CorpusSemanticOracle,
) -> bool:
    underlying_equal = all(
        _cell_equal(left, right, column)
        for left, right, column in zip(
            expected.rows[expected_index],
            actual.rows[actual_index],
            oracle.columns,
            strict=True,
        )
    )
    if oracle.authoritative_values == "underlying":
        return underlying_equal
    assert expected.formatted_rows is not None
    assert actual.formatted_rows is not None
    formatted_equal = expected.formatted_rows[expected_index] == actual.formatted_rows[actual_index]
    if oracle.authoritative_values == "formatted":
        return formatted_equal
    return underlying_equal and formatted_equal


def _maximum_row_matching(
    expected: CanonicalSemanticResult,
    actual: CanonicalSemanticResult,
    oracle: CorpusSemanticOracle,
) -> tuple[tuple[int | None, ...], tuple[int | None, ...]]:
    """Return a deterministic maximum matching for tolerance-compatible rows."""

    adjacency = [
        [
            actual_index
            for actual_index in range(len(actual.rows))
            if _rows_equal_for_authority(expected, expected_index, actual, actual_index, oracle)
        ]
        for expected_index in range(len(expected.rows))
    ]
    actual_to_expected: list[int | None] = [None] * len(actual.rows)

    def augment(expected_index: int, seen: list[bool]) -> bool:
        for actual_index in adjacency[expected_index]:
            if seen[actual_index]:
                continue
            seen[actual_index] = True
            previous = actual_to_expected[actual_index]
            if previous is None or augment(previous, seen):
                actual_to_expected[actual_index] = expected_index
                return True
        return False

    for expected_index in range(len(expected.rows)):
        augment(expected_index, [False] * len(actual.rows))

    expected_to_actual: list[int | None] = [None] * len(expected.rows)
    for actual_index, matched_expected_index in enumerate(actual_to_expected):
        if matched_expected_index is not None:
            expected_to_actual[matched_expected_index] = actual_index
    return tuple(expected_to_actual), tuple(actual_to_expected)


def _compare_authoritative_rows(
    expected: CanonicalSemanticResult,
    expected_index: int,
    actual: CanonicalSemanticResult,
    actual_index: int,
    oracle: CorpusSemanticOracle,
    base_path: str,
) -> list[SemanticMismatch]:
    mismatches: list[SemanticMismatch] = []
    if oracle.authoritative_values in {"underlying", "both"}:
        mismatches.extend(
            _compare_rows(
                expected.rows[expected_index], actual.rows[actual_index], oracle, base_path
            )
        )
    if oracle.authoritative_values in {"formatted", "both"}:
        assert expected.formatted_rows is not None
        assert actual.formatted_rows is not None
        mismatches.extend(
            _compare_formatted_rows(
                expected.formatted_rows[expected_index],
                actual.formatted_rows[actual_index],
                oracle,
                base_path,
            )
        )
    return mismatches


def _dimension_mismatches(result: CanonicalSemanticResult, label: str) -> list[SemanticMismatch]:
    """Validate dimensions for results that may have been constructed directly."""

    column_count = len(result.columns)
    mismatches = [
        SemanticMismatch(
            path=f"{label}.rows[{index}]",
            kind="row-width",
            expected=column_count,
            actual=len(row),
        )
        for index, row in enumerate(result.rows)
        if len(row) != column_count
    ]
    if result.formatted_rows is None:
        return mismatches
    if len(result.formatted_rows) != len(result.rows):
        mismatches.append(
            SemanticMismatch(
                path=f"{label}.formatted_rows",
                kind="formatted-row-count",
                expected=len(result.rows),
                actual=len(result.formatted_rows),
            )
        )
    mismatches.extend(
        SemanticMismatch(
            path=f"{label}.formatted_rows[{index}]",
            kind="formatted-row-width",
            expected=column_count,
            actual=len(row),
        )
        for index, row in enumerate(result.formatted_rows)
        if len(row) != column_count
    )
    return mismatches


def compare_semantic_results(
    expected: CanonicalSemanticResult,
    actual: CanonicalSemanticResult,
    oracle: CorpusSemanticOracle,
) -> SemanticComparison:
    """Compare normalized rows using the oracle's explicit ordering and tolerances."""

    mismatches: list[SemanticMismatch] = []
    expected_schema = tuple(
        (c.name, c.logical_type, c.nullable, c.length) for c in expected.columns
    )
    actual_schema = tuple((c.name, c.logical_type, c.nullable, c.length) for c in actual.columns)
    oracle_schema = tuple((c.name, c.logical_type, c.nullable, c.length) for c in oracle.columns)
    if expected_schema != oracle_schema:
        mismatches.append(
            SemanticMismatch("columns", "oracle-schema", oracle_schema, expected_schema)
        )
    if actual_schema != oracle_schema:
        mismatches.append(
            SemanticMismatch("columns", "actual-schema", oracle_schema, actual_schema)
        )
    mismatches.extend(_dimension_mismatches(expected, "expected"))
    mismatches.extend(_dimension_mismatches(actual, "actual"))
    if mismatches:
        return SemanticComparison(tuple(mismatches))
    if oracle.authoritative_values not in {"underlying", "formatted", "both"}:
        raise ValueError(f"Unsupported semantic value authority: {oracle.authoritative_values}")
    if oracle.authoritative_values in {"formatted", "both"}:
        if expected.formatted_rows is None:
            mismatches.append(
                SemanticMismatch(
                    "expected.formatted_rows", "missing-formatted-values", "formatted rows", None
                )
            )
        if actual.formatted_rows is None:
            mismatches.append(
                SemanticMismatch(
                    "actual.formatted_rows", "missing-formatted-values", "formatted rows", None
                )
            )
        if mismatches:
            return SemanticComparison(tuple(mismatches))

    if oracle.comparison == "ordered":
        if len(expected.rows) != len(actual.rows):
            mismatches.append(
                SemanticMismatch("rows", "row-count", len(expected.rows), len(actual.rows))
            )
        for index in range(min(len(expected.rows), len(actual.rows))):
            mismatches.extend(
                _compare_authoritative_rows(
                    expected, index, actual, index, oracle, f"rows[{index}]"
                )
            )
    elif oracle.comparison == "keyed":
        indexes = tuple(
            next(i for i, c in enumerate(oracle.columns) if c.name == key) for key in oracle.keys
        )
        for label, result in (("expected", expected), ("actual", actual)):
            for row_index in _duplicate_key_indexes(result, oracle, indexes):
                row = result.rows[row_index]
                mismatches.append(
                    SemanticMismatch(
                        f"rows[{_display_key(oracle.columns, indexes, row)}]",
                        f"duplicate-{label}-key",
                    )
                )

        expected_matches, actual_matches = _maximum_key_matching(expected, actual, oracle, indexes)
        for expected_index, actual_index in enumerate(expected_matches):
            row = expected.rows[expected_index]
            base = f"rows[{_display_key(oracle.columns, indexes, row)}]"
            if actual_index is None:
                mismatches.append(SemanticMismatch(base, "missing-row"))
                continue
            mismatches.extend(
                _compare_authoritative_rows(
                    expected, expected_index, actual, actual_index, oracle, base
                )
            )
        for actual_index, matched_expected_index in enumerate(actual_matches):
            if matched_expected_index is not None:
                continue
            row = actual.rows[actual_index]
            mismatches.append(
                SemanticMismatch(f"rows[{_display_key(oracle.columns, indexes, row)}]", "added-row")
            )
    elif oracle.comparison == "unordered-multiset":
        expected_matches, actual_matches = _maximum_row_matching(expected, actual, oracle)
        for index, matched_index in enumerate(expected_matches):
            if matched_index is None:
                mismatches.append(
                    SemanticMismatch(f"rows[{index}]", "missing-row", expected.rows[index], None)
                )
        mismatches.extend(
            SemanticMismatch(f"rows[added={index}]", "added-row", None, actual.rows[index])
            for index, matched_index in enumerate(actual_matches)
            if matched_index is None
        )
    else:
        raise ValueError(f"Unsupported semantic comparison policy: {oracle.comparison}")
    return SemanticComparison(tuple(mismatches))


def load_semantic_registry(manifests_dir: Path) -> tuple[CorpusManifest, ...]:
    """Load all semantic-tier manifests in stable filename order and enforce global IDs."""

    manifests = tuple(
        manifest
        for path in sorted(manifests_dir.glob("*.yaml"))
        if (manifest := load_corpus_manifest(path)).metadata.get("tier") == "semantic"
    )
    scenario_ids = [item.scenario_id for item in manifests]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("Duplicate scenario id in semantic corpus registry")
    oracle_ids = [
        oracle.oracle_id for manifest in manifests for oracle in manifest.semantic_oracles
    ]
    if len(oracle_ids) != len(set(oracle_ids)):
        raise ValueError("Duplicate oracle id in semantic corpus registry")
    for manifest in manifests:
        evidence_by_id = {item.evidence_id: item for item in manifest.output_evidence}
        for oracle in manifest.semantic_oracles:
            load_semantic_result(evidence_by_id[oracle.evidence_id].artifact_path, oracle=oracle)
    return manifests
