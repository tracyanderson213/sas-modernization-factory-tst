import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import ValidationError

from smf.corpus import (
    CanonicalSemanticResult,
    CorpusSemanticColumn,
    compare_semantic_results,
    load_corpus_manifest,
    load_semantic_registry,
    load_semantic_result,
)

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST_ROOT = CORPUS_ROOT / "manifests"
BASE_MANIFEST = MANIFEST_ROOT / "semantic-merge-by.yaml"


def _oracle_and_result(scenario_id: str):
    manifest = next(
        item for item in load_semantic_registry(MANIFEST_ROOT) if item.scenario_id == scenario_id
    )
    oracle = manifest.semantic_oracles[0]
    evidence = next(
        item for item in manifest.output_evidence if item.evidence_id == oracle.evidence_id
    )
    return oracle, load_semantic_result(evidence.artifact_path, oracle=oracle)


def test_ordered_comparison_reports_mutated_cell_path() -> None:
    oracle, expected = _oracle_and_result("semantic-data-step-dates-missing")
    mutated_row = ("WRONG", *expected.rows[0][1:])
    actual = replace(expected, rows=(mutated_row, *expected.rows[1:]))

    comparison = compare_semantic_results(expected, actual, oracle)

    assert not comparison.matches
    assert comparison.mismatches[0].path == "rows[0].member_id"


def test_keyed_comparison_ignores_physical_order_and_names_key_in_failure() -> None:
    oracle, expected = _oracle_and_result("semantic-merge-by")
    reversed_result = replace(expected, rows=expected.rows[::-1])
    assert compare_semantic_results(expected, reversed_result, oracle).matches

    changed = list(expected.rows[0])
    changed[2] = {"number": "999"}
    actual = replace(expected, rows=(tuple(changed), expected.rows[1]))
    mismatch = compare_semantic_results(expected, actual, oracle).mismatches[0]
    assert mismatch.path == 'rows[member_id="M001"].paid_amount'


def test_keyed_comparison_normalizes_numeric_spelling() -> None:
    oracle, expected = _oracle_and_result("semantic-dynamic-macro")
    row = list(expected.rows[0])
    row[0] = {"number": "2.0"}

    comparison = compare_semantic_results(expected, replace(expected, rows=(tuple(row),)), oracle)

    assert comparison.matches


def test_keyed_comparison_applies_declared_key_tolerance() -> None:
    base_oracle, _ = _oracle_and_result("semantic-dynamic-macro")
    key_column = replace(base_oracle.columns[0], absolute_tolerance=0.01)
    oracle = replace(base_oracle, columns=(key_column, *base_oracle.columns[1:]))
    expected = CanonicalSemanticResult(
        columns=oracle.columns,
        rows=(({"number": "2"}, "WEST", {"number": "20"}),),
    )
    actual = replace(
        expected,
        rows=(({"number": "2.005"}, "WEST", {"number": "20"}),),
    )

    assert compare_semantic_results(expected, actual, oracle).matches


def test_multiset_comparison_preserves_duplicate_counts() -> None:
    oracle, expected = _oracle_and_result("semantic-many-to-many-sql")
    reversed_result = replace(expected, rows=expected.rows[::-1])
    assert compare_semantic_results(expected, reversed_result, oracle).matches
    comparison = compare_semantic_results(
        expected, replace(expected, rows=expected.rows[:-1]), oracle
    )
    assert not comparison.matches
    assert comparison.mismatches[0].kind == "missing-row"


def test_tolerant_multiset_uses_complete_one_to_one_matching() -> None:
    base_oracle, _ = _oracle_and_result("semantic-many-to-many-sql")
    column = CorpusSemanticColumn(
        name="value", logical_type="numeric", nullable=False, absolute_tolerance=0.11
    )
    oracle = replace(base_oracle, columns=(column,))
    expected = CanonicalSemanticResult(
        columns=(column,), rows=(({"number": "0"},), ({"number": "0.2"},))
    )
    actual = CanonicalSemanticResult(
        columns=(column,), rows=(({"number": "0.1"},), ({"number": "0"},))
    )

    assert compare_semantic_results(expected, actual, oracle).matches


def test_formatted_and_both_authority_compare_declared_projections() -> None:
    base_oracle, _ = _oracle_and_result("semantic-many-to-many-sql")
    column = CorpusSemanticColumn(name="value", logical_type="numeric", nullable=False)
    expected = CanonicalSemanticResult(
        columns=(column,),
        rows=(({"number": "1"},),),
        formatted_rows=(("1.00",),),
    )
    different_underlying = CanonicalSemanticResult(
        columns=(column,),
        rows=(({"number": "2"},),),
        formatted_rows=(("1.00",),),
    )
    formatted_oracle = replace(
        base_oracle,
        comparison="ordered",
        columns=(column,),
        authoritative_values="formatted",
    )
    both_oracle = replace(formatted_oracle, authoritative_values="both")

    assert compare_semantic_results(expected, different_underlying, formatted_oracle).matches
    assert not compare_semantic_results(expected, different_underlying, both_oracle).matches

    changed_format = replace(different_underlying, formatted_rows=(("2.00",),))
    mismatch = compare_semantic_results(expected, changed_format, formatted_oracle).mismatches[0]
    assert mismatch.path == "rows[0].value.formatted"


def test_formatted_authority_fails_closed_without_formatted_rows() -> None:
    oracle, expected = _oracle_and_result("semantic-date-boundaries")
    formatted_oracle = replace(oracle, authoritative_values="formatted")

    comparison = compare_semantic_results(expected, expected, formatted_oracle)

    assert not comparison.matches
    assert {item.path for item in comparison.mismatches} == {
        "expected.formatted_rows",
        "actual.formatted_rows",
    }


def test_formatted_projection_loads_and_must_align_with_rows(tmp_path: Path) -> None:
    base_oracle, _ = _oracle_and_result("semantic-date-boundaries")
    column = CorpusSemanticColumn(name="date_value", logical_type="date", nullable=False)
    oracle = replace(base_oracle, columns=(column,), authoritative_values="both")
    payload = {
        "schema_version": 1,
        "columns": [{"name": "date_value", "logical_type": "date", "nullable": False}],
        "rows": [[{"number": "0"}]],
        "formatted_rows": [["01JAN1960"]],
    }
    path = tmp_path / "formatted-result.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = load_semantic_result(path, oracle=oracle)
    assert result.formatted_rows == (("01JAN1960",),)

    payload["formatted_rows"] = []
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="formatted rows"):
        load_semantic_result(path, oracle=oracle)


def test_special_missing_values_are_not_interchangeable() -> None:
    oracle, expected = _oracle_and_result("semantic-missing-value-ordering")
    row = list(expected.rows[1])
    row[1] = {"missing": ".Z"}
    actual = replace(expected, rows=(expected.rows[0], tuple(row), *expected.rows[2:]))
    comparison = compare_semantic_results(expected, actual, oracle)
    assert any(item.path == "rows[1].value" for item in comparison.mismatches)


def test_data_step_iteration_oracle_preserves_pdv_order_and_reset() -> None:
    _, expected = _oracle_and_result("semantic-data-step-iteration")

    assert tuple(column.name for column in expected.columns) == (
        "retained",
        "id",
        "value",
        "sum_statement",
        "reset_each_iteration",
    )
    assert expected.rows == (
        (
            {"number": "102"},
            {"number": "2"},
            {"number": "20"},
            {"number": "30"},
            {"missing": "."},
        ),
        (
            {"number": "104"},
            {"number": "4"},
            {"number": "40"},
            {"number": "100"},
            {"missing": "."},
        ),
    )


@pytest.mark.parametrize(("nullable", "value"), [(False, ""), (False, "   "), (True, "\t")])
def test_blank_character_values_must_use_canonical_missing_marker(
    tmp_path: Path, nullable: bool, value: str
) -> None:
    payload = {
        "schema_version": 1,
        "columns": [
            {
                "name": "character_value",
                "logical_type": "character",
                "nullable": nullable,
            }
        ],
        "rows": [[value]],
    }
    path = tmp_path / "blank-character.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValidationError, match="does not match"):
        load_semantic_result(path)


def test_nullable_character_missing_uses_explicit_marker(tmp_path: Path) -> None:
    payload = {
        "schema_version": 1,
        "columns": [{"name": "character_value", "logical_type": "character", "nullable": True}],
        "rows": [[{"missing": "character"}]],
    }
    path = tmp_path / "character-missing.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = load_semantic_result(path)

    assert result.rows == (({"missing": "character"},),)


def test_explicit_numeric_tolerance_is_bounded() -> None:
    oracle, expected = _oracle_and_result("semantic-numeric-precision")
    row = list(expected.rows[0])
    row[4] = {"number": "0.3333333333333338"}
    assert compare_semantic_results(expected, replace(expected, rows=(tuple(row),)), oracle).matches
    row[4] = {"number": "0.3333333333334"}
    assert not compare_semantic_results(
        expected, replace(expected, rows=(tuple(row),)), oracle
    ).matches


def test_empty_results_compare_and_added_row_fails() -> None:
    oracle, expected = _oracle_and_result("semantic-empty-dataset")
    assert compare_semantic_results(expected, expected, oracle).matches
    row = ("A", {"number": "1"})
    assert not compare_semantic_results(expected, replace(expected, rows=(row,)), oracle).matches


def test_schema_difference_fails_before_rows() -> None:
    oracle, expected = _oracle_and_result("semantic-merge-by")
    changed_column = replace(expected.columns[1], nullable=True)
    actual = CanonicalSemanticResult(
        columns=(expected.columns[0], changed_column, expected.columns[2]), rows=expected.rows
    )
    mismatch = compare_semantic_results(expected, actual, oracle).mismatches[0]
    assert mismatch.kind == "actual-schema"


@pytest.mark.parametrize("width_delta", [-1, 1])
def test_comparator_rejects_malformed_actual_row_width(width_delta: int) -> None:
    oracle, expected = _oracle_and_result("semantic-data-step-dates-missing")
    row = expected.rows[0]
    malformed_row = row[:-1] if width_delta < 0 else (*row, "EXTRA")
    actual = replace(expected, rows=(malformed_row, *expected.rows[1:]))

    comparison = compare_semantic_results(expected, actual, oracle)

    assert not comparison.matches
    assert comparison.mismatches[0].path == "actual.rows[0]"
    assert comparison.mismatches[0].kind == "row-width"
    assert comparison.mismatches[0].expected == len(expected.columns)
    assert comparison.mismatches[0].actual == len(malformed_row)


def test_comparator_rejects_misaligned_formatted_rows() -> None:
    base_oracle, _ = _oracle_and_result("semantic-many-to-many-sql")
    column = CorpusSemanticColumn(name="value", logical_type="numeric", nullable=False)
    oracle = replace(
        base_oracle,
        comparison="ordered",
        columns=(column,),
        authoritative_values="formatted",
    )
    expected = CanonicalSemanticResult(
        columns=(column,),
        rows=(({"number": "1"},),),
        formatted_rows=(("1.00",),),
    )
    actual = replace(expected, formatted_rows=(("1.00", "EXTRA"), ("2.00",)))

    comparison = compare_semantic_results(expected, actual, oracle)

    assert not comparison.matches
    assert [(item.path, item.kind) for item in comparison.mismatches] == [
        ("actual.formatted_rows", "formatted-row-count"),
        ("actual.formatted_rows[0]", "formatted-row-width"),
    ]


def test_every_fixture_oracle_is_sensitive_to_a_controlled_mutation() -> None:
    for manifest in load_semantic_registry(MANIFEST_ROOT):
        for oracle in manifest.semantic_oracles:
            evidence = next(
                item for item in manifest.output_evidence if item.evidence_id == oracle.evidence_id
            )
            expected = load_semantic_result(evidence.artifact_path, oracle=oracle)
            if expected.rows:
                actual = replace(expected, rows=expected.rows[1:])
            else:
                actual = replace(
                    expected,
                    rows=(
                        tuple(
                            "X"
                            if column.logical_type == "character"
                            else False
                            if column.logical_type == "boolean"
                            else {"number": "0"}
                            for column in expected.columns
                        ),
                    ),
                )
            assert not compare_semantic_results(expected, actual, oracle).matches, oracle.oracle_id


def _mutated_manifest(tmp_path: Path, mutate: Callable[[dict[str, Any]], None]) -> Path:
    payload = yaml.safe_load(BASE_MANIFEST.read_text(encoding="utf-8"))
    mutate(payload)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda p: p["semantic_oracles"].append(dict(p["semantic_oracles"][0])), "Duplicate"),
        (lambda p: p["semantic_oracles"][0].update(evidence_id="unknown"), "unknown"),
        (lambda p: p["output_evidence"][0].update(authoritative=False), "authoritative"),
        (lambda p: p["output_evidence"][0].update(deterministic=False), "deterministic"),
        (lambda p: p["semantic_oracles"][0].pop("keys"), "requires keys"),
    ],
)
def test_invalid_oracle_contracts_are_rejected(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        load_corpus_manifest(_mutated_manifest(tmp_path, mutate), verify_files=False)


def test_private_semantic_oracle_is_rejected(tmp_path: Path) -> None:
    path = _mutated_manifest(tmp_path, lambda p: p["metadata"].update(private_data=True))
    with pytest.raises(ValueError, match="must not contain private data"):
        load_corpus_manifest(path, verify_files=False)
