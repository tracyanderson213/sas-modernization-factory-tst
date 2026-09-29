from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from smf.validation.structural import (
    DatasetSchemaSnapshot,
    StructuralParityPolicy,
    StructuralParityRequest,
    TypeCompatibilityRule,
    calculate_snapshot_digest,
    compare_snapshots,
    compare_structural_schema,
)


def snapshot(
    columns: list[dict[str, Any]],
    *,
    dataset: str = "work.members",
    engine: str = "sas",
    authoritative: bool = True,
) -> DatasetSchemaSnapshot:
    normalized = []
    for ordinal, column in enumerate(columns, 1):
        normalized.append(
            {
                "ordinal": ordinal,
                "name": column["name"],
                "logical_type": column["logical_type"],
                "native_type": column["native_type"],
                "nullable": column.get("nullable", True),
                "length": column.get("length"),
                "precision": column.get("precision"),
                "scale": column.get("scale"),
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "logical_dataset_id": dataset,
        "engine": engine,
        "columns": normalized,
        "provenance": {
            "producer": "test-fixture",
            "origin": "controlled-test",
            "reference": f"run://{engine}/1",
            "authoritative": authoritative,
        },
        "metadata": {"fixture": True},
    }
    payload["digest"] = calculate_snapshot_digest(payload)
    return DatasetSchemaSnapshot.from_dict(payload)


def column(
    name: str, logical: str = "string", native: str = "CHAR", **kwargs: Any
) -> dict[str, Any]:
    if native.casefold() in {"char", "character", "varchar", "varbinary"}:
        kwargs.setdefault("length", 8)
    return {"name": name, "logical_type": logical, "native_type": native, **kwargs}


def mapped_policy(**kwargs: Any) -> StructuralParityPolicy:
    defaults: dict[str, Any] = {
        "type_mappings": (
            TypeCompatibilityRule("sas-char-spark-string", "string", "CHAR", "string", "STRING"),
            TypeCompatibilityRule("sas-date-spark-date", "date", "DATE", "date", "DATE"),
        )
    }
    defaults.update(kwargs)
    return StructuralParityPolicy(**defaults)


def failed_codes(result: Any) -> list[str]:
    return [check.code for check in result.checks if check.status != "pass"]


def test_identical_schema_passes_and_manifest_contains_itself(tmp_path: Path) -> None:
    source = snapshot([column("member_id", "integer", "INTEGER", nullable=False)])
    target = snapshot([column("member_id", "integer", "INTEGER", nullable=False)], engine="spark")

    result = compare_structural_schema(StructuralParityRequest(source, target, output_dir=tmp_path))

    assert result.status == "passed"
    manifest = tmp_path / "work.members" / "validation" / "structural-parity.manifest.json"
    assert result.output_files == [str(manifest)]
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert str(manifest) in manifest_payload["output_files"]
    assert manifest_payload["policy"]["digest"] == result.policy["digest"]


def test_approved_mapping_to_unbounded_spark_string_passes_widening() -> None:
    source = snapshot([column("Name", length=12)])
    target = snapshot([column("name", native="STRING")], engine="spark")

    result = compare_snapshots(source, target, mapped_policy(length_rule="target_may_widen"))

    assert result.status == "passed"
    type_check = next(check for check in result.checks if check.code == "SCHEMA-TYPE-INCOMPATIBLE")
    assert type_check.applied_rule == "sas-char-spark-string"
    length_check = next(check for check in result.checks if check.code == "SCHEMA-LENGTH-MISMATCH")
    assert length_check.expected == 12
    assert length_check.actual is None
    assert length_check.status == "pass"


def test_unbounded_spark_string_requires_widening_policy() -> None:
    source = snapshot([column("name", length=12)])
    target = snapshot([column("name", native="STRING")], engine="spark")

    result = compare_snapshots(source, target, mapped_policy())

    assert result.status == "failed"
    assert "SCHEMA-LENGTH-MISMATCH" in failed_codes(result)


def test_decimal_widening_preserves_integral_and_fractional_capacity() -> None:
    source = snapshot([column("amount", "decimal", "DECIMAL", precision=12, scale=2)])
    narrower_target = snapshot(
        [column("amount", "decimal", "DECIMAL", precision=12, scale=3)], engine="spark"
    )
    wider_target = snapshot(
        [column("amount", "decimal", "DECIMAL", precision=13, scale=3)], engine="spark"
    )
    policy = StructuralParityPolicy(
        precision_rule="target_may_widen", scale_rule="target_may_widen"
    )

    narrowed = compare_snapshots(source, narrower_target, policy)
    widened = compare_snapshots(source, wider_target, policy)

    assert narrowed.status == "failed"
    assert "SCHEMA-PRECISION-MISMATCH" in failed_codes(narrowed)
    assert widened.status == "passed"


def test_missing_bounded_type_length_blocks_comparison() -> None:
    source = snapshot([column("code", length=None)])
    target = snapshot([column("code", length=None)], engine="spark")

    result = compare_snapshots(source, target, StructuralParityPolicy())

    assert result.status == "blocked"
    insufficient = [
        check
        for check in result.checks
        if check.path.endswith(".attributes") and check.status == "blocked"
    ]
    assert len(insufficient) == 1
    assert insufficient[0].actual == {"source": ["length"], "target": ["length"]}


def test_policy_digest_distinguishes_behavior_under_same_id_and_version() -> None:
    source = snapshot([column("a"), column("b")])
    target = snapshot([column("b"), column("a")], engine="spark")

    sensitive = compare_snapshots(source, target, StructuralParityPolicy())
    insensitive = compare_snapshots(source, target, StructuralParityPolicy(order_significant=False))

    assert sensitive.status == "failed"
    assert insensitive.status == "passed"
    assert sensitive.policy["digest"] != insensitive.policy["digest"]
    assert sensitive.comparison_id != insensitive.comparison_id


def test_approved_sas_date_to_spark_date_mapping_passes() -> None:
    source = snapshot([column("service_date", "date", "DATE")])
    target = snapshot(
        [column("service_date", "date", "DATE")],
        engine="spark",
    )

    result = compare_snapshots(source, target, mapped_policy())

    assert result.status == "passed"
    type_check = next(check for check in result.checks if check.code == "SCHEMA-TYPE-INCOMPATIBLE")
    assert type_check.applied_rule == "sas-date-spark-date"


def test_undeclared_mapping_and_attributes_are_blocking_failures() -> None:
    source = snapshot([column("amount", "decimal", "DECIMAL", precision=12, scale=2)])
    target = snapshot(
        [column("amount", "decimal", "NUMERIC", precision=10, scale=3)], engine="spark"
    )

    result = compare_snapshots(source, target, StructuralParityPolicy())

    assert result.status == "failed"
    assert failed_codes(result) == [
        "SCHEMA-TYPE-INCOMPATIBLE",
        "SCHEMA-PRECISION-MISMATCH",
        "SCHEMA-SCALE-MISMATCH",
    ]


def test_missing_then_unexpected_columns_have_deterministic_order() -> None:
    source = snapshot([column("a"), column("b")])
    target = snapshot([column("a"), column("c")])

    result = compare_snapshots(source, target, StructuralParityPolicy())

    assert failed_codes(result) == ["SCHEMA-COLUMN-MISSING", "SCHEMA-COLUMN-UNEXPECTED"]


def test_case_sensitive_and_order_policies() -> None:
    source = snapshot([column("A"), column("b")])
    target = snapshot([column("b"), column("a")])

    insensitive = compare_snapshots(source, target, StructuralParityPolicy(order_significant=False))
    sensitive = compare_snapshots(
        source,
        target,
        StructuralParityPolicy(case_sensitive_names=True, order_significant=False),
    )

    assert insensitive.status == "passed"
    assert sensitive.status == "failed"
    assert "SCHEMA-COLUMN-MISSING" in failed_codes(sensitive)


def test_order_and_nullability_differences_fail() -> None:
    source = snapshot([column("a", nullable=False), column("b")])
    target = snapshot([column("b"), column("a", nullable=True)])

    result = compare_snapshots(source, target, StructuralParityPolicy())

    assert failed_codes(result).count("SCHEMA-ORDER-MISMATCH") == 2
    assert "SCHEMA-NULLABILITY-MISMATCH" in failed_codes(result)


def test_casefold_duplicates_and_unsupported_types_block() -> None:
    source = snapshot([column("A"), column("a")])
    target = snapshot([column("A", "variant", "VARIANT"), column("b")])

    duplicate = compare_snapshots(source, target, StructuralParityPolicy())
    unsupported = compare_snapshots(
        snapshot([column("v", "variant", "VARIANT")]),
        snapshot([column("v", "variant", "VARIANT")], engine="spark"),
        StructuralParityPolicy(),
    )

    assert duplicate.status == "blocked"
    assert "SCHEMA-DUPLICATE-COLUMN" in failed_codes(duplicate)
    assert unsupported.status == "blocked"
    assert "SCHEMA-TYPE-UNSUPPORTED" in failed_codes(unsupported)


def test_unknown_native_type_blocks_without_explicit_mapping() -> None:
    source = snapshot([column("v", "string", "MYSTERY")])
    target = snapshot([column("v", "string", "MYSTERY")], engine="spark")

    result = compare_snapshots(source, target, StructuralParityPolicy())

    assert result.status == "blocked"
    assert "SCHEMA-TYPE-UNSUPPORTED" in failed_codes(result)


def test_untrusted_or_tampered_evidence_and_unmapped_dataset_block() -> None:
    source = snapshot([column("a")], authoritative=False)
    target = snapshot([column("a")], dataset="other", engine="spark")
    tampered = DatasetSchemaSnapshot(**{**target.__dict__, "digest": "sha256:" + "0" * 64})

    result = compare_snapshots(source, tampered, StructuralParityPolicy())

    assert result.status == "blocked"
    assert failed_codes(result)[:3] == [
        "SCHEMA-EVIDENCE-MISSING",
        "SCHEMA-EVIDENCE-DIGEST",
        "SCHEMA-DATASET-UNMAPPED",
    ]


def test_empty_schema_requires_explicit_policy() -> None:
    source = snapshot([])
    target = snapshot([], engine="spark")

    assert compare_snapshots(source, target, StructuralParityPolicy()).status == "blocked"
    assert (
        compare_snapshots(source, target, StructuralParityPolicy(allow_empty_schemas=True)).status
        == "passed"
    )


def test_malformed_decimal_and_ambiguous_policy_are_rejected() -> None:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "logical_dataset_id": "work.amounts",
        "engine": "sas",
        "columns": [
            {
                "ordinal": 1,
                "name": "amount",
                "logical_type": "decimal",
                "native_type": "DECIMAL",
                "nullable": True,
                "length": None,
                "precision": None,
                "scale": None,
            }
        ],
        "provenance": {
            "producer": "test",
            "origin": "test",
            "reference": "run://1",
            "authoritative": True,
        },
        "metadata": {},
    }
    payload["digest"] = calculate_snapshot_digest(payload)
    with pytest.raises(ValueError, match="schema validation failed"):
        DatasetSchemaSnapshot.from_dict(payload)

    rule = TypeCompatibilityRule("same", "string", "CHAR", "string", "STRING")
    with pytest.raises(ValueError, match="duplicate or ambiguous"):
        compare_snapshots(
            snapshot([column("a")]),
            snapshot([column("a", native="STRING")], engine="spark"),
            StructuralParityPolicy(type_mappings=(rule, rule)),
        )


def test_snapshot_contract_rejects_unknown_fields_and_contains_no_rows() -> None:
    source = snapshot([column("a")])
    payload = source.to_dict()
    payload["rows"] = [{"a": "protected"}]

    with pytest.raises(ValueError, match="Additional properties"):
        DatasetSchemaSnapshot.from_dict(payload)
    assert "rows" not in source.to_dict()
