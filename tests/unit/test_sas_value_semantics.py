from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from smf.conversion.registry import PlanDisposition, execute_plan, plan_rules
from smf.conversion.value_semantics import (
    ValueCompatibilityPolicy,
    ValueDisposition,
    classify_value_semantics,
)

ROOT = Path(__file__).parents[2]


def policy() -> ValueCompatibilityPolicy:
    return ValueCompatibilityPolicy.from_dict(
        json.loads((ROOT / "examples/policies/sas-value-compatibility-v1.json").read_text())
    )


def test_policy_example_matches_public_and_packaged_strict_schemas() -> None:
    payload = policy().to_dict()
    public = json.loads((ROOT / "schemas/sas-value-compatibility-policy.schema.json").read_text())
    packaged = json.loads(
        (ROOT / "src/smf/schemas/sas-value-compatibility-policy.schema.json").read_text()
    )

    assert public == packaged
    Draft202012Validator(public).validate(payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"character_to_numeric_mode": "best-effort"}, "character coercion"),
        ({"missing_comparison_mode": "null-equivalent"}, "cannot be widened"),
        ({"supported_targets": ["spark-ish"]}, "unsupported target"),
        ({"version": "latest"}, "identity or version"),
        ({"maximum_integer_digits": True}, "bounds are malformed"),
        ({"unsupported_cases": ["secret-canary-value"]}, "protected data"),
    ],
)
def test_unknown_lossy_and_secret_policy_values_fail_closed(
    mutation: dict[str, object], message: str
) -> None:
    payload = policy().to_dict()
    payload.update(mutation)
    with pytest.raises(ValueError, match=message):
        ValueCompatibilityPolicy.from_dict(payload)


def test_policy_rejects_unknown_attestation_fields() -> None:
    payload = policy().to_dict()
    payload["approved"] = True
    with pytest.raises(ValueError, match="unknown or missing"):
        ValueCompatibilityPolicy.from_dict(payload)


@pytest.mark.parametrize(
    ("source", "category"),
    [
        (b"select . from t", "ordinary"),
        (b"select ._ from t", "special-low"),
        (b"select .A from t", "special-A"),
        (b"select .Z from t", "special-Z"),
        (b"select ' ' from t", "character-blank"),
    ],
)
def test_missing_categories_are_byte_bound_and_never_collapse_to_null(
    source: bytes, category: str
) -> None:
    result = classify_value_semantics(source, policy(), target="sparksql")

    assert result.disposition is ValueDisposition.UNSUPPORTED
    assert result.rewritten is None
    assert result.occurrences[0].missing_category == category
    assert result.occurrences[0].source_token_sha256
    assert result.occurrences[0].target_expression is None


def test_applicable_semantics_without_policy_are_blocked_not_skipped() -> None:
    missing = classify_value_semantics(b"select .A from t", None, target="sparksql")
    coercion = classify_value_semantics(b"select * from t where '1'=1", None, target="sparksql")

    assert missing.disposition is ValueDisposition.BLOCKED
    assert coercion.disposition is ValueDisposition.BLOCKED
    assert all(item.policy_digest is None for item in (*missing.occurrences, *coercion.occurrences))


@pytest.mark.parametrize(
    ("literal", "normalized"),
    [("' 001.500 '", "1.5"), ('"-0002"', "-2"), ("'+0.00'", "0")],
)
def test_exact_literal_coercion_is_the_only_qualified_subset(literal: str, normalized: str) -> None:
    source = f"proc sql; select * from t where {literal}=1; quit;".encode()
    plan = plan_rules(source, "sparksql", value_policy=policy())

    assert plan.disposition is PlanDisposition.QUALIFIED
    assert len(plan.value_occurrences) == 1
    assert plan.value_occurrences[0]["normalized_value"] == normalized
    converted = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-1",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )
    assert f"where {normalized}=1" in converted.content
    mapping = converted.metadata["value_mappings"][0]
    assert mapping["workload_id"] == "WL-1"
    assert mapping["source_artifact_id"] == "ART-1"
    assert mapping["run_id"] == "RUN-1" and mapping["attempt_id"] == "ATT-1"
    assert mapping["policy_digest"] == policy().policy_digest
    assert mapping["generated_sha256"] == converted.metadata["generated_sha256"]
    mapping_schema = json.loads((ROOT / "schemas/sas-value-mapping.schema.json").read_text())
    Draft202012Validator(mapping_schema).validate({"mappings": [mapping]})


@pytest.mark.parametrize(
    "literal",
    [
        "''",
        "'   '",
        "'+'",
        "'1.2.3'",
        "'1e2'",
        "'NaN'",
        "'Infinity'",
        "'1,5'",
        "'2024-01-01'",
        "'1234567890123456789'",
        "'1.1234567890'",
    ],
)
def test_malformed_or_lossy_numeric_strings_remain_unresolved(literal: str) -> None:
    source = f"proc sql; select * from t where {literal}=1; quit;".encode()
    plan = plan_rules(source, "sparksql", value_policy=policy())

    assert plan.disposition is PlanDisposition.UNSUPPORTED
    assert plan.selected_rules == ()
    assert plan.value_occurrences
    assert plan.value_occurrences[0]["target_expression"] is None


@pytest.mark.parametrize("keyword", ["between", "not between"])
@pytest.mark.parametrize(
    ("subject", "bounds"),
    [
        ("1", ("'1'", "'2'")),
        ("1", ("'bogus'", "'2'")),
        ("'1'", ("1", "2")),
        ("1", ("'1'", "2")),
    ],
)
def test_between_character_bounds_are_attributable_but_unsupported(
    keyword: str, subject: str, bounds: tuple[str, str]
) -> None:
    source = (
        f"proc sql; select * from t where {subject} {keyword} {bounds[0]} and {bounds[1]}; quit;"
    ).encode()

    without_policy = plan_rules(source, "sparksql", value_policy=None)
    with_policy = plan_rules(source, "sparksql", value_policy=policy())

    assert without_policy.disposition is PlanDisposition.BLOCKED
    assert with_policy.disposition is PlanDisposition.UNSUPPORTED
    for plan in (without_policy, with_policy):
        assert plan.value_occurrences
        assert all(item["byte_start"] < item["byte_end"] for item in plan.value_occurrences)
        assert all(item["source_token_sha256"] for item in plan.value_occurrences)
        with pytest.raises(ValueError, match="Only a uniquely qualified"):
            execute_plan(
                source,
                plan,
                workload_id="WL-BETWEEN",
                source_artifact_id="ART-BETWEEN",
                run_id="RUN-BETWEEN",
                attempt_id="ATT-BETWEEN",
            )


@pytest.mark.parametrize("expression", ["'1'||2", "2||'1'"])
def test_numeric_character_concatenation_is_attributable_but_unsupported(
    expression: str,
) -> None:
    source = f"proc sql; select {expression} as x from t; quit;".encode()

    without_policy = plan_rules(source, "sparksql", value_policy=None)
    with_policy = plan_rules(source, "sparksql", value_policy=policy())

    assert without_policy.disposition is PlanDisposition.BLOCKED
    assert with_policy.disposition is PlanDisposition.UNSUPPORTED
    assert without_policy.value_occurrences
    assert with_policy.value_occurrences
    assert {item["conversion_direction"] for item in with_policy.value_occurrences} == {
        "numeric-to-character"
    }
    with pytest.raises(ValueError, match="Only a uniquely qualified"):
        execute_plan(
            source,
            with_policy,
            workload_id="WL-CONCAT",
            source_artifact_id="ART-CONCAT",
            run_id="RUN-CONCAT",
            attempt_id="ATT-CONCAT",
        )


@pytest.mark.parametrize(
    "expression",
    ["1||2", "'1'||member_id", "member_id||'1'", "left_id||right_id"],
)
def test_other_concat_coercion_and_type_ambiguity_cannot_bypass_policy(
    expression: str,
) -> None:
    source = f"proc sql; select {expression} as x from t; quit;".encode()

    without_policy = plan_rules(source, "sparksql", value_policy=None)
    with_policy = plan_rules(source, "sparksql", value_policy=policy())

    assert without_policy.disposition is PlanDisposition.BLOCKED
    assert with_policy.disposition is PlanDisposition.UNSUPPORTED
    assert without_policy.value_occurrences
    assert with_policy.value_occurrences


def test_between_character_literal_and_unbound_identifier_is_schema_dependent() -> None:
    source = b"proc sql; select * from t where member_id between '1' and '2'; quit;"

    without_policy = plan_rules(source, "sparksql", value_policy=None)
    with_policy = plan_rules(source, "sparksql", value_policy=policy())

    assert without_policy.disposition is PlanDisposition.BLOCKED
    assert with_policy.disposition is PlanDisposition.UNSUPPORTED
    assert with_policy.value_occurrences
    assert {item["reason_code"] for item in with_policy.value_occurrences} == {
        "authoritative_type_binding_missing"
    }


@pytest.mark.parametrize("operator", ["+", "-", "*", "/"])
@pytest.mark.parametrize(
    "literal",
    [
        "'9007199254740991'",
        "'9007199254740992'",
        "'9007199254740993'",
        "'0.123456789'",
    ],
)
def test_arithmetic_literal_coercion_requires_operation_specific_equivalence_evidence(
    operator: str, literal: str
) -> None:
    source = f"proc sql; select {literal}{operator}1 as x from t; quit;".encode()
    plan = plan_rules(source, "sparksql", value_policy=policy())

    assert plan.disposition is PlanDisposition.UNSUPPORTED
    assert plan.value_occurrences
    assert plan.value_occurrences[0]["target_expression"] is None
    assert plan.value_occurrences[0]["reason_code"] == "arithmetic_equivalence_unproven"
    with pytest.raises(ValueError, match="Only a uniquely qualified"):
        execute_plan(
            source,
            plan,
            workload_id="WL-ARITHMETIC",
            source_artifact_id="ART-ARITHMETIC",
            run_id="RUN-ARITHMETIC",
            attempt_id="ATT-ARITHMETIC",
        )


@pytest.mark.parametrize("literal", ["'9007199254740993'", "'0.123456789'"])
def test_nonrepresentable_comparison_literals_remain_unsupported(literal: str) -> None:
    source = f"proc sql; select * from t where {literal}=1; quit;".encode()
    plan = plan_rules(source, "sparksql", value_policy=policy())

    assert plan.disposition is PlanDisposition.UNSUPPORTED
    assert plan.value_occurrences[0]["reason_code"] == "malformed_or_lossy_numeric_literal"


def test_schema_dependent_column_comparison_is_unresolved_without_type_binding() -> None:
    source = b"proc sql; select * from t where member_id='001'; quit;"
    plan = plan_rules(source, "sparksql", value_policy=policy())

    assert plan.disposition is PlanDisposition.UNSUPPORTED
    assert plan.value_occurrences[0]["reason_code"] == "authoritative_type_binding_missing"


def test_missing_like_text_inside_character_literal_is_not_numeric_missing() -> None:
    result = classify_value_semantics(b"select '.A' as label", policy(), target="sparksql")

    assert result.disposition is ValueDisposition.NOT_APPLICABLE
    assert result.occurrences == ()


@pytest.mark.parametrize("marker", [b".AA", b".__", b".unknown"])
def test_unknown_missing_markers_fail_closed(marker: bytes) -> None:
    result = classify_value_semantics(b"select " + marker + b" from t", policy(), target="sparksql")

    assert result.disposition is ValueDisposition.UNSUPPORTED
    assert result.occurrences[0].reason_code == "unsupported_missing_marker"


def test_source_and_policy_mutation_change_plan_identity_and_replay_fails() -> None:
    source = b"proc sql; select * from t where '001'=1; quit;"
    original = plan_rules(source, "sparksql", value_policy=policy())
    changed_policy = replace(policy(), maximum_integer_digits=17).validate()
    changed = plan_rules(source, "sparksql", value_policy=changed_policy)

    assert original.plan_id != changed.plan_id
    with pytest.raises(ValueError, match="no longer matches"):
        execute_plan(
            source.replace(b"001", b"002"),
            original,
            workload_id="WL-1",
            source_artifact_id="ART-1",
            run_id="RUN-1",
            attempt_id="ATT-1",
        )


def test_missing_category_mutation_changes_plan_and_never_passes() -> None:
    first = plan_rules(b"proc sql; select .A from t; quit;", "sparksql", value_policy=policy())
    second = plan_rules(b"proc sql; select .Z from t; quit;", "sparksql", value_policy=policy())

    assert first.disposition is second.disposition is PlanDisposition.UNSUPPORTED
    assert first.plan_id != second.plan_id
    assert (
        first.value_occurrences[0]["missing_category"]
        != second.value_occurrences[0]["missing_category"]
    )
