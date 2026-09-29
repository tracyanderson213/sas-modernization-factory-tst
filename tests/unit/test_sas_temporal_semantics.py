from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from smf.conversion.registry import PlanDisposition, execute_plan, plan_rules
from smf.conversion.temporal import (
    TemporalDisposition,
    TemporalLiteralKind,
    TemporalPolicy,
    normalize_temporal_literals,
    utc_temporal_policy,
)


def test_epoch_units_boundaries_and_fractional_precision_are_exact() -> None:
    source = (
        b"select '01JAN1960'd as epoch_day, '31DEC1959'd as before_epoch, "
        b"'29FEB2000:23:59:59.123400'dt as leap_timestamp"
    )
    result = normalize_temporal_literals(source, utc_temporal_policy())

    assert result.disposition is TemporalDisposition.NORMALIZED
    assert [mapping.kind for mapping in result.mappings] == [
        TemporalLiteralKind.DATE,
        TemporalLiteralKind.DATE,
        TemporalLiteralKind.DATETIME,
    ]
    assert [mapping.normalized_value for mapping in result.mappings] == [
        "0",
        "-1",
        "1267487999.123400",
    ]
    assert result.mappings[2].canonical_source == "29FEB2000:23:59:59.123400"
    assert result.mappings[2].target_expression.endswith("23:59:59.123400'")
    for mapping in result.mappings:
        literal = source[mapping.byte_start : mapping.byte_end]
        assert hashlib.sha256(literal).hexdigest() == mapping.literal_sha256


@pytest.mark.parametrize(
    ("literal", "reason"),
    [
        ("'29FEB1900'd", "calendar"),
        ("'31APR2020'd", "calendar"),
        ("'01JAN20'd", "grammar"),
        ("'01JAN2020:24:00:00'dt", "clock"),
        ("'01JAN2020:23:59:60'dt", "clock"),
        ("'01JAN2020:00:00:00.1234567'dt", "precision"),
    ],
)
def test_invalid_or_ambiguous_literals_fail_closed(literal: str, reason: str) -> None:
    source = f"select {literal} as value".encode()
    result = normalize_temporal_literals(source, utc_temporal_policy())

    assert result.disposition is TemporalDisposition.BLOCKED
    assert reason in result.blockers[0]
    assert literal not in repr(result)


def test_time_literals_unknown_suffixes_and_missing_or_non_utc_policy_do_not_convert() -> None:
    assert (
        normalize_temporal_literals(
            b"select '12:30:00't as value", utc_temporal_policy()
        ).disposition
        is TemporalDisposition.UNSUPPORTED
    )
    assert (
        normalize_temporal_literals(
            b"select '01JAN2020'dx as value", utc_temporal_policy()
        ).disposition
        is TemporalDisposition.UNSUPPORTED
    )
    assert (
        normalize_temporal_literals(b"select '01JAN2020'd as value", None).disposition
        is TemporalDisposition.BLOCKED
    )

    policy = utc_temporal_policy()
    with pytest.raises(ValueError, match="UTC"):
        replace(policy, source_timezone="America/New_York").validate()


def test_policy_rejects_malformed_enums_targets_and_caller_attestations() -> None:
    payload = utc_temporal_policy().to_dict()
    payload["source_timezone"] = "utc-ish"
    with pytest.raises(ValueError, match="timezone"):
        TemporalPolicy.from_dict(payload)
    payload = utc_temporal_policy().to_dict()
    payload["supported_targets"] = ["sparksql", "spark-ish"]
    with pytest.raises(ValueError, match="target"):
        TemporalPolicy.from_dict(payload)
    payload = utc_temporal_policy().to_dict()
    payload["approved"] = True
    with pytest.raises(ValueError, match="fields"):
        TemporalPolicy.from_dict(payload)


def test_proc_sql_temporal_plan_rewrites_and_binds_policy_and_mapping_identity() -> None:
    source = (
        b"proc sql; select id from members "
        b"where service_date >= '01JAN1960'd "
        b"and service_ts < '02JAN1960:00:00:00.5'dt; quit;"
    )
    policy = utc_temporal_policy()
    plan = plan_rules(source, "sparksql", temporal_policy=policy)

    assert plan.disposition is PlanDisposition.QUALIFIED
    assert plan.temporal_policy_digest == policy.policy_digest
    assert len(plan.temporal_mappings) == 2
    assert {item["literal_kind"] for item in plan.temporal_mappings} == {
        "date",
        "datetime",
    }

    result = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-1",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )
    assert "DATE '1960-01-01'" in result.content
    assert "TIMESTAMP '1960-01-02 00:00:00.5'" in result.content
    mappings = result.metadata["temporal_mappings"]
    assert len({item["mapping_id"] for item in mappings}) == 2
    assert all(item["workload_id"] == "WL-1" for item in mappings)
    assert all(item["generated_sha256"] == result.metadata["generated_sha256"] for item in mappings)
    schema = json.loads(
        (Path(__file__).parents[2] / "schemas" / "sas-temporal-mapping.schema.json").read_text()
    )
    Draft202012Validator(schema).validate({"mappings": mappings})


@pytest.mark.parametrize("target", ["sparksql", "pyspark"])
@pytest.mark.parametrize("quote", ["'", '"'])
@pytest.mark.parametrize(
    ("literal_value", "suffix", "expected_kind", "expected_expression"),
    [
        ("01JAN1960", "d", "date", "DATE '1960-01-01'"),
        (
            "01JAN1960:00:00:00.125000",
            "dt",
            "datetime",
            "TIMESTAMP '1960-01-01 00:00:00.125000'",
        ),
    ],
)
def test_both_sas_quote_forms_are_normalized_with_bound_evidence(
    target: str,
    quote: str,
    literal_value: str,
    suffix: str,
    expected_kind: str,
    expected_expression: str,
) -> None:
    literal = f"{quote}{literal_value}{quote}{suffix}"
    source = f"proc sql; select * from t where x={literal}; quit;".encode()
    plan = plan_rules(source, target, temporal_policy=utc_temporal_policy())

    assert plan.disposition is PlanDisposition.QUALIFIED
    assert len(plan.temporal_mappings) == 1
    mapping = plan.temporal_mappings[0]
    assert mapping["literal_kind"] == expected_kind
    assert mapping["literal_sha256"] == hashlib.sha256(literal.encode()).hexdigest()
    assert source[mapping["byte_start"] : mapping["byte_end"]] == literal.encode()

    result = execute_plan(
        source,
        plan,
        workload_id="WL-QUOTE",
        source_artifact_id="ART-QUOTE",
        run_id="RUN-QUOTE",
        attempt_id="ATT-QUOTE",
    )
    assert expected_expression in result.content
    assert literal not in result.content
    assert (
        result.metadata["temporal_mappings"][0]["source_sha256"]
        == hashlib.sha256(source).hexdigest()
    )


@pytest.mark.parametrize("target", ["sparksql", "pyspark"])
@pytest.mark.parametrize("quote", ["'", '"'])
@pytest.mark.parametrize(
    "literal_value,suffix,policy_present,expected",
    [
        ("01JAN1960", "d", False, PlanDisposition.BLOCKED),
        ("01JAN1960:00:00:00", "dt", False, PlanDisposition.BLOCKED),
        ("12:30:00", "t", False, PlanDisposition.UNSUPPORTED),
        ("12:30:00", "t", True, PlanDisposition.UNSUPPORTED),
    ],
)
def test_both_sas_quote_forms_fail_closed_without_policy_or_for_time_literals(
    target: str,
    quote: str,
    literal_value: str,
    suffix: str,
    policy_present: bool,
    expected: PlanDisposition,
) -> None:
    literal = f"{quote}{literal_value}{quote}{suffix}"
    source = f"proc sql; select * from t where x={literal}; quit;".encode()
    plan = plan_rules(
        source,
        target,
        temporal_policy=utc_temporal_policy() if policy_present else None,
    )

    assert plan.disposition is expected
    assert plan.disposition is not PlanDisposition.QUALIFIED


def test_checked_in_temporal_policy_matches_strict_schema() -> None:
    schema = json.loads(
        (Path(__file__).parents[2] / "schemas" / "sas-temporal-policy.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(utc_temporal_policy().to_dict())


def test_temporal_literal_requires_policy_and_replay_detects_source_change() -> None:
    source = b"proc sql; select * from t where d='01JAN1960'd; quit;"
    blocked = plan_rules(source, "sparksql")
    assert blocked.disposition is PlanDisposition.BLOCKED

    policy = utc_temporal_policy()
    plan = plan_rules(source, "sparksql", temporal_policy=policy)
    with pytest.raises(ValueError, match="no longer matches"):
        execute_plan(
            source.replace(b"01JAN1960", b"02JAN1960"),
            plan,
            workload_id="WL-1",
            source_artifact_id="ART-1",
            run_id="RUN-1",
            attempt_id="ATT-1",
        )


def test_non_temporal_output_is_unchanged() -> None:
    source = b"proc sql; select id from members; quit;"
    plan = plan_rules(source, "sparksql")
    result = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-1",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )
    assert result.content == "select id from members;\n"


def test_identical_literals_in_two_workloads_have_distinct_mapping_identities() -> None:
    source = b"proc sql; select * from t where d='01JAN1960'd; quit;"
    plan = plan_rules(source, "sparksql", temporal_policy=utc_temporal_policy())
    first = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-1",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )
    second = execute_plan(
        source,
        plan,
        workload_id="WL-2",
        source_artifact_id="ART-1",
        run_id="RUN-2",
        attempt_id="ATT-1",
    )
    assert (
        first.metadata["temporal_mappings"][0]["mapping_id"]
        != second.metadata["temporal_mappings"][0]["mapping_id"]
    )
