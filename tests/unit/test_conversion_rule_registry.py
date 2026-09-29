from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from smf.conversion.registry import (
    DEFAULT_REGISTRY,
    Applicability,
    ConstructFamily,
    PlanDisposition,
    RuleType,
    build_registry,
    execute_plan,
    plan_rules,
)


def test_registry_is_versioned_qualified_and_reconstructable() -> None:
    snapshot = DEFAULT_REGISTRY.snapshot()

    assert snapshot["registry_id"] == "smf.deterministic.proc_sql"
    assert len(snapshot["registry_digest"]) == 64
    assert {rule["construct_family"] for rule in snapshot["rules"]} >= {
        "proc_sql",
        "select",
        "join",
        "aggregate",
        "ctas",
    }
    assert all(rule["supported_semantics"] for rule in snapshot["rules"])
    assert all(rule["unsupported_cases"] for rule in snapshot["rules"])
    assert all(rule["fixture_qualifications"] for rule in snapshot["rules"])
    assert all(len(rule["descriptor_digest"]) == 64 for rule in snapshot["rules"])
    assert len(snapshot["qualification_evidence"]) == len(snapshot["rules"])
    assert all(item["result"] == "passed" for item in snapshot["qualification_evidence"])
    assert all(len(item["result_digest"]) == 64 for item in snapshot["qualification_evidence"])


def test_positive_select_join_and_aggregate_emit_exact_application_evidence() -> None:
    source = (
        b"proc sql;\nselect a.member_id, count(*) as visits\n"
        b"from source.members a left join source.visits b on a.member_id=b.member_id\n"
        b"where a.active=1 group by a.member_id order by a.member_id;\nquit;\n"
    )
    plan = plan_rules(source, "sparksql")

    assert plan.disposition is PlanDisposition.QUALIFIED
    assert {item["rule_id"] for item in plan.selected_rules} == {
        "smf.proc_sql.envelope",
        "smf.proc_sql.select",
        "smf.proc_sql.join",
        "smf.proc_sql.aggregate",
    }
    result = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-1",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )
    assert result.content.startswith("select a.member_id")
    assert (
        hashlib.sha256(result.content.encode()).hexdigest() == result.metadata["generated_sha256"]
    )
    applications = result.metadata["applications"]
    assert len(applications) == 4
    assert all(item["workload_id"] == "WL-1" for item in applications)
    assert all(item["run_id"] == "RUN-1" and item["attempt_id"] == "ATT-1" for item in applications)
    assert all(item["input_sha256"] == plan.statement_sha256 for item in applications)
    assert all(item["applicability"] == Applicability.APPLICABLE for item in applications)


@pytest.mark.parametrize(
    ("source", "family"),
    [
        (b"", "proc_sql"),
        (b"   \n", "proc_sql"),
        (b"/* proc sql; select 1; quit; */", "proc_sql"),
        (b"proc format; value x 1='one'; run;", "proc_format"),
        (b"%macro x; proc sql; select 1; quit; %mend;", "sas_macro_processor"),
        (b"proc sql; select {{ column }} from t; quit;", "target_template"),
        (b"proc sql; connect to odbc(x); select 1; quit;", "proc_sql"),
        (b"proc sql; select mystery(x) from t; quit;", None),
        (b"proc sql; select 1; select 2; quit;", None),
    ],
)
def test_unsupported_constructs_never_fall_through(source: bytes, family: str | None) -> None:
    plan = plan_rules(source, "sparksql")

    assert plan.disposition is PlanDisposition.UNSUPPORTED
    assert plan.selected_rules == ()
    if family is not None:
        assert family in {item["construct_family"] for item in plan.observations}


def test_comment_only_false_entrypoint_and_secret_canary_fail_closed() -> None:
    comment = plan_rules(b"/* harmless note; data fake; run; */", "sparksql")
    secret = plan_rules(b"proc sql; select 'secret-canary-123' as x; quit;", "sparksql")

    assert comment.disposition is PlanDisposition.UNSUPPORTED
    assert secret.disposition is PlanDisposition.BLOCKED
    assert b"secret-canary-123" not in repr(secret.to_dict()).encode()


def test_ctas_requires_authoritative_mapping() -> None:
    source = b"proc sql; create table out.members as select * from in.members; quit;"

    blocked = plan_rules(source, "sparksql")

    assert blocked.disposition is PlanDisposition.BLOCKED
    assert blocked.selected_rules == ()
    assert "mapping" in blocked.blockers[0]


def test_unknown_enums_versions_duplicates_and_overlaps_are_rejected() -> None:
    original = DEFAULT_REGISTRY.rules[0]
    with pytest.raises(ValueError, match="duplicate"):
        build_registry((original, original))
    with pytest.raises(ValueError, match="version"):
        build_registry((replace(original, version="latest"),))
    with pytest.raises(ValueError, match="unknown target"):
        build_registry((replace(original, target="spark-ish"),))
    with pytest.raises(ValueError, match="unknown enum"):
        build_registry((replace(original, construct_family="proc-sq1"),))  # type: ignore[arg-type]
    overlapping = replace(original, rule_id="smf.proc_sql.other")
    with pytest.raises(ValueError, match="overlapping composition"):
        build_registry((original, overlapping))


def test_rule_change_without_version_requires_requalification() -> None:
    selected_rule = next(
        rule
        for rule in DEFAULT_REGISTRY.rules
        if rule.rule_id == "smf.proc_sql.select" and rule.target == "sparksql"
    )
    changed = replace(
        selected_rule,
        supported_semantics=("weakened mutation",),
    )
    with pytest.raises(ValueError, match="qualification"):
        build_registry(
            tuple(
                changed
                if rule.rule_id == changed.rule_id and rule.target == changed.target
                else rule
                for rule in DEFAULT_REGISTRY.rules
            )
        )


@pytest.mark.parametrize("target", ["spark-sql", "SPARKSQL", ""])
def test_unknown_target_cannot_bypass_planning(target: str) -> None:
    with pytest.raises(ValueError, match="Unknown"):
        plan_rules(b"proc sql; select 1; quit;", target)


def test_pyspark_generation_is_distinct_but_not_execution_or_parity_evidence() -> None:
    source = b"proc sql; select 1; quit;"
    plan = plan_rules(source, "pyspark")
    result = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-1",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )

    assert result.content == 'spark.sql("""select 1;""")\n'
    assert "validated" not in result.metadata
    assert "parity_passed" not in result.metadata


def test_construct_families_remain_explicitly_distinct() -> None:
    assert ConstructFamily.PROC_FORMAT != ConstructFamily.SAS_MACRO
    assert ConstructFamily.SAS_MACRO != ConstructFamily.TARGET_TEMPLATE
    assert RuleType.ENVELOPE != RuleType.STATEMENT


@pytest.mark.parametrize(
    "clause",
    [
        "select id from a union select id from b",
        "select id, count(*) from a group by id having count(*) > 1",
        "select id into :chosen_id from a",
        "select calculated total from a",
        "select case when active=1 then 'Y' else 'N' end from a",
        "select id from a intersect select id from b",
        "select id from a except select id from b",
        "select id from a qualify row_number() over (partition by id)=1",
        "select id from a limit 1",
        "select id from a offset 1 rows",
        "select id from (select id from a) nested",
        "select id from members where event_time = '12:30:00't",
    ],
)
def test_unqualified_sql_grammar_never_emits_a_plausible_rewrite(clause: str) -> None:
    source = f"proc sql; {clause}; quit;".encode()

    plan = plan_rules(source, "sparksql")

    assert plan.disposition is PlanDisposition.UNSUPPORTED
    assert plan.selected_rules == ()
    with pytest.raises(ValueError, match="qualified"):
        execute_plan(
            source,
            plan,
            workload_id="WL-1",
            source_artifact_id="ART-1",
            run_id="RUN-1",
            attempt_id="ATT-1",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"version": "2.0.0", "fixture_qualifications": ("trust-me",)},
        {
            "supported_semantics": ("silently widened semantics",),
            "fixture_qualifications": ("cv01-proc-sql-positive", "cv01-proc-sql-negative"),
        },
        {
            "unsupported_cases": ("invented qualification",),
            "fixture_qualifications": ("stale-descriptor-reference",),
        },
    ],
)
def test_rule_qualification_is_package_owned_and_descriptor_bound(
    mutation: dict[str, object],
) -> None:
    original = DEFAULT_REGISTRY.rules[0]

    with pytest.raises(ValueError, match="qualification"):
        build_registry((replace(original, **mutation),))


def test_two_active_rule_revisions_are_rejected_even_at_distinct_positions() -> None:
    original = next(
        rule
        for rule in DEFAULT_REGISTRY.rules
        if rule.rule_id == "smf.proc_sql.select" and rule.target == "sparksql"
    )
    competing = replace(original, version="2.0.0", composition_order=999)

    with pytest.raises(ValueError, match="active revision"):
        build_registry((original, competing))


def test_application_identity_binds_exact_source_artifact() -> None:
    source = b"proc sql; select 1; quit;"
    plan = plan_rules(source, "sparksql")

    first = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-A",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )
    second = execute_plan(
        source,
        plan,
        workload_id="WL-1",
        source_artifact_id="ART-B",
        run_id="RUN-1",
        attempt_id="ATT-1",
    )

    first_ids = {item["application_id"] for item in first.metadata["applications"]}
    second_ids = {item["application_id"] for item in second.metadata["applications"]}
    assert first_ids.isdisjoint(second_ids)


@pytest.mark.parametrize(
    "status",
    [
        "converted",
        "review_required",
        "failed",
        "unsupported",
        "blocked",
        "human_pending",
        "human_denied",
    ],
)
def test_conversion_schema_accepts_every_emitted_terminal_status(status: str) -> None:
    schema_path = Path(__file__).parents[2] / "schemas" / "conversion-manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    deterministic = status != "review_required"
    disposition = (
        status
        if status
        in {
            "unsupported",
            "blocked",
            "human_pending",
            "human_denied",
        }
        else "qualified"
    )
    manifest = {
        "source_file": "artifact:ART-1",
        "target": "sparksql",
        "route": "deterministic",
        "provider": "smf-deterministic" if deterministic else "sas2databricks",
        "status": status,
        "output_files": [],
        "warnings": [],
        "metadata": {
            "rule_plan": {"disposition": disposition},
            "telemetry": {
                "generated": status == "converted",
                "executed": False,
                "validated": False,
                "parity_passed": False,
                "certified": False,
                "human_assisted": False,
                "human_pending": status == "human_pending",
                "human_denied": status == "human_denied",
                "blocked": status == "blocked",
                "unsupported": status == "unsupported",
                "failed": status == "failed",
            },
        },
    }
    if not deterministic:
        manifest["metadata"] = {}

    Draft202012Validator(schema).validate(manifest)


def test_conversion_schema_rejects_unknown_status_and_unbound_deterministic_evidence() -> None:
    schema_path = Path(__file__).parents[2] / "schemas" / "conversion-manifest.schema.json"
    validator = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    manifest = {
        "source_file": "artifact:ART-1",
        "target": "sparksql",
        "route": "deterministic",
        "provider": "smf-deterministic",
        "status": "convertedish",
        "output_files": [],
        "warnings": [],
        "metadata": {},
    }

    with pytest.raises(ValidationError):
        validator.validate(manifest)
    manifest["status"] = "blocked"
    with pytest.raises(ValidationError):
        validator.validate(manifest)
