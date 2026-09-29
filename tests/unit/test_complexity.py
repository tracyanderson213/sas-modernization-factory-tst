from smf.assessment.complexity import (
    calculate_confidence,
    classify_complexity,
    recommended_validation_level,
    score_complexity,
    select_route,
)
from smf.assessment.models import DependencySummary


def test_simple_sql_routes_deterministically() -> None:
    constructs = ["CREATE TABLE", "GROUP BY", "PROC SQL", "SELECT", "SUM"]
    dependencies = DependencySummary(
        inputs=["work.source"],
        outputs=["work.output"],
    )

    score, _reasons, risks, unsupported = score_complexity(
        constructs,
        dependencies,
    )
    complexity = classify_complexity(score, unsupported)

    assert complexity == "simple"
    assert select_route(complexity, unsupported, risks) == "deterministic"
    assert recommended_validation_level(complexity) == 3
    assert calculate_confidence(complexity, unsupported, risks) >= 0.90


def test_macro_workload_requires_ai_assistance() -> None:
    constructs = ["MACRO DEFINITION", "PROC SQL"]
    dependencies = DependencySummary(
        macros_defined=["build_report"],
    )

    score, _reasons, risks, unsupported = score_complexity(
        constructs,
        dependencies,
    )
    complexity = classify_complexity(score, unsupported)

    assert risks
    assert select_route(complexity, unsupported, risks) == "ai_assisted"


def test_advanced_proc_routes_to_human() -> None:
    constructs = ["PROC LOGISTIC"]
    dependencies = DependencySummary()

    score, _reasons, risks, unsupported = score_complexity(
        constructs,
        dependencies,
    )
    complexity = classify_complexity(score, unsupported)

    assert complexity == "highly_complex"
    assert "PROC LOGISTIC" in unsupported
    assert risks
    assert select_route(complexity, unsupported, risks) == "human_supervised"
    assert recommended_validation_level(complexity) == 5
