from smf.assessment.models import DependencySummary, ScoreReason

ADVANCED_PROCS = {
    "PROC LOGISTIC",
    "PROC REG",
    "PROC GLM",
    "PROC MIXED",
    "PROC GENMOD",
    "PROC MODEL",
    "PROC NLMIXED",
    "PROC PHREG",
    "PROC ARIMA",
    "PROC TIMESERIES",
}

HIGH_RISK_CONSTRUCTS = {
    "PROC SQL PASS-THROUGH",
    "CALL SYMPUT",
    "ARRAY",
    "RETAIN",
}


def score_complexity(
    constructs: list[str],
    dependencies: DependencySummary,
) -> tuple[int, list[ScoreReason], list[str], list[str]]:
    score = 0
    reasons: list[ScoreReason] = []
    risk_factors: list[str] = []
    unsupported_constructs: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(ScoreReason(points=points, reason=reason))

    if "PROC SQL" in constructs:
        add(2, "PROC SQL detected")

    if "DATA STEP" in constructs:
        add(2, "DATA step detected")

    if "CREATE TABLE" in constructs:
        add(1, "Creates target table")

    if "JOIN" in constructs:
        add(2, "Join logic detected")

    if "GROUP BY" in constructs:
        add(1, "Grouped aggregation detected")

    aggregate_count = len({"SUM", "COUNT", "AVG", "MIN", "MAX"} & set(constructs))
    if aggregate_count:
        add(aggregate_count, f"{aggregate_count} aggregate function type(s) detected")

    if dependencies.inputs:
        add(min(3, len(dependencies.inputs)), "Input dataset dependencies detected")

    if dependencies.outputs:
        add(min(2, len(dependencies.outputs)), "Output dataset dependencies detected")

    if dependencies.includes:
        add(3, "%INCLUDE dependencies detected")
        risk_factors.append("External SAS include dependency")

    if dependencies.macros_defined:
        add(4, "SAS macro definition detected")
        risk_factors.append("Macro expansion may alter static code path")

    if dependencies.macros_invoked:
        add(2, "Custom macro invocation detected")
        risk_factors.append("Custom macro invocation requires expansion analysis")

    for construct in sorted(set(constructs) & ADVANCED_PROCS):
        add(8, f"Advanced SAS procedure detected: {construct}")
        risk_factors.append(f"Advanced analytics procedure: {construct}")
        unsupported_constructs.append(construct)

    for construct in sorted(set(constructs) & HIGH_RISK_CONSTRUCTS):
        add(4, f"High-risk construct detected: {construct}")
        risk_factors.append(f"High-risk SAS construct: {construct}")

    return (
        score,
        reasons,
        sorted(set(risk_factors)),
        sorted(set(unsupported_constructs)),
    )


def classify_complexity(score: int, unsupported_constructs: list[str]) -> str:
    if unsupported_constructs or score >= 24:
        return "highly_complex"
    if score >= 16:
        return "complex"
    if score >= 9:
        return "moderate"
    return "simple"


def select_route(
    complexity: str,
    unsupported_constructs: list[str],
    risk_factors: list[str],
) -> str:
    if unsupported_constructs or complexity == "highly_complex":
        return "human_supervised"

    if complexity == "complex" or risk_factors:
        return "ai_assisted"

    return "deterministic"


def calculate_confidence(
    complexity: str,
    unsupported_constructs: list[str],
    risk_factors: list[str],
) -> float:
    base = {
        "simple": 0.96,
        "moderate": 0.88,
        "complex": 0.76,
        "highly_complex": 0.58,
    }[complexity]

    base -= min(0.15, len(risk_factors) * 0.03)
    base -= min(0.20, len(unsupported_constructs) * 0.08)

    return round(max(0.0, min(1.0, base)), 2)


def recommended_validation_level(complexity: str) -> int:
    return {
        "simple": 3,
        "moderate": 4,
        "complex": 4,
        "highly_complex": 5,
    }[complexity]
