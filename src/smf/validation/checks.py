from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from smf.validation.models import ValidationCheck

SAS_REMAINDER_PATTERNS: dict[str, re.Pattern[str]] = {
    "PROC statement": re.compile(r"\bproc\s+[a-zA-Z_]", re.IGNORECASE),
    "QUIT statement": re.compile(r"\bquit\s*;", re.IGNORECASE),
    "macro definition": re.compile(r"%macro\b", re.IGNORECASE),
    "macro end": re.compile(r"%mend\b", re.IGNORECASE),
    "SAS include": re.compile(r"%include\b", re.IGNORECASE),
}

MANUAL_REVIEW_PATTERNS: dict[str, re.Pattern[str]] = {
    "manual review marker": re.compile(r"MANUAL REVIEW", re.IGNORECASE),
    "review marker": re.compile(r"\[REVIEW\]", re.IGNORECASE),
    "low-confidence conversion": re.compile(
        r"\bconf(?:idence)?\s*=\s*0\.[0-6]\d*",
        re.IGNORECASE,
    ),
    "pending host fulfillment": re.compile(
        r"pending host fulfillment",
        re.IGNORECASE,
    ),
}


def check_generated_nonempty(generated_file: Path) -> ValidationCheck:
    content = generated_file.read_text(encoding="utf-8")
    if content.strip():
        return ValidationCheck(
            check_id="VAL-STATIC-001",
            name="Generated artifact is non-empty",
            status="pass",
            message="Generated artifact contains content.",
            weight=3,
            evidence={"characters": len(content)},
        )

    return ValidationCheck(
        check_id="VAL-STATIC-001",
        name="Generated artifact is non-empty",
        status="fail",
        message="Generated artifact is empty.",
        weight=3,
    )


def check_python_syntax(generated_file: Path, target: str) -> ValidationCheck:
    if target.lower() not in {"pyspark", "python"} and generated_file.suffix != ".py":
        return ValidationCheck(
            check_id="VAL-STATIC-002",
            name="Python syntax",
            status="not_applicable",
            message="Target is not Python/PySpark.",
            weight=3,
        )

    content = generated_file.read_text(encoding="utf-8")
    try:
        ast.parse(content)
    except SyntaxError as exc:
        return ValidationCheck(
            check_id="VAL-STATIC-002",
            name="Python syntax",
            status="fail",
            message=f"Generated Python does not parse: {exc.msg}",
            weight=3,
            evidence={
                "line": exc.lineno,
                "offset": exc.offset,
            },
        )

    return ValidationCheck(
        check_id="VAL-STATIC-002",
        name="Python syntax",
        status="pass",
        message="Generated Python parses successfully.",
        weight=3,
    )


def check_sql_shape(generated_file: Path, target: str) -> ValidationCheck:
    if target.lower() not in {"sparksql", "sql"} and generated_file.suffix != ".sql":
        return ValidationCheck(
            check_id="VAL-STATIC-003",
            name="Spark SQL shape",
            status="not_applicable",
            message="Target is not Spark SQL.",
            weight=2,
        )

    content = generated_file.read_text(encoding="utf-8")
    if re.search(r"\b(select|create|insert|merge|with)\b", content, re.IGNORECASE):
        return ValidationCheck(
            check_id="VAL-STATIC-003",
            name="Spark SQL shape",
            status="pass",
            message="Generated SQL contains a recognizable SQL statement.",
            weight=2,
        )

    return ValidationCheck(
        check_id="VAL-STATIC-003",
        name="Spark SQL shape",
        status="warning",
        message="Generated SQL does not contain a recognizable top-level SQL statement.",
        weight=2,
    )


def check_sas_remainders(generated_file: Path) -> ValidationCheck:
    content = generated_file.read_text(encoding="utf-8")
    matches = [
        label for label, pattern in SAS_REMAINDER_PATTERNS.items() if pattern.search(content)
    ]

    if not matches:
        return ValidationCheck(
            check_id="VAL-STATIC-004",
            name="Residual SAS syntax",
            status="pass",
            message="No obvious SAS-only syntax remains in the generated artifact.",
            weight=3,
        )

    return ValidationCheck(
        check_id="VAL-STATIC-004",
        name="Residual SAS syntax",
        status="fail",
        message="Generated artifact still contains SAS-only syntax.",
        weight=3,
        evidence={"matches": matches},
    )


def check_manual_review_markers(generated_file: Path) -> ValidationCheck:
    content = generated_file.read_text(encoding="utf-8")
    matches = [
        label for label, pattern in MANUAL_REVIEW_PATTERNS.items() if pattern.search(content)
    ]

    if not matches:
        return ValidationCheck(
            check_id="VAL-REVIEW-001",
            name="Conversion review markers",
            status="pass",
            message="No converter-emitted manual-review markers detected.",
            weight=4,
        )

    return ValidationCheck(
        check_id="VAL-REVIEW-001",
        name="Conversion review markers",
        status="warning",
        message="Converter emitted one or more manual-review indicators.",
        weight=4,
        evidence={"matches": matches},
    )


def check_assessment_risk(assessment: dict[str, Any]) -> ValidationCheck:
    unsupported = list(assessment.get("unsupported_constructs", []))
    risk_factors = list(assessment.get("risk_factors", []))

    if unsupported:
        return ValidationCheck(
            check_id="VAL-RISK-001",
            name="Assessment risk gate",
            status="warning",
            message="Source assessment contains unsupported constructs.",
            weight=4,
            evidence={
                "unsupported_constructs": unsupported,
                "risk_factors": risk_factors,
            },
        )

    if risk_factors:
        return ValidationCheck(
            check_id="VAL-RISK-001",
            name="Assessment risk gate",
            status="warning",
            message="Source assessment contains risk factors requiring enhanced validation.",
            weight=4,
            evidence={"risk_factors": risk_factors},
        )

    return ValidationCheck(
        check_id="VAL-RISK-001",
        name="Assessment risk gate",
        status="pass",
        message="No assessment-level blockers detected.",
        weight=4,
    )


def _normalized_name(name: str) -> str:
    return name.lower().replace(".", "_")


def check_dependency_traceability(
    generated_file: Path,
    assessment: dict[str, Any],
) -> ValidationCheck:
    dependencies = assessment.get("dependencies", {})
    if not isinstance(dependencies, dict):
        dependencies = {}

    input_names = [str(value) for value in dependencies.get("inputs", [])]
    output_names = [str(value) for value in dependencies.get("outputs", [])]
    names = input_names + output_names

    if not names:
        return ValidationCheck(
            check_id="VAL-TRACE-001",
            name="Dependency traceability",
            status="not_applicable",
            message="Assessment did not identify source or target datasets.",
            weight=2,
        )

    content = generated_file.read_text(encoding="utf-8").lower()
    missing: list[str] = []

    for name in names:
        variants = {
            name.lower(),
            _normalized_name(name),
            name.split(".")[-1].lower(),
        }
        if not any(variant in content for variant in variants):
            missing.append(name)

    if not missing:
        return ValidationCheck(
            check_id="VAL-TRACE-001",
            name="Dependency traceability",
            status="pass",
            message="Assessed dataset dependencies are traceable in generated code.",
            weight=2,
            evidence={"dependencies": names},
        )

    return ValidationCheck(
        check_id="VAL-TRACE-001",
        name="Dependency traceability",
        status="warning",
        message="Some assessed dataset dependencies are not textually traceable.",
        weight=2,
        evidence={
            "dependencies": names,
            "missing": missing,
        },
    )
