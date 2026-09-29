import hashlib
from pathlib import Path
from typing import Any

from smf.assessment.complexity import (
    calculate_confidence,
    classify_complexity,
    recommended_validation_level,
    score_complexity,
    select_route,
)
from smf.assessment.constructs import detect_constructs
from smf.assessment.dependencies import extract_dependencies
from smf.assessment.models import AssessmentResult
from smf.assessment.schema import validate_assessment


def _workload_id(source_path: Path) -> str:
    digest = hashlib.sha256(str(source_path.resolve()).encode("utf-8")).hexdigest()
    numeric = int(digest[:12], 16) % 1_000_000
    return f"SMF-{numeric:06d}"


def assess_sas_file(path: str) -> dict[str, Any]:
    source_path = Path(path)

    if not source_path.exists():
        raise FileNotFoundError(f"SAS file not found: {path}")

    if not source_path.is_file():
        raise ValueError(f"SAS workload path is not a file: {path}")

    source = source_path.read_text(encoding="utf-8")

    constructs = detect_constructs(source)
    dependencies = extract_dependencies(source)
    score, breakdown, risk_factors, unsupported_constructs = score_complexity(
        constructs=constructs,
        dependencies=dependencies,
    )

    complexity = classify_complexity(score, unsupported_constructs)
    route = select_route(complexity, unsupported_constructs, risk_factors)
    confidence = calculate_confidence(
        complexity,
        unsupported_constructs,
        risk_factors,
    )

    result = AssessmentResult(
        workload_id=_workload_id(source_path),
        source_file=str(source_path),
        complexity=complexity,
        complexity_score=score,
        automation_route=route,
        confidence=confidence,
        sas_constructs=constructs,
        dependencies=dependencies,
        risk_factors=risk_factors,
        unsupported_constructs=unsupported_constructs,
        recommended_validation_level=recommended_validation_level(complexity),
        score_breakdown=breakdown,
    )

    payload = result.to_dict()
    validate_assessment(payload)
    return payload
