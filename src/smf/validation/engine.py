from __future__ import annotations

from smf.assessment.analyzer import assess_sas_file
from smf.validation.checks import (
    check_assessment_risk,
    check_dependency_traceability,
    check_generated_nonempty,
    check_manual_review_markers,
    check_python_syntax,
    check_sas_remainders,
    check_sql_shape,
)
from smf.validation.manifest import write_validation_manifest
from smf.validation.models import (
    ValidationRequest,
    ValidationResult,
    ValidationStatus,
)
from smf.validation.schema import validate_result_schema
from smf.validation.scoring import calculate_validation_confidence, has_blocking_failure


def validate_conversion(request: ValidationRequest) -> ValidationResult:
    if not request.source_file.exists():
        raise FileNotFoundError(request.source_file)

    if not request.generated_file.exists():
        raise FileNotFoundError(request.generated_file)

    assessment = assess_sas_file(str(request.source_file))

    checks = [
        check_generated_nonempty(request.generated_file),
        check_python_syntax(request.generated_file, request.target),
        check_sql_shape(request.generated_file, request.target),
        check_sas_remainders(request.generated_file),
        check_manual_review_markers(request.generated_file),
        check_assessment_risk(assessment),
        check_dependency_traceability(request.generated_file, assessment),
    ]

    confidence = calculate_validation_confidence(checks)
    blocking_failure = has_blocking_failure(checks)
    unsupported = bool(assessment.get("unsupported_constructs"))
    assessment_route = str(assessment.get("automation_route", "human_supervised"))
    review_marker_warning = any(
        check.check_id == "VAL-REVIEW-001" and check.status == "warning" for check in checks
    )

    warnings = [check.message for check in checks if check.status == "warning"]

    requires_human_review = (
        blocking_failure
        or unsupported
        or assessment_route == "human_supervised"
        or review_marker_warning
        or confidence < request.minimum_confidence
    )

    status: ValidationStatus
    if blocking_failure:
        status = "failed"
    elif requires_human_review:
        status = "human_review"
    elif warnings:
        status = "warning"
    else:
        status = "passed"

    workload_dir = request.output_dir / request.source_file.stem / "validation"

    result = ValidationResult(
        source_file=str(request.source_file),
        generated_file=str(request.generated_file),
        target=request.target,
        status=status,
        confidence=confidence,
        requires_human_review=requires_human_review,
        checks=checks,
        warnings=warnings,
        metadata={
            "assessment": assessment,
            "minimum_confidence": request.minimum_confidence,
        },
    )

    payload = result.to_dict()
    validate_result_schema(payload)

    manifest = write_validation_manifest(workload_dir, payload)
    result.output_files.append(str(manifest))

    return result
