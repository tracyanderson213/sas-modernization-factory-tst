from __future__ import annotations

from smf.validation.models import ValidationCheck


def calculate_validation_confidence(checks: list[ValidationCheck]) -> float:
    applicable = [check for check in checks if check.status != "not_applicable"]
    if not applicable:
        return 0.0

    max_score = sum(check.weight for check in applicable)
    if max_score <= 0:
        return 0.0

    earned = 0.0
    for check in applicable:
        if check.status == "pass":
            earned += check.weight
        elif check.status == "warning":
            earned += check.weight * 0.5

    return round(earned / max_score, 2)


def has_blocking_failure(checks: list[ValidationCheck]) -> bool:
    return any(check.status == "fail" for check in checks)
