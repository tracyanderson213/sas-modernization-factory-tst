from smf.validation.models import ValidationCheck
from smf.validation.scoring import (
    calculate_validation_confidence,
    has_blocking_failure,
)


def test_all_pass_scores_one() -> None:
    checks = [
        ValidationCheck("A", "a", "pass", "ok", weight=2),
        ValidationCheck("B", "b", "pass", "ok", weight=3),
    ]

    assert calculate_validation_confidence(checks) == 1.0
    assert has_blocking_failure(checks) is False


def test_warning_reduces_score() -> None:
    checks = [
        ValidationCheck("A", "a", "pass", "ok", weight=2),
        ValidationCheck("B", "b", "warning", "warn", weight=2),
    ]

    assert calculate_validation_confidence(checks) == 0.75


def test_failure_is_blocking() -> None:
    checks = [
        ValidationCheck("A", "a", "fail", "bad", weight=3),
    ]

    assert has_blocking_failure(checks) is True
    assert calculate_validation_confidence(checks) == 0.0
