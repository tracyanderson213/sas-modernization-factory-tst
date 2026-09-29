from pathlib import Path

from smf.validation.checks import check_manual_review_markers


def test_manual_review_marker_produces_warning(tmp_path: Path) -> None:
    generated = tmp_path / "generated.py"
    generated.write_text(
        "# [REVIEW] pending host fulfillment\nvalue = 1\n",
        encoding="utf-8",
    )

    result = check_manual_review_markers(generated)

    assert result.status == "warning"
    assert result.evidence["matches"]


def test_clean_generated_code_passes_review_marker_check(tmp_path: Path) -> None:
    generated = tmp_path / "generated.py"
    generated.write_text("value = 1\n", encoding="utf-8")

    result = check_manual_review_markers(generated)

    assert result.status == "pass"
