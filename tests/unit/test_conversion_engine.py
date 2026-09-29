from pathlib import Path
from unittest.mock import patch

import pytest

from smf.conversion.engine import convert_workload
from smf.conversion.models import ConversionRequest


def test_conversion_without_readiness_context_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="deployment readiness binding is required"),
    ):
        convert_workload(ConversionRequest(source_file=source, output_dir=tmp_path / "out"))
    provider.assert_not_called()


def test_missing_source_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.sas"
    try:
        convert_workload(ConversionRequest(source_file=missing))
    except FileNotFoundError:
        return
    raise AssertionError("Expected FileNotFoundError")
