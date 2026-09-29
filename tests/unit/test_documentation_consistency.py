from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "competition/SEPTEMBER-27-DEADLINE-DASHBOARD.md"


def test_documentation_consistency_check_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check-documentation-consistency.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "documentation consistency: PASS" in result.stdout


def test_dashboard_active_records_are_machine_readable_and_not_completed() -> None:
    text = DASHBOARD.read_text(encoding="utf-8")
    match = re.search(r"<!-- smf-doc-status: (\{.*\}) -->", text)
    assert match is not None
    metadata = json.loads(match.group(1))
    active_block = text.split("<!-- active-day1:begin -->", 1)[1].split(
        "<!-- active-day1:end -->", 1
    )[0]
    active_rows = sorted(
        set(re.findall(r"^\| `([A-Z0-9-]+)` \|", active_block, flags=re.MULTILINE))
    )
    assert active_rows == sorted(metadata["active_records"])
    assert not set(metadata["active_records"]) & set(metadata["completed_records"])
