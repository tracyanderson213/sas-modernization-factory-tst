from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/project-tools/repository-hygiene.py"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("repository_hygiene", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_backlog_association_is_boundary_aware() -> None:
    module = _module()
    keys = {"DP-02", "DP-03", "TASK-2"}
    assert module._associated_keys("agent/dp-02-v1", keys=keys) == ["DP-02"]
    assert module._associated_keys("agent/dp-020-v1", keys=keys) == []


def test_ownership_check_detects_overlap(tmp_path: Path) -> None:
    module = _module()
    ownership = tmp_path / "ownership.yaml"
    ownership.write_text(
        """assignments:
- work_id: A
  files: [src/smf/validation/]
- work_id: B
  files: [src/smf/validation/row_count.py]
""",
        encoding="utf-8",
    )
    result = module._ownership_findings(ownership)
    assert result["available"] is True
    assert result["overlapping_paths"] == [
        {
            "work_id": "B",
            "path": "src/smf/validation/row_count.py",
            "conflicts_with": "A",
            "conflicting_path": "src/smf/validation/",
        }
    ]


def test_ownership_check_detects_glob_and_literal_overlap(tmp_path: Path) -> None:
    module = _module()
    ownership = tmp_path / "ownership.yaml"
    ownership.write_text(
        """assignments:
- work_id: A
  files: [src/smf/validation/*.py]
- work_id: B
  files: [src/smf/validation/row_count.py]
""",
        encoding="utf-8",
    )
    result = module._ownership_findings(ownership)
    assert result["overlapping_paths"] == [
        {
            "work_id": "B",
            "path": "src/smf/validation/row_count.py",
            "conflicts_with": "A",
            "conflicting_path": "src/smf/validation/*.py",
        }
    ]


def test_status_path_handles_rename() -> None:
    module = _module()
    assert module._status_path(" M docs/CLI.md") == "docs/CLI.md"
    assert module._status_path("R  old.md -> docs/new.md") == "docs/new.md"
