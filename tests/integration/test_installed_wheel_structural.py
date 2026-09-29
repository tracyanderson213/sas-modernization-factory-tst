from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

SCHEMA_NAMES = (
    "dataset-schema-snapshot.schema.json",
    "readiness-input.schema.json",
    "readiness-policy.schema.json",
    "readiness-result.schema.json",
    "pilot-selection-policy.schema.json",
    "pilot-inventory.schema.json",
    "pilot-selection-result.schema.json",
    "batch-intake-manifest.schema.json",
    "batch-intake-policy.schema.json",
    "batch-intake-result.schema.json",
    "architecture-review-packet.schema.json",
    "architecture-review-projection.schema.json",
    "structural-parity-policy.schema.json",
    "structural-parity-result.schema.json",
    "migration-cli-request.schema.json",
    "migration-cli-result.schema.json",
    "migration-cli-telemetry.schema.json",
    "migration-source-snapshot.schema.json",
    "migration-configuration-manifest.schema.json",
)

_COVERAGE_SUBPROCESS_ENV_KEYS = {
    "COVERAGE_FILE",
    "COVERAGE_PROCESS_START",
}


def _subprocess_environment(*, pythonpath: Path | None = None) -> dict[str, str]:
    """Return an environment that does not inherit pytest-cov subprocess tracing.

    This integration test intentionally starts build/install/smoke subprocesses
    outside the repository checkout. pytest-cov 6.x enables subprocess coverage
    through COV_CORE_* environment variables. Letting those subprocesses emit
    coverage data from a temporary cwd can create statement-only data that
    cannot be combined with the repository's branch coverage.

    The parent pytest process still measures this test normally; only the
    packaging subprocesses are excluded from inherited coverage instrumentation.
    """

    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("COV_CORE_") or key in _COVERAGE_SUBPROCESS_ENV_KEYS:
            environment.pop(key, None)
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    if pythonpath is not None:
        environment["PYTHONPATH"] = str(pythonpath)
    return environment


def test_installed_wheel_can_validate_structural_snapshot(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    project = tmp_path / "project"
    project.mkdir()
    shutil.copy2(repository / "pyproject.toml", project / "pyproject.toml")
    shutil.copy2(repository / "README.md", project / "README.md")
    shutil.copytree(
        repository / "src",
        project / "src",
        ignore=shutil.ignore_patterns("__pycache__"),
    )

    for schema_name in SCHEMA_NAMES:
        assert (repository / "schemas" / schema_name).read_bytes() == (
            repository / "src" / "smf" / "schemas" / schema_name
        ).read_bytes()

    wheelhouse = tmp_path / "wheelhouse"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(wheelhouse),
        ],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
        env=_subprocess_environment(),
    )
    wheel = next(wheelhouse.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        packaged_names = set(archive.namelist())
    for schema_name in SCHEMA_NAMES:
        assert f"smf/schemas/{schema_name}" in packaged_names

    installed = tmp_path / "installed"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(installed),
            str(wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=_subprocess_environment(),
    )

    smoke = """
from pathlib import Path
from smf.validation import DatasetSchemaSnapshot, calculate_snapshot_digest
from smf.validation import structural

payload = {
    "schema_version": "1.0",
    "logical_dataset_id": "work.members",
    "engine": "sas",
    "columns": [],
    "provenance": {
        "producer": "wheel-smoke",
        "origin": "installed-wheel",
        "reference": "artifact://wheel-smoke",
        "authoritative": True,
    },
    "metadata": {},
}
payload["digest"] = calculate_snapshot_digest(payload)
snapshot = DatasetSchemaSnapshot.from_dict(payload)
assert snapshot.logical_dataset_id == "work.members"
assert Path(structural.__file__).resolve().is_relative_to(Path(__import__("sys").argv[1]))
"""
    subprocess.run(
        [sys.executable, "-c", smoke, str(installed)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        env=_subprocess_environment(pythonpath=installed),
    )
