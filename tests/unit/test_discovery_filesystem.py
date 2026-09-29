from pathlib import Path

from smf.discovery import discover_source
from smf.workload.models import ArtifactKind, EvidenceMethod


def test_filesystem_discovery_inventories_and_classifies(tmp_path: Path) -> None:
    (tmp_path / "jobs").mkdir()
    (tmp_path / "macros").mkdir()
    (tmp_path / "jobs" / "claims.sas").write_text("data work.x; run;\n")
    (tmp_path / "macros" / "common.sas").write_text("%macro common; %mend;\n")
    (tmp_path / "run.sh").write_text("#!/usr/bin/env bash\n")
    (tmp_path / "notes.txt").write_text("business notes\n")

    result = discover_source(tmp_path, provider="filesystem", namespace="test")

    assert result.provider == "filesystem"
    assert result.artifact_count == 4
    assert result.unclassified_count == 1

    artifacts = {artifact.logical_path: artifact for artifact in result.workloads[0].artifacts}
    assert artifacts["jobs/claims.sas"].kind is ArtifactKind.SAS_PROGRAM
    assert artifacts["macros/common.sas"].kind is ArtifactKind.SAS_MACRO
    assert artifacts["run.sh"].kind is ArtifactKind.SHELL_SCRIPT
    assert artifacts["jobs/claims.sas"].checksum
    assert artifacts["jobs/claims.sas"].evidence[0].method is EvidenceMethod.FILESYSTEM


def test_filesystem_workload_identity_survives_different_checkout_roots(
    tmp_path: Path,
) -> None:
    first = tmp_path / "one" / "estate"
    second = tmp_path / "two" / "estate"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "job.sas").write_text("data x; run;\n")
    (second / "job.sas").write_text("data x; run;\n")

    one = discover_source(first, provider="filesystem", namespace="humana")
    two = discover_source(second, provider="filesystem", namespace="humana")

    assert one.workloads[0].workload_id == two.workloads[0].workload_id
