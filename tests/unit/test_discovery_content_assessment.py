import json
from pathlib import Path

from smf.discovery import discover_source
from smf.workload.models import ArtifactKind, EvidenceMethod


def test_content_assessment_inventory_is_auto_detected(tmp_path: Path) -> None:
    preview = tmp_path / "assessment" / "preview" / "inventory" / "CSV"
    preview.mkdir(parents=True)
    (preview / "objects.csv").write_text(
        "SERVER_LABEL,Name,TypeName,Path,StorageType\n"
        "SAS1,claims.sas,SAS Program,/sas/jobs/claims.sas,FileSystem\n"
        "SAS1,Daily Claims,SAS Data Integration Studio Job,/Jobs/Daily Claims,Metadata\n"
    )
    (preview / "servers.csv").write_text("Name,Type\nSAS1,Workspace\n")
    (preview / "deployments.csv").write_text("Product,Version\nBase SAS,9.4M8\n")

    result = discover_source(tmp_path, provider="auto", namespace="test")

    assert result.provider == "sas-content-assessment"
    assert result.artifact_count == 2

    workload = result.workloads[0]
    by_name = {artifact.name: artifact for artifact in workload.artifacts}
    assert by_name["claims.sas"].kind is ArtifactKind.SAS_PROGRAM
    assert by_name["Daily Claims"].kind is ArtifactKind.SCHEDULER_JOB
    assert by_name["claims.sas"].evidence[0].method is EvidenceMethod.RUNTIME_METADATA
    assert workload.metadata["assessment_metadata"]["deployments"][0]["version"] == "9.4M8"


def test_explicit_content_assessment_provider_requires_objects_csv(
    tmp_path: Path,
) -> None:
    try:
        discover_source(tmp_path, provider="sas-content-assessment")
    except ValueError as exc:
        assert "objects.csv" in str(exc)
    else:
        raise AssertionError("Expected missing Content Assessment inventory to fail")


def test_content_assessment_nested_rows_are_sanitized(tmp_path: Path) -> None:
    preview = tmp_path / "assessment" / "preview" / "inventory" / "CSV"
    preview.mkdir(parents=True)
    (preview / "objects.csv").write_text(
        "Name,TypeName,Path,DB_PASSWORD,Command\n"
        "claims.sas,SAS Program,/sas/jobs/claims.sas,object-canary,"
        '"sas -sysin claims.sas --api-key command-canary"\n'
    )
    (preview / "servers.csv").write_text(
        "Name,ConnectionString\nwarehouse,"
        '"Server=db.example;Password=server-canary;Database=claims"\n'
    )
    (preview / "deployments.csv").write_text("Product,AUTH_TOKEN\nBase SAS,deployment-canary\n")

    result = discover_source(tmp_path, provider="sas-content-assessment", namespace="test")
    serialized = json.dumps(result.to_dict())

    assert not any(
        secret in serialized
        for secret in (
            "object-canary",
            "command-canary",
            "server-canary",
            "deployment-canary",
        )
    )
    assert "db.example" in serialized
    assert "Database=claims" in serialized
    assert "claims.sas" in serialized
