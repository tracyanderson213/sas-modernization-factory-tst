from pathlib import Path

from smf.discovery import discover_source
from smf.discovery.sas_data import (
    EndpointResolution,
    characterize_dataset,
    discover_library_bindings,
)
from smf.workload.models import DatasetKind


def test_libname_path_characterizes_sas_library() -> None:
    source = 'libname claims "/data/claims";\ndata out; set claims.members; run;\n'
    bindings = discover_library_bindings(source)
    endpoint = characterize_dataset("claims.members", bindings)

    assert bindings["claims"].engine == "base"
    assert bindings["claims"].location == "/data/claims"
    assert endpoint.kind is DatasetKind.SAS_DATASET
    assert endpoint.system == "claims"
    assert endpoint.location == "/data/claims/members"
    assert endpoint.metadata["resolution"] == EndpointResolution.RESOLVED.value


def test_database_libname_characterizes_external_table_and_redacts_password() -> None:
    source = (
        "libname wh odbc dsn='EDW' user='svc_sas' password='secret' schema='CLAIMS';\n"
        "proc sql; create table work.out as select * from wh.claims; quit;\n"
    )
    bindings = discover_library_bindings(source)
    endpoint = characterize_dataset("wh.claims", bindings)

    assert endpoint.kind is DatasetKind.DATABASE_TABLE
    assert endpoint.system == "odbc"
    assert endpoint.location == "wh.claims"
    options = endpoint.metadata["connection_options"]
    assert isinstance(options, dict)
    assert options["dsn"] == "EDW"
    assert options["schema"] == "CLAIMS"
    assert options["password"] == "<redacted>"


def test_unknown_libref_remains_unresolved_instead_of_being_guessed() -> None:
    endpoint = characterize_dataset("mystery.members", {})

    assert endpoint.kind is DatasetKind.SAS_DATASET
    assert endpoint.system == "mystery"
    assert endpoint.metadata["resolution"] == EndpointResolution.UNRESOLVED.value


def test_unqualified_dataset_is_work_intermediate() -> None:
    endpoint = characterize_dataset("stage", {})

    assert endpoint.kind is DatasetKind.INTERMEDIATE
    assert endpoint.system == "work"


def test_filesystem_discovery_enriches_sources_and_outputs(tmp_path: Path) -> None:
    sas = tmp_path / "claims.sas"
    sas.write_text(
        "libname wh odbc dsn='EDW' schema='CLAIMS';\n"
        "libname mart '/sas/mart';\n"
        "data mart.summary; set wh.claims; run;\n"
        "data staged; set mart.summary; run;\n",
        encoding="utf-8",
    )

    result = discover_source(tmp_path, provider="filesystem", namespace="test")
    datasets = {dataset.name: dataset for dataset in result.workloads[0].datasets}

    assert datasets["wh.claims"].kind is DatasetKind.DATABASE_TABLE
    assert datasets["wh.claims"].system == "odbc"
    assert datasets["mart.summary"].kind is DatasetKind.SAS_DATASET
    assert datasets["mart.summary"].location == "/sas/mart/summary"
    assert datasets["work.staged"].kind is DatasetKind.INTERMEDIATE
    assert datasets["work.staged"].system == "work"
