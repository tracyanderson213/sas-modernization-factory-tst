from __future__ import annotations

import json
from pathlib import Path

from smf.discovery import discover_source
from smf.discovery.external_dependencies import (
    discover_sas_external_dependencies,
    discover_shell_external_dependencies,
)
from smf.workload.models import ExternalDependencyKind, RelationshipKind


def test_sas_connection_inventory_redacts_credentials_and_preserves_connection_identity() -> None:
    source = (
        "libname wh odbc dsn='EDW' server='db01' schema='CLAIMS' "
        "user='svc_sas' password='TOP_SECRET';\n"
        "data work.out; set wh.claims; run;\n"
    )
    dependencies = discover_sas_external_dependencies(source)
    connection = next(item for item in dependencies if item.name == "libref:wh")

    assert connection.kind is ExternalDependencyKind.DATABASE_CONNECTION
    assert connection.system == "odbc"
    assert connection.location == "dsn=EDW"
    assert connection.metadata is not None
    options = connection.metadata["connection_options"]
    assert isinstance(options, dict)
    assert options["password"] == "<redacted>"
    assert options["user"] == "svc_sas"
    assert "TOP_SECRET" not in json.dumps(connection.metadata)


def test_sas_filesystem_sysget_and_unresolved_libref_are_explicit() -> None:
    source = (
        'libname mart "/sas/mart";\n'
        'filename ext "%sysget(EXTERNAL_DROP)/claims.csv";\n'
        "data mart.out; set mystery.input; run;\n"
    )
    dependencies = discover_sas_external_dependencies(source)
    by_name = {item.name: item for item in dependencies}

    assert by_name["libref:mart"].kind is ExternalDependencyKind.FILESYSTEM
    assert by_name["libref:mart"].location == "/sas/mart"
    assert by_name["EXTERNAL_DROP"].kind is ExternalDependencyKind.ENVIRONMENT_VARIABLE
    assert by_name["libref:mystery"].kind is ExternalDependencyKind.UNRESOLVED_CONNECTION


def test_shell_inventory_finds_external_commands_and_only_external_environment_requirements() -> (
    None
):
    source = """#!/usr/bin/env bash
LOCAL=/tmp/local
curl -sS "$API_URL" | jq '.items'
python3 scripts/load.py --token "$SERVICE_TOKEN"
echo "$LOCAL"
# wget "$COMMENT_ONLY"
printf '%s\\n' '$SINGLE_QUOTED'
"""
    dependencies = discover_shell_external_dependencies(source)
    keys = {(item.kind, item.name) for item in dependencies}

    assert (ExternalDependencyKind.EXECUTABLE, "curl") in keys
    assert (ExternalDependencyKind.EXECUTABLE, "jq") in keys
    assert (ExternalDependencyKind.EXECUTABLE, "python3") in keys
    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "API_URL") in keys
    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "SERVICE_TOKEN") in keys
    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "LOCAL") not in keys
    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "COMMENT_ONLY") not in keys
    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "SINGLE_QUOTED") not in keys


def test_filesystem_discovery_normalizes_external_dependencies_into_graph(tmp_path: Path) -> None:
    (tmp_path / "jobs").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "jobs" / "claims.sas").write_text(
        "libname wh odbc dsn='EDW' password='DO_NOT_LEAK';\ndata work.out; set wh.claims; run;\n",
        encoding="utf-8",
    )
    (tmp_path / "scripts" / "run.sh").write_text(
        'curl "$CONTROL_API" && sas -sysin jobs/claims.sas\n', encoding="utf-8"
    )

    workload = discover_source(tmp_path, provider="filesystem", namespace="test").workloads[0]
    dependencies = {(item.kind, item.name): item for item in workload.external_dependencies}
    payload = json.dumps(workload.to_dict())

    assert (ExternalDependencyKind.DATABASE_CONNECTION, "libref:wh") in dependencies
    assert (ExternalDependencyKind.EXECUTABLE, "curl") in dependencies
    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "CONTROL_API") in dependencies
    assert "DO_NOT_LEAK" not in payload

    dependency_ids = {item.dependency_id for item in workload.external_dependencies}
    assert any(
        edge.kind is RelationshipKind.DEPENDS_ON and edge.target_id in dependency_ids
        for edge in workload.relationships
    )
