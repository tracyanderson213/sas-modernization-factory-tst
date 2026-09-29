from __future__ import annotations

import base64
import dataclasses
import json
from pathlib import Path

import pytest

from smf.workload.lineage import (
    LineageArtifact,
    LineageOperation,
    build_run_lineage,
    publish_run_lineage,
    verify_run_lineage,
)

SOURCE_A = "a" * 64
SOURCE_B = "b" * 64
POLICY = "c" * 64
STRATEGY = "d" * 64
CONFIGURATION = "e" * 64


def _artifact(**changes: object) -> LineageArtifact:
    values: dict[str, object] = {
        "subject_id": "script-1",
        "kind": "sas_program",
        "logical_path": "jobs/claims.sas",
        "sha256": SOURCE_A,
        "size_bytes": 42,
        "entrypoint": True,
        "source_locators": ("drop/a/claims.sas", "s3://redacted/claims.sas"),
    }
    values.update(changes)
    return LineageArtifact(**values)  # type: ignore[arg-type]


def _lineage(**changes: object):
    values: dict[str, object] = {
        "client_id": "client-a",
        "workload_key": "claims-daily",
        "artifacts": (_artifact(),),
        "operation": LineageOperation.INTAKE,
        "target": "offline-factory",
        "policy_digest": POLICY,
        "strategy_digest": STRATEGY,
        "configuration_digest": CONFIGURATION,
        "idempotency_key": "run-key-1",
        "attempt_key": "attempt-key-1",
        "provider": "filesystem",
        "provider_version": "1.0",
        "qualified_input_digests": (SOURCE_A,),
    }
    values.update(changes)
    return build_run_lineage(**values)  # type: ignore[arg-type]


def test_repeated_inputs_reproduce_ids_and_new_attempt_is_distinct() -> None:
    first = _lineage()
    assert _lineage() == first

    second_attempt = _lineage(attempt_key="attempt-key-2")
    assert second_attempt.workload_id == first.workload_id
    assert second_attempt.source_revision_id == first.source_revision_id
    assert second_attempt.run_id == first.run_id
    assert second_attempt.attempt_id != first.attempt_id
    assert second_attempt.lineage_id != first.lineage_id


def test_changed_source_changes_revision_run_and_attempt() -> None:
    first = _lineage()
    changed = _lineage(
        artifacts=(_artifact(sha256=SOURCE_B),),
        qualified_input_digests=(SOURCE_B,),
    )
    assert changed.workload_id == first.workload_id
    assert changed.source_revision_id != first.source_revision_id
    assert changed.run_id != first.run_id
    assert changed.attempt_id != first.attempt_id


def test_locator_aliases_preserve_provenance_without_changing_identity() -> None:
    first = _lineage()
    aliased = _lineage(artifacts=(_artifact(source_locators=("renamed/claims.sas",)),))
    assert aliased.workload_id == first.workload_id
    assert aliased.source_revision_id == first.source_revision_id
    assert aliased.run_id == first.run_id
    assert aliased.attempt_id == first.attempt_id
    assert aliased.lineage_id != first.lineage_id
    assert aliased.artifacts[0].source_locators == ("renamed/claims.sas",)


@pytest.mark.parametrize(
    "artifacts,match",
    [
        ((_artifact(), _artifact(logical_path="jobs/other.sas")), "subject"),
        (
            (_artifact(), _artifact(subject_id="script-2", logical_path="JOBS/CLAIMS.SAS")),
            "logical path",
        ),
        ((_artifact(entrypoint=False),), "entrypoint"),
    ],
)
def test_ambiguous_or_incomplete_source_closure_is_rejected(
    artifacts: tuple[LineageArtifact, ...], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        _lineage(artifacts=artifacts)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("client_id", "password=secret-canary-ORCH04"),
        ("workload_key", "123-45-6789"),
        ("idempotency_key", "patient@example.test"),
        ("provider", "token=ghp_abcdefghijklmnopqrstuvwxyz123456"),
    ],
)
def test_protected_identity_values_are_rejected_without_leaking(field: str, value: str) -> None:
    with pytest.raises(ValueError) as caught:
        _lineage(**{field: value})
    assert value not in str(caught.value)


def _percent_encode(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))


def _encoded_canary(value: str, encoding: str) -> str:
    if encoding == "percent":
        return _percent_encode(value)
    if encoding == "base64url":
        return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return value


@pytest.mark.parametrize("encoding", ["plain", "percent", "base64url"])
@pytest.mark.parametrize("admission", ["construction", "publication"])
@pytest.mark.parametrize(
    "field",
    [
        "client_id",
        "workload_key",
        "target",
        "idempotency_key",
        "attempt_key",
        "provider",
        "provider_version",
        "subject_id",
        "logical_path",
        "source_locator",
    ],
)
def test_secret_canary_is_rejected_at_every_persisted_string_boundary(
    tmp_path: Path, field: str, admission: str, encoding: str
) -> None:
    canary = "secret-canary-ORCH04-DO-NOT-PERSIST"
    unsafe = _encoded_canary(canary, encoding)
    lineage_changes: dict[str, object] = {}
    artifact_changes: dict[str, object] = {}
    if field == "logical_path":
        artifact_changes[field] = f"jobs/{unsafe}/claims.sas"
    elif field == "source_locator":
        artifact_changes["source_locators"] = (f"drop/{unsafe}/claims.sas",)
    elif field == "subject_id":
        artifact_changes[field] = unsafe
    else:
        lineage_changes[field] = unsafe
    if artifact_changes:
        lineage_changes["artifacts"] = (_artifact(**artifact_changes),)

    with pytest.raises(ValueError) as caught:
        if admission == "construction":
            _lineage(**lineage_changes)
        else:
            payload = _lineage().to_dict()
            if artifact_changes:
                artifact = payload["artifacts"][0]
                assert isinstance(artifact, dict)
                artifact.update(artifact_changes)
                if "source_locators" in artifact:
                    artifact["source_locators"] = list(artifact["source_locators"])
            else:
                payload[field] = unsafe
            publish_run_lineage(tmp_path, payload)

    assert canary not in str(caught.value).lower()
    assert unsafe not in str(caught.value)
    assert not any(path.is_file() for path in tmp_path.rglob("*"))


def test_unknown_operation_and_caller_authored_claims_fail_closed() -> None:
    with pytest.raises(ValueError, match="operation"):
        _lineage(operation="executted")
    payload = _lineage().to_dict()
    payload["approved"] = True
    with pytest.raises(ValueError, match="fields"):
        verify_run_lineage(payload)


def test_mutated_envelope_is_not_evidence() -> None:
    payload = _lineage().to_dict()
    payload["run_id"] = "RUN-v1-" + "f" * 64
    with pytest.raises(ValueError, match="run identity"):
        verify_run_lineage(payload)


def test_publication_is_immutable_and_retry_recovers_projection(tmp_path: Path) -> None:
    lineage = _lineage()
    path = publish_run_lineage(tmp_path, lineage)
    original = path.read_bytes()
    assert publish_run_lineage(tmp_path, lineage) == path
    assert path.read_bytes() == original

    conflicting = dataclasses.replace(lineage, target="different-target")
    with pytest.raises(ValueError, match="verification"):
        publish_run_lineage(tmp_path, conflicting)

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["lineage_id"] = "LIN-v1-" + "f" * 64
    path.chmod(0o644)
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="lineage identity"):
        publish_run_lineage(tmp_path, lineage)


def test_run_key_cannot_be_reused_for_changed_source(tmp_path: Path) -> None:
    publish_run_lineage(tmp_path, _lineage())
    changed = _lineage(
        artifacts=(_artifact(sha256=SOURCE_B),),
        qualified_input_digests=(SOURCE_B,),
        attempt_key="attempt-key-2",
    )
    with pytest.raises(FileExistsError, match="run idempotency"):
        publish_run_lineage(tmp_path, changed)
