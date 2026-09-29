from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from tests.unit.batch_intake_support import make_manifest, make_policy, sign_manifest

from smf.intake import (
    IntakeRequest,
    evaluate_batch_intake,
    load_intake_result,
    verify_intake_workload,
    write_intake_result,
)
from smf.readiness.policy import digest_value


def _request(tmp_path: Path, manifest: dict, policy):
    return IntakeRequest(
        manifest, policy, tmp_path / "source", tmp_path / "out", "run-1", "attempt-1"
    )


def test_invalid_workload_is_isolated_from_valid_workload(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key)
    manifest["workloads"][1]["entrypoint_ids"] = ["missing"]
    manifest = sign_manifest(manifest, key)
    result = evaluate_batch_intake(_request(tmp_path, manifest, policy))
    assert [item["state"] for item in result["decisions"]] == ["admitted", "blocked"]
    assert result["disposition"] == "partial"


@pytest.mark.parametrize(
    "source_uri", ["../alpha.sas", "%252e%252e/alpha.sas", "https://example.test/a.sas"]
)
def test_boundary_escape_blocks_without_echo(tmp_path: Path, source_uri: str) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    manifest["artifacts"][0]["source_uri"] = source_uri
    manifest = sign_manifest(manifest, key)
    result = evaluate_batch_intake(_request(tmp_path, manifest, policy))
    assert result["decisions"][0]["state"] == "blocked"
    assert source_uri not in json.dumps(result["decisions"][0])


def test_unknown_kind_and_nonconvertible_entrypoint_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    manifest["artifacts"][0]["kind"] = "sas_progam"
    manifest = sign_manifest(manifest, key)
    result = evaluate_batch_intake(_request(tmp_path, manifest, policy))
    assert "unsupported_artifact_kind" in result["decisions"][0]["blockers"]
    (source / "alpha.sas").write_text("/* comment only */\n", encoding="utf-8")
    data = (source / "alpha.sas").read_bytes()
    manifest["artifacts"][0].update(
        kind="sas_program",
        sha256=__import__("hashlib").sha256(data).hexdigest(),
        size_bytes=len(data),
    )
    manifest = sign_manifest(manifest, key)
    result = evaluate_batch_intake(_request(tmp_path, manifest, policy))
    assert "no_meaningful_sas_entrypoint" in result["decisions"][0]["blockers"]


def test_duplicate_identity_and_protected_identity_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key)
    manifest["workloads"][1]["alias"] = "ALPHA"
    manifest = sign_manifest(manifest, key)
    result = evaluate_batch_intake(_request(tmp_path, manifest, policy))
    assert all("duplicate_workload_alias" in item["blockers"] for item in result["decisions"])
    manifest["workloads"][0]["alias"] = "123-45-6789"
    manifest = sign_manifest(manifest, key)
    with pytest.raises(ValueError, match="Unsafe workload alias"):
        evaluate_batch_intake(_request(tmp_path, manifest, policy))


@pytest.mark.parametrize(
    "path",
    [
        ("schema_version",),
        ("policy_id",),
        ("policy_version",),
        ("client_id",),
        ("provider",),
        ("provider_version",),
        ("discovery_strategy_version",),
        ("manifest_provenance", "authorities", 0),
        ("manifest_provenance", "key_ids", 0),
        ("verification_keys", "key-1"),
        ("readiness_prerequisites", 0, "kind"),
        ("readiness_prerequisites", 0, "owner"),
    ],
)
def test_mutated_policy_digest_is_rejected(tmp_path: Path, path: tuple[object, ...]) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    target: object = policy.payload
    for component in path[:-1]:
        target = target[component]  # type: ignore[index]
    final = path[-1]
    current = target[final]  # type: ignore[index]
    target[final] = f"{current}-mutated"  # type: ignore[index]
    with pytest.raises(ValueError):
        evaluate_batch_intake(_request(tmp_path, manifest, policy))


def test_duplicate_artifact_aliases_and_orphan_scripts_are_explicit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    duplicate = make_manifest(source, key)
    duplicate["artifacts"][1]["alias"] = duplicate["artifacts"][0]["alias"].upper()
    duplicate = sign_manifest(duplicate, key)
    result = evaluate_batch_intake(_request(tmp_path, duplicate, policy))
    assert result["disposition"] == "blocked"
    assert all("duplicate_artifact_alias" in item["blockers"] for item in result["decisions"])

    orphan = make_manifest(source, key)
    orphan["workloads"] = orphan["workloads"][:1]
    orphan = sign_manifest(orphan, key)
    result = evaluate_batch_intake(_request(tmp_path, orphan, policy))
    assert result["disposition"] == "partial"
    assert result["denominator_reconciled"] is False
    assert result["unassigned_scripts"] == [
        {"script_id": "script-2", "reason_code": "unmapped_inventory_script"}
    ]


@pytest.mark.parametrize(
    "protected_statement",
    [
        'password="secret-canary-AD01"',
        'note="123-45-6789"',
        'email="patient@example.test"',
    ],
)
def test_protected_source_is_blocked_before_snapshot(
    tmp_path: Path, protected_statement: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    secret = f"data alpha; {protected_statement}; run;\n".encode()
    (source / "alpha.sas").write_bytes(secret)
    manifest["artifacts"][0]["sha256"] = hashlib.sha256(secret).hexdigest()
    manifest["artifacts"][0]["size_bytes"] = len(secret)
    manifest = sign_manifest(manifest, key)
    result = evaluate_batch_intake(_request(tmp_path, manifest, policy))
    assert result["disposition"] == "blocked"
    assert "protected_source_content" in result["decisions"][0]["blockers"]
    assert result["decisions"][0]["snapshot_refs"] == []
    assert protected_statement not in json.dumps(result)


@pytest.mark.parametrize("encoding", ["plain", "percent", "base64url"])
@pytest.mark.parametrize("boundary", ["run_id", "source_locator"])
def test_secret_canary_identity_is_rejected_before_intake_persistence(
    tmp_path: Path, boundary: str, encoding: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    manifest = make_manifest(source, key, two=False)
    canary = "secret-canary-ORCH04-DO-NOT-PERSIST"
    unsafe = canary
    source_name = canary
    if encoding == "percent":
        unsafe = "".join(f"%{byte:02X}" for byte in canary.encode("utf-8"))
    elif encoding == "base64url":
        unsafe = base64.urlsafe_b64encode(canary.encode()).decode().rstrip("=")
        source_name = unsafe
    run_id = "run-1"
    if boundary == "run_id":
        run_id = unsafe
    else:
        (source / source_name).write_bytes((source / "alpha.sas").read_bytes())
        manifest["artifacts"][0]["source_uri"] = unsafe
        manifest = sign_manifest(manifest, key)

    request = IntakeRequest(manifest, policy, source, tmp_path / "out", run_id, "attempt-1")
    with pytest.raises(ValueError) as caught:
        evaluate_batch_intake(request)

    assert canary not in str(caught.value).lower()
    assert unsafe not in str(caught.value)
    assert not any(path.is_file() for path in (tmp_path / "out").rglob("*"))


def test_mutated_snapshot_and_fabricated_success_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    result = evaluate_batch_intake(
        _request(tmp_path, make_manifest(source, key, two=False), policy)
    )
    path = write_intake_result(tmp_path / "out", result, trusted_policy=policy)
    snapshot = tmp_path / "out" / result["decisions"][0]["snapshot_refs"][0]["snapshot_uri"]
    decision = result["decisions"][0]
    verified = verify_intake_workload(
        path,
        output_root=tmp_path / "out",
        trusted_policy=policy,
        workload_id=decision["workload_id"],
        workload_revision_id=decision["workload_revision_id"],
        closure_digest=decision["closure_digest"],
        run_id="run-1",
        attempt_id="attempt-1",
    )
    original_bytes = (source / "alpha.sas").read_bytes()
    assert snapshot.stat().st_mode & 0o222 == 0
    with pytest.raises(PermissionError):
        snapshot.write_text("data changed; run;\n", encoding="utf-8")
    snapshot.chmod(0o644)
    snapshot.write_text("data changed; run;\n", encoding="utf-8")
    assert verified.sources[0].data == original_bytes
    assert not hasattr(verified.sources[0], "snapshot_uri")
    with pytest.raises(ValueError, match="snapshot"):
        load_intake_result(path, output_root=tmp_path / "out", trusted_policy=policy)
    snapshot.write_bytes(original_bytes)
    snapshot.chmod(0o444)
    asserted = copy.deepcopy(result)
    asserted["decisions"][0]["discovery"]["approved"] = True
    asserted["decisions"][0]["readiness_input"]["workload"]["approved"] = True
    asserted["content_digest"] = digest_value({**asserted, "content_digest": ""})
    path.write_text(json.dumps(asserted), encoding="utf-8")
    with pytest.raises(ValueError, match="canonical projection binding"):
        load_intake_result(path, output_root=tmp_path / "out", trusted_policy=policy)
    fake = copy.deepcopy(result)
    fake["decisions"][0]["telemetry"]["parity_passed"] = True
    fake["content_digest"] = digest_value({**fake, "content_digest": ""})
    path.write_text(json.dumps(fake), encoding="utf-8")
    with pytest.raises(ValueError, match="telemetry claim"):
        load_intake_result(path, output_root=tmp_path / "out", trusted_policy=policy)


def test_self_authored_manifest_cannot_manufacture_durable_admission(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    policy, key = make_policy()
    result = evaluate_batch_intake(
        _request(tmp_path, make_manifest(source, key, two=False), policy)
    )
    path = write_intake_result(tmp_path / "out", result, trusted_policy=policy)
    forged = copy.deepcopy(result)
    forged["manifest_snapshot"]["batch_version"] = "forged"
    from smf.intake.engine import manifest_digest

    forged["manifest_snapshot"]["manifest_digest"] = manifest_digest(forged["manifest_snapshot"])
    forged["manifest_digest"] = forged["manifest_snapshot"]["manifest_digest"]
    forged["content_digest"] = digest_value({**forged, "content_digest": ""})
    path.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(ValueError, match="attestation is invalid"):
        load_intake_result(path, output_root=tmp_path / "out", trusted_policy=policy)
