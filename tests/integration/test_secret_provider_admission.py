import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from smf.security.admission import request_from_readiness_manifest


def admission_arguments(tmp_path: Path) -> dict[str, object]:
    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    return {
        "manifest_path": tmp_path / "readiness.json",
        "client_id": "client-1",
        "deployment_id": "deployment-1",
        "environment_id": "environment-1",
        "workload_id": "workload-1",
        "boundary_id": "boundary-1",
        "subject_id": "subject-1",
        "source_path": source,
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "consumer_id": "consumer-1",
        "consumer_contract_version": "1.0",
        "identity_binding_id": "identity-1",
        "secret_binding_id": "secret-1",
        "security_policy_id": "policy-1",
        "security_policy_version": "1",
        "security_policy_digest": "1" * 64,
        "configuration_digest": "2" * 64,
        "activation_evidence_id": "activation-1",
        "activation_evidence_digest": "3" * 64,
    }


def test_admission_rejects_non_ready_and_ambiguous_subjects(tmp_path: Path) -> None:
    arguments = admission_arguments(tmp_path)
    manifest = {
        "classification": "BLOCKED",
        "workload_id": "workload-1",
        "boundary_id": "boundary-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
    }
    with (
        patch("smf.security.admission.load_manifest", return_value=manifest),
        pytest.raises(ValueError, match="not READY"),
    ):
        request_from_readiness_manifest(**arguments)

    source = arguments["source_path"]
    assert isinstance(source, Path)
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest.update(
        classification="READY",
        policy_snapshot={
            "prerequisite_binding": {
                "client_id": "client-1",
                "deployment_id": "deployment-1",
                "environment_id": "environment-1",
            }
        },
        qualification_input={
            "workload": {
                "artifacts": [
                    {"artifact_id": "subject-1", "checksum": checksum},
                    {"artifact_id": "subject-1", "checksum": checksum},
                ]
            }
        },
    )
    with (
        patch("smf.security.admission.load_manifest", return_value=manifest),
        pytest.raises(ValueError, match="exactly one"),
    ):
        request_from_readiness_manifest(**arguments)


def test_admission_rehashes_qualified_source_bytes(tmp_path: Path) -> None:
    arguments = admission_arguments(tmp_path)
    source = arguments["source_path"]
    assert isinstance(source, Path)
    manifest = {
        "classification": "READY",
        "workload_id": "workload-1",
        "workload_digest": "4" * 64,
        "boundary_id": "boundary-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "result_id": "ready-1",
        "content_digest": "5" * 64,
        "policy_snapshot": {
            "prerequisite_binding": {
                "client_id": "client-1",
                "deployment_id": "deployment-1",
                "environment_id": "environment-1",
            }
        },
        "qualification_input": {
            "workload": {"artifacts": [{"artifact_id": "subject-1", "checksum": "6" * 64}]}
        },
        "evidence_references": [
            {"kind": "discovery_snapshot", "snapshot_uri": "evidence://snapshot/1"}
        ],
    }
    with (
        patch("smf.security.admission.load_manifest", return_value=manifest),
        pytest.raises(ValueError, match="source bytes"),
    ):
        request_from_readiness_manifest(**arguments)


def test_admission_rejects_comment_only_source(tmp_path: Path) -> None:
    arguments = admission_arguments(tmp_path)
    source = arguments["source_path"]
    assert isinstance(source, Path)
    source.write_text("/* harmless note; data fake; run; */\n* proc sql;\n", encoding="utf-8")
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = {
        "classification": "READY",
        "workload_id": "workload-1",
        "workload_digest": "4" * 64,
        "boundary_id": "boundary-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "result_id": "ready-1",
        "content_digest": "5" * 64,
        "policy_snapshot": {
            "prerequisite_binding": {
                "client_id": "client-1",
                "deployment_id": "deployment-1",
                "environment_id": "environment-1",
            }
        },
        "qualification_input": {
            "workload": {"artifacts": [{"artifact_id": "subject-1", "checksum": checksum}]}
        },
        "evidence_references": [
            {"kind": "discovery_snapshot", "snapshot_uri": "evidence://snapshot/1"}
        ],
    }
    with (
        patch("smf.security.admission.load_manifest", return_value=manifest),
        pytest.raises(ValueError, match="executable SAS entry point"),
    ):
        request_from_readiness_manifest(**arguments)


@pytest.mark.parametrize(
    "source_text",
    ["%let harmless = proc sql; %put &=harmless;\n", "%put data fake;\n"],
)
def test_admission_rejects_macro_text_without_executable_entrypoint(
    tmp_path: Path, source_text: str
) -> None:
    arguments = admission_arguments(tmp_path)
    source = arguments["source_path"]
    assert isinstance(source, Path)
    source.write_text(source_text, encoding="utf-8")
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = {
        "classification": "READY",
        "workload_id": "workload-1",
        "workload_digest": "4" * 64,
        "boundary_id": "boundary-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "result_id": "ready-1",
        "content_digest": "5" * 64,
        "policy_snapshot": {
            "prerequisite_binding": {
                "client_id": "client-1",
                "deployment_id": "deployment-1",
                "environment_id": "environment-1",
            }
        },
        "qualification_input": {
            "workload": {"artifacts": [{"artifact_id": "subject-1", "checksum": checksum}]}
        },
        "evidence_references": [
            {"kind": "discovery_snapshot", "snapshot_uri": "evidence://snapshot/1"}
        ],
    }
    with (
        patch("smf.security.admission.load_manifest", return_value=manifest),
        pytest.raises(ValueError, match="executable SAS entry point"),
    ):
        request_from_readiness_manifest(**arguments)
