"""Construction of secret requests from replay-valid readiness evidence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from smf.readiness.manifest import load_manifest
from smf.security.models import SecretResolutionRequest

_BLOCK_COMMENTS = re.compile(rb"/\*.*?\*/", re.DOTALL)
_STATEMENT_COMMENTS = re.compile(rb"(?m)^\s*\*[^;]*;")
_QUOTED_TEXT = re.compile(rb"(?s)(?:'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")")
_NONEXECUTING_MACRO_STATEMENT = re.compile(rb"(?is)%\s*(?:let|put)\b[^;]*;")
_SAS_ENTRY = re.compile(rb"(?i)\b(?:data\s+[A-Za-z_][\w.]*|proc\s+(?!format\b)[A-Za-z_]\w*)\b")


def has_executable_sas_entrypoint(source_bytes: bytes) -> bool:
    """Recognize an executable DATA/PROC boundary outside comments, strings, and macro text."""

    executable = _BLOCK_COMMENTS.sub(b" ", source_bytes)
    executable = _QUOTED_TEXT.sub(b"''", executable)
    executable = _NONEXECUTING_MACRO_STATEMENT.sub(b" ", executable)
    while True:
        without_comments = _STATEMENT_COMMENTS.sub(b"", executable)
        if without_comments == executable:
            break
        executable = without_comments
    return bool(_SAS_ENTRY.search(executable))


def request_from_readiness_manifest(
    manifest_path: Path,
    *,
    client_id: str,
    deployment_id: str,
    environment_id: str,
    workload_id: str,
    boundary_id: str,
    subject_id: str,
    source_path: Path,
    run_id: str,
    attempt_id: str,
    consumer_id: str,
    consumer_contract_version: str,
    identity_binding_id: str,
    secret_binding_id: str,
    security_policy_id: str,
    security_policy_version: str,
    security_policy_digest: str,
    configuration_digest: str,
    activation_evidence_id: str,
    activation_evidence_digest: str,
) -> SecretResolutionRequest:
    manifest = load_manifest(manifest_path)
    expected = {
        "workload_id": workload_id,
        "boundary_id": boundary_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
    }
    if manifest["classification"] != "READY" or any(
        manifest[key] != value for key, value in expected.items()
    ):
        raise ValueError("Readiness manifest is not READY for the requested identity")
    readiness_binding = manifest["policy_snapshot"].get("prerequisite_binding")
    expected_deployment = {
        "client_id": client_id,
        "deployment_id": deployment_id,
        "environment_id": environment_id,
    }
    if not isinstance(readiness_binding, dict) or any(
        readiness_binding.get(key) != value for key, value in expected_deployment.items()
    ):
        raise ValueError("Readiness manifest deployment binding mismatch")
    artifacts = manifest["qualification_input"]["workload"].get("artifacts", [])
    matches = [item for item in artifacts if item.get("artifact_id") == subject_id]
    if len(matches) != 1:
        raise ValueError("Readiness manifest must contain exactly one requested subject")
    source_bytes = source_path.read_bytes()
    if not has_executable_sas_entrypoint(source_bytes):
        raise ValueError("Qualified source must contain an executable SAS entry point")
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    if matches[0].get("checksum") != source_digest:
        raise ValueError("Qualified source bytes do not match readiness evidence")
    snapshots = [
        item.get("snapshot_uri")
        for item in manifest["evidence_references"]
        if item.get("kind") == "discovery_snapshot" and item.get("snapshot_uri")
    ]
    if len(snapshots) != 1:
        raise ValueError("Readiness evidence must contain one qualified snapshot")
    return SecretResolutionRequest(
        schema_version="1.0",
        client_id=client_id,
        deployment_id=deployment_id,
        environment_id=environment_id,
        workload_id=workload_id,
        workload_digest=manifest["workload_digest"],
        boundary_id=boundary_id,
        subject_id=subject_id,
        source_sha256=source_digest,
        run_id=run_id,
        attempt_id=attempt_id,
        consumer_id=consumer_id,
        consumer_contract_version=consumer_contract_version,
        identity_binding_id=identity_binding_id,
        secret_binding_id=secret_binding_id,
        security_policy_id=security_policy_id,
        security_policy_version=security_policy_version,
        security_policy_digest=security_policy_digest,
        configuration_digest=configuration_digest,
        readiness_result_id=manifest["result_id"],
        readiness_manifest_digest=str(manifest["content_digest"]),
        qualified_snapshot_ref=str(snapshots[0]),
        activation_evidence_id=activation_evidence_id,
        activation_evidence_digest=activation_evidence_digest,
    )
