from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.batch_intake_support import make_manifest, make_policy

from smf.baseline.approved_export import approval_subject_digest
from smf.baseline.models import AcquisitionMode, BaselineAcquisitionRequest
from smf.baseline.policy import baseline_policy_from_dict
from smf.intake import IntakeRequest, evaluate_batch_intake, write_intake_result
from smf.readiness.policy import canonical_json, digest_value


def _public(key: Ed25519PrivateKey) -> str:
    value = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(value).decode("ascii")


def _sign(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> None:
    unsigned = dict(payload)
    unsigned.pop("proof", None)
    payload["proof"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(canonical_json(unsigned).encode("utf-8"))).decode(
            "ascii"
        ),
    }


def build_baseline_case(tmp_path: Path) -> dict[str, Any]:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    output_root = tmp_path / "out"
    intake_policy, intake_key = make_policy()
    manifest = make_manifest(source, intake_key, two=False)
    intake_result = evaluate_batch_intake(
        IntakeRequest(manifest, intake_policy, source, output_root, "run-1", "attempt-1")
    )
    intake_path = write_intake_result(output_root, intake_result, trusted_policy=intake_policy)
    decision = intake_result["decisions"][0]
    workload = decision["discovery"]
    boundary = workload["boundaries"][0]
    output = workload["outputs"][0]

    producer_key = Ed25519PrivateKey.generate()
    approval_key = Ed25519PrivateKey.generate()
    policy_raw = {
        "schema_version": "1.0",
        "policy_id": "baseline-policy",
        "policy_version": "1",
        "client_id": "client-a",
        "provider": "approved_export",
        "provider_version": "1",
        "allowed_modes": ["approved_export", "sas_execution"],
        "allowed_output_formats": ["json"],
        "max_export_age_seconds": 3600,
        "max_output_bytes": 1048576,
        "producer_provenance": {
            "authorities": ["sas-export-service"],
            "key_ids": ["producer-key"],
        },
        "approval_provenance": {
            "authorities": ["baseline-owner"],
            "key_ids": ["approval-key"],
        },
        "verification_keys": {
            "producer-key": _public(producer_key),
            "approval-key": _public(approval_key),
        },
    }
    policy = baseline_policy_from_dict(policy_raw)
    policy_path = tmp_path / "baseline-policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy_raw), encoding="utf-8")

    package = tmp_path / "package"
    (package / "outputs").mkdir(parents=True)
    output_bytes = b'{"columns":["x"],"rows":[[1]]}\n'
    output_path = package / "outputs" / "alpha.json"
    output_path.write_bytes(output_bytes)
    now = datetime.now(UTC).replace(microsecond=0)
    source_ref = decision["snapshot_refs"][0]
    receipt = {
        "schema_version": "1.0",
        "package_id": "package-1",
        "acquisition_id": "acq-1",
        "client_id": "client-a",
        "workload_id": decision["workload_id"],
        "workload_revision_id": decision["workload_revision_id"],
        "workload_digest": digest_value(workload),
        "closure_digest": decision["closure_digest"],
        "boundary_id": boundary["boundary_id"],
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "acquisition_policy_digest": policy.policy_digest,
        "producer_authority": "sas-export-service",
        "provider": "approved_export",
        "provider_version": "1",
        "format": "json",
        "source_closure": [
            {
                "script_id": source_ref["script_id"],
                "logical_path": source_ref["logical_path"],
                "sha256": source_ref["sha256"],
                "byte_count": source_ref["size_bytes"],
            }
        ],
        "input_snapshots": [],
        "execution": {
            "sas_execution_id": "sas-run-1",
            "environment_id": "sas-env-1",
            "sas_product": "SAS-9.4",
            "sas_release": "M8",
            "runtime_configuration_digest": "a" * 64,
            "executed_at": (now - timedelta(minutes=2)).isoformat(),
        },
        "executed_at": (now - timedelta(minutes=2)).isoformat(),
        "exported_at": (now - timedelta(minutes=1)).isoformat(),
        "outputs": [
            {
                "output_id": output["output_id"],
                "dataset_id": output["dataset_id"],
                "logical_name": "alpha",
                "format": "json",
                "artifact_path": "outputs/alpha.json",
                "byte_count": len(output_bytes),
                "content_digest": hashlib.sha256(output_bytes).hexdigest(),
                "schema_digest": "b" * 64,
                "normalization_version": "raw-1",
                "origin": "sas_execution",
                "status": "completed",
            }
        ],
    }
    _sign(receipt, producer_key, "producer-key")
    receipt_path = package / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    approval = {
        "schema_version": "1.0",
        "decision_id": "decision-1",
        "state": "approved",
        "authority": "baseline-owner",
        "owner_assignment_ref": "owner-1",
        "subject_digest": approval_subject_digest(receipt, policy.policy_digest),
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    _sign(approval, approval_key, "approval-key")
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    request = BaselineAcquisitionRequest(
        acquisition_id="acq-1",
        mode=AcquisitionMode.APPROVED_EXPORT,
        policy_path=policy_path,
        intake_result_path=intake_path,
        intake_policy=intake_policy,
        package_root=package,
        receipt_path=receipt_path,
        approval_path=approval_path,
        output_root=output_root,
        workload_id=decision["workload_id"],
        workload_revision_id=decision["workload_revision_id"],
        closure_digest=decision["closure_digest"],
        boundary_id=boundary["boundary_id"],
        run_id="run-1",
        attempt_id="attempt-1",
    )
    return {
        "request": request,
        "policy": policy,
        "receipt": receipt,
        "receipt_path": receipt_path,
        "approval": approval,
        "approval_path": approval_path,
        "approval_key": approval_key,
        "producer_key": producer_key,
        "output_path": output_path,
        "output_bytes": output_bytes,
    }
