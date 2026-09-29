from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.intake.engine import manifest_digest
from smf.intake.policy import IntakePolicy, intake_policy_from_dict


def make_policy(
    private_key: Ed25519PrivateKey | None = None,
) -> tuple[IntakePolicy, Ed25519PrivateKey]:
    key = private_key or Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    raw = {
        "schema_version": "1.0",
        "policy_id": "intake-policy",
        "policy_version": "1",
        "client_id": "client-a",
        "provider": "filesystem",
        "provider_version": "1",
        "discovery_strategy_version": "1",
        "manifest_provenance": {"authorities": ["inventory-owner"], "key_ids": ["key-1"]},
        "verification_keys": {"key-1": base64.b64encode(public).decode()},
        "readiness_prerequisites": [
            {"kind": "sas_baseline", "owner": "validation-owner"},
            {"kind": "validation_policy", "owner": "validation-owner"},
        ],
    }
    return intake_policy_from_dict(raw), key


def sign_manifest(raw: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    raw = {
        **raw,
        "manifest_digest": "0" * 64,
        "proof": {"algorithm": "ed25519", "key_id": "key-1", "value": "pending"},
    }
    digest = manifest_digest(raw)
    raw["manifest_digest"] = digest
    raw["proof"]["value"] = base64.b64encode(key.sign(bytes.fromhex(digest))).decode()
    return raw


def make_manifest(source: Path, key: Ed25519PrivateKey, *, two: bool = True) -> dict[str, Any]:
    sources = [("script-1", "alpha", "alpha.sas", b"data alpha; x=1; run;\n")]
    if two:
        sources.append(("script-2", "beta", "beta.sas", b"proc print data=sashelp.class; run;\n"))
    artifacts = []
    workloads = []
    for script_id, alias, name, data in sources:
        (source / name).write_bytes(data)
        artifacts.append(
            {
                "script_id": script_id,
                "alias": alias,
                "logical_path": name,
                "source_uri": name,
                "kind": "sas_program",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )
        workloads.append(
            {
                "alias": alias,
                "script_ids": [script_id],
                "entrypoint_ids": [script_id],
                "closure_ids": [script_id],
            }
        )
    return sign_manifest(
        {
            "schema_version": "1.0",
            "client_id": "client-a",
            "batch_id": "batch-1",
            "batch_version": "1",
            "expected_script_count": len(sources),
            "authority": "inventory-owner",
            "artifacts": artifacts,
            "workloads": workloads,
            "unprocessable": [],
        },
        key,
    )
