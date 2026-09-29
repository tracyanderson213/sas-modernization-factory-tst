"""Synthetic-only LIC-01 fixture construction."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.compliance import CompliancePolicy, load_compliance_policy
from smf.upstream.crypto import digest_value, sign_payload
from smf.workload.identity import stable_id


def _key(tmp_path: Path, name: str) -> tuple[Path, str]:
    private = Ed25519PrivateKey.generate()
    path = tmp_path / f"{name}.pem"
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return path, public


def build_fixture(
    tmp_path: Path, *, inconsistent_sec03: bool = True
) -> tuple[CompliancePolicy, dict[str, Any], dict[str, Path]]:
    names = ("collector", "legal", "security", "scanner", "prerequisite", "evaluator")
    pairs = {name: _key(tmp_path, name) for name in names}
    digest_a = "a" * 64
    digest_b = "b" * 64
    policy_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "policy_id": "lic-policy",
        "policy_version": "1",
        "client_id": "synthetic-client",
        "max_evidence_age_seconds": 3600,
        "allowed_deployment_profiles": [
            {"profile_id": "synthetic-profile", "profile_digest": "c" * 64}
        ],
        "approved_license_ids": ["Synthetic-Test-License"],
        "vulnerability_exception_allowlist": [],
        "sec03_acceptance_contract_digests": (
            [digest_a, digest_b] if inconsistent_sec03 else [digest_a]
        ),
        "collector_provenance": {
            "authorities": ["synthetic-collector-authority"],
            "key_ids": ["collector-key"],
        },
        "license_provenance": {
            "authorities": ["synthetic-legal-authority"],
            "key_ids": ["legal-key"],
        },
        "security_provenance": {
            "authorities": ["synthetic-security-authority"],
            "key_ids": ["security-key"],
        },
        "scanner_provenance": {
            "authorities": ["synthetic-scanner-authority"],
            "key_ids": ["scanner-key"],
        },
        "evaluator_provenance": {
            "authorities": ["synthetic-evaluator-authority"],
            "key_ids": ["evaluator-key"],
        },
        "prerequisite_provenance": {
            "authorities": ["synthetic-prerequisite-authority"],
            "key_ids": ["prerequisite-key"],
        },
        "verification_keys": {f"{name}-key": pairs[name][1] for name in names},
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy_payload), encoding="utf-8")
    policy = load_compliance_policy(policy_path)

    component = {
        "component_id": "synthetic-component",
        "version": "1.0",
        "artifact_type": "python",
        "artifact_digest": "d" * 64,
    }
    resolution = {"resolution_id": "resolution-1", "components": [component]}
    resolution["resolution_digest"] = digest_value(resolution)
    environment = {"environment_id": "environment-1", "components": [component]}
    environment["environment_digest"] = digest_value(environment)
    sbom = {
        "sbom_id": "sbom-1",
        "format": "cyclonedx-json",
        "resolution_digest": resolution["resolution_digest"],
        "environment_digest": environment["environment_digest"],
        "components": [component],
    }
    sbom["sbom_digest"] = digest_value(sbom)
    subject = {
        "client_id": "synthetic-client",
        "workload_id": "synthetic-workload",
        "source_digest": "e" * 64,
        "run_id": "run-1",
        "attempt_id": "attempt-1",
    }
    license_record = {
        "component_id": "synthetic-component",
        "version": "1.0",
        "artifact_type": "python",
        "artifact_digest": "d" * 64,
        "license_id": "Synthetic-Test-License",
        "license_evidence_digest": "f" * 64,
        "notice_required": True,
        "source_revision": "synthetic-revision",
        "upq_result_digest": "1" * 64,
        "state": "verified",
        "authority": "synthetic-legal-authority",
        "proof": {},
    }
    sign_payload(license_record, private_key_path=pairs["legal"][0], key_id="legal-key")
    upq = {
        "prerequisite_id": "UPQ-01",
        "status": "complete",
        "result_id": "upq-result",
        "result_digest": "1" * 64,
        **subject,
        "authority": "synthetic-prerequisite-authority",
        "proof": {},
    }
    sec03 = {
        "prerequisite_id": "SEC-03",
        "status": "complete",
        "result_id": "sec03-result",
        "result_digest": "2" * 64,
        **subject,
        "acceptance_contract_digest": digest_a,
        "scope_statement": "synthetic SBOM and dependency scanning contract",
        "authority": "synthetic-prerequisite-authority",
        "proof": {},
    }
    for record in (upq, sec03):
        sign_payload(
            record,
            private_key_path=pairs["prerequisite"][0],
            key_id="prerequisite-key",
        )
    vulnerability = {
        "scanner_id": "synthetic-scanner",
        "scanner_version": "1",
        "status": "complete",
        "scan_id": "scan-1",
        "scanned_at": "2026-09-19T12:00:00Z",
        "resolution_digest": resolution["resolution_digest"],
        "environment_digest": environment["environment_digest"],
        "sbom_digest": sbom["sbom_digest"],
        "advisories_digest": digest_value([]),
        "advisories": [],
        "findings": [],
        "exceptions": [],
        "authority": "synthetic-scanner-authority",
        "proof": {},
    }
    sign_payload(vulnerability, private_key_path=pairs["scanner"][0], key_id="scanner-key")
    evidence: dict[str, Any] = {
        "schema_version": "1.0",
        "evidence_class": "synthetic_contract",
        "bundle_id": "pending",
        **subject,
        "observed_at": "2026-09-19T12:00:00Z",
        "evaluated_at": "2026-09-19T12:10:00Z",
        "deployment_profile": {
            "profile_id": "synthetic-profile",
            "profile_digest": "c" * 64,
        },
        "resolution": resolution,
        "installed_environment": environment,
        "sbom": sbom,
        "licenses": [license_record],
        "notice_files": [
            {
                "component_id": "synthetic-component",
                "notice_path": "notices/synthetic-component.NOTICE",
                "notice_digest": "4" * 64,
            }
        ],
        "provenance": [
            {
                "component_id": "synthetic-component",
                "source_revision": "synthetic-revision",
                "artifact_digest": "d" * 64,
                "upq_result_digest": "1" * 64,
            }
        ],
        "upq": upq,
        "sec03": sec03,
        "vulnerability": vulnerability,
        "authority": "synthetic-collector-authority",
        "proof": {},
    }
    evidence["bundle_id"] = stable_id(
        "LICB",
        {
            **subject,
            "observed_at": evidence["observed_at"],
            "policy_digest": policy.policy_digest,
        },
    )
    sign_payload(evidence, private_key_path=pairs["collector"][0], key_id="collector-key")
    return policy, evidence, {name: pairs[name][0] for name in names}
