from dataclasses import replace
from pathlib import Path

import pytest
from test_secret_provider import request
from test_security_configuration import write_configuration

from smf.readiness.policy import digest_value
from smf.security import ReasonCode, ResolutionState, load_receipt, write_receipt
from smf.security.secrets import HashiCorpVaultSecretProvider


def test_receipt_is_append_only_and_telemetry_is_recoverable(tmp_path: Path) -> None:
    config, _, _, _ = write_configuration(tmp_path)
    provider = HashiCorpVaultSecretProvider(None, None)  # type: ignore[arg-type]
    receipt = provider._receipt(
        request(config),
        ResolutionState.BLOCKED_MISSING,
        ReasonCode.APPROVAL_MISSING,
        "unverified",
        0.0,
    )
    path = write_receipt(tmp_path / "out", receipt)
    telemetry = path.with_name("secret-resolution.telemetry.json")
    telemetry.unlink()
    assert write_receipt(tmp_path / "out", receipt) == path
    assert telemetry.exists()
    conflict = replace(receipt, decision_id="different", content_digest="")
    conflict = replace(conflict, content_digest=digest_value(conflict.to_dict()))
    with pytest.raises(FileExistsError):
        write_receipt(tmp_path / "out", conflict)


def test_mutation_cannot_manufacture_resolved_receipt(tmp_path: Path) -> None:
    config, _, _, _ = write_configuration(tmp_path)
    provider = HashiCorpVaultSecretProvider(None, None)  # type: ignore[arg-type]
    blocked = provider._receipt(
        request(config),
        ResolutionState.BLOCKED_MISSING,
        ReasonCode.APPROVAL_MISSING,
        "unverified",
        0.0,
    )
    forged = replace(
        blocked,
        state=ResolutionState.RESOLVED,
        reason_code=ReasonCode.RESOLVED,
        terminal_disposition="secret_available_transiently",
        content_digest="",
    )
    forged = replace(forged, content_digest=digest_value(forged.to_dict()))
    with pytest.raises(ValueError, match="not reconstructable"):
        write_receipt(tmp_path / "out", forged)


def test_receipt_rejects_unbound_evidence_and_malformed_request(tmp_path: Path) -> None:
    config, _, _, _ = write_configuration(tmp_path)
    provider = HashiCorpVaultSecretProvider(None, None)  # type: ignore[arg-type]
    receipt = provider._receipt(
        request(config),
        ResolutionState.BLOCKED_MISSING,
        ReasonCode.APPROVAL_MISSING,
        "unverified",
        0.0,
    )
    path = write_receipt(tmp_path / "out", receipt)
    payload = load_receipt(path)
    payload["evidence_refs"] = ["unrelated-ready", "unrelated-activation"]
    payload["content_digest"] = ""
    payload["content_digest"] = digest_value(payload)
    path.write_text(__import__("json").dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="evidence references"):
        load_receipt(path)

    payload = receipt.to_dict()
    payload["request"]["source_sha256"] = "not-a-digest"
    payload["content_digest"] = ""
    payload["content_digest"] = digest_value(payload)
    path.write_text(__import__("json").dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match|request binding is invalid"):
        load_receipt(path)
