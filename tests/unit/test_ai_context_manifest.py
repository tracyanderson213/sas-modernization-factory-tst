from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.ai_context_test_support import make_case

from smf.security.ai_admission import qualify_ai_context
from smf.security.ai_manifest import load_ai_context_result, write_ai_context_result
from smf.security.ai_models import AIAdmissionState

EVIDENCE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
VERIFY_KEYS = {"offline-evidence-key": EVIDENCE_KEY.public_key()}


def _result(tmp_path: Path):
    policy, request, evidence, manifest = make_case(tmp_path)
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        return qualify_ai_context(
            request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=evidence,
        )


def test_append_only_result_and_idempotent_telemetry_recovery(tmp_path: Path) -> None:
    outcome = _result(tmp_path)
    result = outcome.result
    path = write_ai_context_result(
        tmp_path / "out", result, signing_key=EVIDENCE_KEY, key_id="offline-evidence-key"
    )
    canonical = path.read_bytes()
    telemetry = path.with_name("ai-context-admission.telemetry.json")
    event = json.loads(telemetry.read_text(encoding="utf-8"))
    assert event["outcome"] == "qualified_offline"
    assert not event["generated"] and not event["parity_passed"]
    assert load_ai_context_result(path, verification_keys=VERIFY_KEYS)["decision_id"] == (
        result.decision_id
    )
    with pytest.raises(ValueError, match="trusted evidence proof"):
        load_ai_context_result(path, verification_keys={})
    telemetry.unlink()
    assert (
        write_ai_context_result(
            tmp_path / "out", result, signing_key=EVIDENCE_KEY, key_id="offline-evidence-key"
        )
        == path
    )
    assert path.read_bytes() == canonical
    assert telemetry.exists()


def test_conflicting_retry_and_false_success_claim_are_rejected(tmp_path: Path) -> None:
    outcome = _result(tmp_path)
    result = outcome.result
    path = write_ai_context_result(
        tmp_path / "out", result, signing_key=EVIDENCE_KEY, key_id="offline-evidence-key"
    )
    conflicting = replace(
        result,
        checks=(*result.checks, {"check_id": "additional_check", "status": "pass"}),
        content_digest="",
    )
    from smf.security.ai_policy import ai_digest

    unsigned = conflicting.to_dict()
    unsigned["content_digest"] = ""
    conflicting = replace(conflicting, content_digest=ai_digest(unsigned))
    with pytest.raises(ValueError, match="not reconstructable"):
        write_ai_context_result(
            tmp_path / "out",
            conflicting,
            signing_key=EVIDENCE_KEY,
            key_id="offline-evidence-key",
        )

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["parity_passed"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="trusted evidence proof is invalid"):
        load_ai_context_result(path, verification_keys=VERIFY_KEYS)


def test_self_authored_qualified_result_requires_trusted_proof(tmp_path: Path) -> None:
    outcome = _result(tmp_path)
    payload = outcome.result.to_dict()
    payload["context_digest"] = "f" * 64
    payload["context_byte_count"] = 1
    payload["checks"] = []
    from smf.security.ai_policy import ai_digest

    payload["content_digest"] = ""
    payload["content_digest"] = ai_digest(payload)
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="trusted evidence proof"):
        load_ai_context_result(forged, verification_keys=VERIFY_KEYS)
    with pytest.raises(ValueError, match="signing key"):
        write_ai_context_result(tmp_path / "out", outcome.result)


def test_one_workload_path_cannot_collide_with_another(tmp_path: Path) -> None:
    first = _result(tmp_path).result
    first_path = write_ai_context_result(
        tmp_path / "out", first, signing_key=EVIDENCE_KEY, key_id="offline-evidence-key"
    )
    second_request = {**first.request, "workload_id": "WL-two", "run_id": "run-two"}
    # A blocked result still receives an isolated workload/run path.
    from smf.security.ai_policy import ai_digest

    decision_id = "ai-" + ai_digest(
        {"contract": "smf-ai-context-admission-v1", "request": second_request}
    )
    second = replace(
        first,
        decision_id=decision_id,
        request=second_request,
        state=AIAdmissionState.BLOCKED_MISSING,
        blocker_codes=("classification_missing",),
        permitted_artifact_ids=(),
        permitted_fields=(),
        context_digest=None,
        context_byte_count=None,
        terminal_disposition="context_not_qualified",
        context_qualified=False,
        content_digest="",
    )
    unsigned = second.to_dict()
    unsigned["content_digest"] = ""
    second = replace(second, content_digest=ai_digest(unsigned))
    second_path = write_ai_context_result(
        tmp_path / "out", second, signing_key=EVIDENCE_KEY, key_id="offline-evidence-key"
    )
    assert first_path != second_path
    assert first_path.exists() and second_path.exists()
