from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.unit.ai_transport_test_support import EVIDENCE_KEY, make_transport_case

from smf.security.ai_policy import ai_digest
from smf.security.ai_transport_manifest import (
    load_transport_result,
    recover_transport_telemetry,
    write_transport_result,
)
from smf.security.ai_transport_models import AITransportResult, AITransportState


def _blocked(case: dict[str, Any]) -> AITransportResult:
    request = case["request"]
    return AITransportResult(
        schema_version="1.0",
        decision_id="ait-"
        + ai_digest({"contract": "smf-ai-transport-v1", "request": request.bindings()}),
        request=request.bindings(),
        state=AITransportState.BLOCKED_MISSING,
        blocker_codes=("submission_evidence_missing",),
        evidence_refs=(),
        response_status=None,
        response_digest=None,
        response_byte_count=None,
        elapsed_ms=0,
        context_qualified=True,
        submission_authorized=False,
        transport_attempted=False,
        response_received=False,
    )


def test_result_is_signed_append_only_and_telemetry_is_recoverable(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    path = write_transport_result(
        tmp_path / "out",
        _blocked(case),
        signing_key=EVIDENCE_KEY,
        key_id="evidence-key",
    )
    canonical = path.read_bytes()
    telemetry = path.with_name("telemetry.json")
    telemetry.unlink()
    recover_transport_telemetry(path, verification_keys={"evidence-key": EVIDENCE_KEY.public_key()})
    assert path.read_bytes() == canonical
    assert json.loads(telemetry.read_text())["blocked"] is True


def test_self_authored_false_success_is_not_evidence(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    path = write_transport_result(
        tmp_path / "out",
        _blocked(case),
        signing_key=EVIDENCE_KEY,
        key_id="evidence-key",
    )
    value = json.loads(path.read_text())
    value["parity_passed"] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="proof is invalid"):
        load_transport_result(path, verification_keys={"evidence-key": EVIDENCE_KEY.public_key()})
