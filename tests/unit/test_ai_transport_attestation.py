from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

from tests.unit.ai_transport_test_support import AUTHORITY_KEY, make_transport_case

from smf.security.ai_transport_attestation import (
    attestation_digest,
    attestation_payload,
    verify_submission_evidence,
)
from smf.security.ai_transport_models import AITransportState


def test_submission_is_bound_to_exact_transport_attempt(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    request = replace(case["request"], transport_attempt_id="transport-attempt-two")
    state, code, _ = verify_submission_evidence(
        case["submission"],
        request,
        authority="submission-owner",
        verification_keys={"authority-key": AUTHORITY_KEY.public_key()},
    )
    assert state is AITransportState.INVALID_BINDING
    assert code == "submission_evidence_invalid"


def test_missing_pending_and_denied_are_distinct(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    state, code, _ = verify_submission_evidence(
        None,
        case["request"],
        authority="submission-owner",
        verification_keys={"authority-key": AUTHORITY_KEY.public_key()},
    )
    assert (state, code) == (AITransportState.BLOCKED_MISSING, "submission_evidence_missing")

    for evidence_state, expected in (
        ("pending", AITransportState.BLOCKED_PENDING),
        ("denied", AITransportState.DENIED),
    ):
        evidence = dict(case["submission"])
        evidence["proof"] = dict(evidence["proof"])
        evidence["state"] = evidence_state
        evidence["proof"]["value"] = base64.b64encode(
            AUTHORITY_KEY.sign(attestation_payload(evidence))
        ).decode("ascii")
        request = replace(case["request"], submission_evidence_digest=attestation_digest(evidence))
        state, _, _ = verify_submission_evidence(
            evidence,
            request,
            authority="submission-owner",
            verification_keys={"authority-key": AUTHORITY_KEY.public_key()},
        )
        assert state is expected
