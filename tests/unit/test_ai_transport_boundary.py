from __future__ import annotations

import hashlib
import inspect
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.unit.ai_transport_test_support import (
    AUTHORITY_KEY,
    CONFIG_KEY,
    EVIDENCE_KEY,
    fresh_buffers,
    make_transport_case,
    rebind_transport_attestations,
)

from smf.security.ai_transport import _send_https_once, guarded_ai_transport
from smf.security.ai_transport_models import AITransportResponse, AITransportState
from smf.security.ai_transport_policy import load_ai_endpoint_binding


class RecordingSender:
    def __init__(self, response: AITransportResponse | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response = response or AITransportResponse(
            status_code=200, body=b'{"content":"synthetic"}', media_type="application/json"
        )

    def send(self, **kwargs: Any) -> AITransportResponse:
        self.calls.append(kwargs)
        return self.response


def _invoke(tmp_path: Path, case: dict[str, Any], sender: RecordingSender, **changes: Any):
    payload, context, credential = fresh_buffers(case)
    values = {
        "submission_evidence": case["submission"],
        "identity_evidence": case["identity"],
        "credential_evidence": case["credential_evidence"],
        "payload_classification_evidence": case["payload_classification"],
    }
    values.update(changes)
    with patch("smf.security.ai_transport._send_https_once", side_effect=sender.send):
        return guarded_ai_transport(
            case["request"],
            payload=payload,
            context=context,
            credential=credential,
            transport_policy_path=case["policy_path"],
            endpoint_binding_path=case["endpoint_path"],
            sec02_result_path=case["sec02_path"],
            configuration_keys={"configuration-key": CONFIG_KEY.public_key()},
            sec02_keys={"evidence-key": EVIDENCE_KEY.public_key()},
            identity_keys={"authority-key": AUTHORITY_KEY.public_key()},
            credential_keys={"authority-key": AUTHORITY_KEY.public_key()},
            payload_classification_keys={"authority-key": AUTHORITY_KEY.public_key()},
            submission_keys={"authority-key": AUTHORITY_KEY.public_key()},
            evidence_keys={"evidence-key": EVIDENCE_KEY.public_key()},
            evidence_root=tmp_path / "transport-evidence",
            evidence_signing_key=EVIDENCE_KEY,
            evidence_key_id="evidence-key",
            **values,
        )


def test_positive_transport_uses_only_bound_endpoint_and_no_success_inflation(
    tmp_path: Path,
) -> None:
    case = make_transport_case(tmp_path)
    sender = RecordingSender()
    result = _invoke(tmp_path, case, sender)
    assert result.state is AITransportState.RESPONSE_RECEIVED
    assert len(sender.calls) == 1
    assert sender.calls[0]["url"] == "https://approved.example.test/v1/messages"
    assert set(sender.calls[0]) == {
        "url",
        "method",
        "payload",
        "media_type",
        "credential",
        "max_response_bytes",
    }
    assert result.submission_authorized and result.transport_attempted
    assert not result.generated and not result.validated and not result.parity_passed


def test_missing_submission_blocks_with_zero_network_calls(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    sender = RecordingSender()
    result = _invoke(tmp_path, case, sender, submission_evidence=None)
    assert result.state is AITransportState.BLOCKED_MISSING
    assert result.blocker_codes == ("submission_evidence_missing",)
    assert sender.calls == []


def test_missing_payload_classification_blocks_with_zero_network_calls(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    sender = RecordingSender()
    result = _invoke(tmp_path, case, sender, payload_classification_evidence=None)
    assert result.state is AITransportState.BLOCKED_MISSING
    assert result.blocker_codes == ("payload_classification_evidence_missing",)
    assert sender.calls == []


def test_arbitrary_payload_mutation_invalidates_classification_binding(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    stale_classification = case["payload_classification"]
    stale_digest = case["request"].payload_classification_evidence_digest
    changed = b'{"task":"summarize an unrelated unclassified record"}'
    case["request"] = replace(
        case["request"],
        payload_digest=hashlib.sha256(changed).hexdigest(),
        payload_byte_count=len(changed),
    )
    case["payload_bytes"] = changed
    rebind_transport_attestations(case)
    case["request"] = replace(case["request"], payload_classification_evidence_digest=stale_digest)
    case["payload_classification"] = stale_classification
    sender = RecordingSender()
    result = _invoke(tmp_path, case, sender)
    assert result.state is AITransportState.INVALID_BINDING
    assert result.blocker_codes == ("payload_classification_evidence_invalid",)
    assert sender.calls == []


def test_missing_protected_configuration_is_a_durable_blocker(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    case["endpoint_path"].unlink()
    sender = RecordingSender()
    result = _invoke(tmp_path, case, sender)
    assert result.state is AITransportState.BLOCKED_MISSING
    assert result.blocker_codes == ("trusted_prerequisite_unavailable",)
    assert sender.calls == []
    assert list((tmp_path / "transport-evidence").rglob("result.json"))


def test_redirect_is_terminal_and_location_is_not_contacted(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    sender = RecordingSender(
        AITransportResponse(
            status_code=307,
            body=b"redirect",
            media_type="text/plain",
            redirect_location="https://evil.example/steal",
        )
    )
    result = _invoke(tmp_path, case, sender)
    assert result.state is AITransportState.REDIRECT_REJECTED
    assert len(sender.calls) == 1
    assert "evil.example" not in str(result.to_dict())


def test_concrete_transport_cannot_redirect_or_select_fallback() -> None:
    connections: list[tuple[str, dict[str, Any]]] = []

    class RedirectResponse:
        status = 307

        def read(self, limit: int) -> bytes:
            assert limit == 1025
            return b"redirect"

        def getheader(self, name: str, default: str = "") -> str:
            if name == "Location":
                return "https://evil.example/steal"
            return "text/plain"

    class FakeHTTPSConnection:
        def __init__(self, host: str, **kwargs: Any) -> None:
            connections.append((host, kwargs))

        def request(self, *args: Any, **kwargs: Any) -> None:
            return None

        def getresponse(self) -> RedirectResponse:
            return RedirectResponse()

        def close(self) -> None:
            return None

    with patch("smf.security.ai_transport.http.client.HTTPSConnection", FakeHTTPSConnection):
        response = _send_https_once(
            url="https://approved.example.test/v1/messages",
            method="POST",
            payload=b"{}",
            media_type="application/json",
            credential=b"credential",
            max_response_bytes=1024,
        )

    assert response.status_code == 307
    assert len(connections) == 1
    host, options = connections[0]
    assert host == "approved.example.test"
    assert options["port"] == 443
    assert options["context"].verify_mode is ssl.CERT_REQUIRED
    assert options["context"].check_hostname is True
    assert "sender" not in inspect.signature(guarded_ai_transport).parameters


def test_protected_payload_blocks_before_sender(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    unsafe = b'{"prompt":"patient@example.com"}'
    unsafe_digest = hashlib.sha256(unsafe).hexdigest()
    case["request"] = replace(
        case["request"],
        payload_digest=unsafe_digest,
        payload_byte_count=len(unsafe),
    )
    case["payload_bytes"] = unsafe
    rebind_transport_attestations(case)
    sender = RecordingSender()
    result = _invoke(tmp_path, case, sender)
    assert result.state is AITransportState.DENIED
    assert result.blocker_codes == ("protected_data_detected",)
    assert sender.calls == []
    evidence_text = "\n".join(
        path.read_text() for path in (tmp_path / "transport-evidence").rglob("*.json")
    )
    assert "patient@example.com" not in evidence_text
    assert unsafe_digest not in evidence_text


def test_unclassified_phone_and_member_payloads_block_before_sender(tmp_path: Path) -> None:
    for index, unsafe in enumerate(
        (
            b'{"prompt":"call patient at 212-555-1212"}',
            b'{"prompt":"member number ABC1234567"}',
        )
    ):
        case_root = tmp_path / f"case-{index}"
        case_root.mkdir()
        case = make_transport_case(case_root)
        case["request"] = replace(
            case["request"],
            payload_digest=hashlib.sha256(unsafe).hexdigest(),
            payload_byte_count=len(unsafe),
        )
        case["payload_bytes"] = unsafe
        rebind_transport_attestations(case)
        sender = RecordingSender()
        result = _invoke(tmp_path / f"case-{index}", case, sender)
        assert result.state is AITransportState.DENIED
        assert sender.calls == []


def test_existing_dispatch_without_result_never_resends(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    sender = RecordingSender()
    first = _invoke(tmp_path, case, sender)
    evidence = (
        tmp_path
        / "transport-evidence"
        / "runs"
        / case["request"].run_id
        / "workloads"
        / case["request"].workload_id
        / "attempts"
        / case["request"].workflow_attempt_id
        / "security"
        / "ai-transport"
        / case["request"].provider_request_id
        / case["request"].transport_attempt_id
    )
    (evidence / "result.json").unlink()
    (evidence / "telemetry.json").unlink()
    second = _invoke(tmp_path, case, sender)
    assert first.state is AITransportState.RESPONSE_RECEIVED
    assert second.state is AITransportState.OUTCOME_UNKNOWN
    assert len(sender.calls) == 1


def test_retry_recovers_missing_telemetry_without_resending(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    sender = RecordingSender()
    first = _invoke(tmp_path, case, sender)
    result_path = next((tmp_path / "transport-evidence").rglob("result.json"))
    canonical = result_path.read_bytes()
    telemetry_path = result_path.with_name("telemetry.json")
    telemetry_path.unlink()

    second = _invoke(tmp_path, case, sender)

    assert first == second
    assert result_path.read_bytes() == canonical
    assert telemetry_path.is_file()
    assert len(sender.calls) == 1


def test_concurrent_identical_attempt_has_one_dispatch_claimant(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    class BlockingSender(RecordingSender):
        def send(self, **kwargs: Any) -> AITransportResponse:
            self.calls.append(kwargs)
            entered.set()
            assert release.wait(timeout=5)
            return self.response

    sender = BlockingSender()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(_invoke, tmp_path, case, sender)
        assert entered.wait(timeout=5)
        second = pool.submit(_invoke, tmp_path, case, sender)
        second_result = second.result(timeout=5)
        release.set()
        first_result = first.result(timeout=5)

    assert len(sender.calls) == 1
    assert first_result.state is AITransportState.RESPONSE_RECEIVED
    assert second_result.state in {
        AITransportState.RESPONSE_RECEIVED,
        AITransportState.OUTCOME_UNKNOWN,
    }
    assert len(list((tmp_path / "transport-evidence").rglob("result.json"))) == 1


def test_endpoint_mutation_between_checks_blocks_before_dispatch(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    sender = RecordingSender()
    endpoint = load_ai_endpoint_binding(
        case["endpoint_path"],
        verification_keys={"configuration-key": CONFIG_KEY.public_key()},
    )
    changed = replace(endpoint, snapshot=endpoint.snapshot + b" ")
    with patch(
        "smf.security.ai_transport.load_ai_endpoint_binding",
        side_effect=[endpoint, changed],
    ):
        result = _invoke(tmp_path, case, sender)
    assert result.state is AITransportState.INVALID_BINDING
    assert result.blocker_codes == ("configuration_changed_before_dispatch",)
    assert sender.calls == []


def test_workload_attempt_paths_are_isolated(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    first = _invoke(tmp_path, case, RecordingSender())
    second_case = dict(case)
    second_case["request"] = replace(
        case["request"],
        workload_id="WL-two",
        run_id="run-two",
        provider_request_id="provider-request-two",
        transport_attempt_id="transport-attempt-two",
    )
    # Replayed authority evidence cannot authorize the changed workload.
    sender = RecordingSender()
    second = _invoke(tmp_path, second_case, sender)
    assert first.state is AITransportState.RESPONSE_RECEIVED
    assert second.state is AITransportState.INVALID_BINDING
    assert sender.calls == []
