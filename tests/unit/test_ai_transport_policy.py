from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from tests.unit.ai_transport_test_support import CONFIG_KEY, make_transport_case

from smf.security.ai_transport_models import AITransportRequest
from smf.security.ai_transport_policy import (
    load_ai_endpoint_binding,
    load_ai_transport_policy,
)


def test_signed_policy_and_endpoint_are_loaded_from_trusted_snapshots(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    keys = {"configuration-key": CONFIG_KEY.public_key()}
    policy = load_ai_transport_policy(case["policy_path"], verification_keys=keys)
    endpoint = load_ai_endpoint_binding(case["endpoint_path"], verification_keys=keys)
    assert policy.status == "active"
    assert endpoint.url == "https://approved.example.test/v1/messages"


@pytest.mark.parametrize(
    "url",
    [
        "http://approved.example.test/v1/messages",
        "https://user@approved.example.test/v1/messages",
        "https://approved.example.test/v1/messages?next=evil",
        "https://approved.example.test/%2e%2e/evil",
        "https://127.0.0.1/v1/messages",
    ],
)
def test_endpoint_canonicalization_rejects_boundary_escape(tmp_path: Path, url: str) -> None:
    case = make_transport_case(tmp_path)
    value = json.loads(case["endpoint_path"].read_text())
    value["url"] = url
    case["endpoint_path"].write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_ai_endpoint_binding(
            case["endpoint_path"],
            verification_keys={"configuration-key": CONFIG_KEY.public_key()},
        )


def test_unknown_policy_enum_and_poisoned_signature_fail_closed(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    value = json.loads(case["policy_path"].read_text())
    value["status"] = "enabled"
    case["policy_path"].write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_ai_transport_policy(
            case["policy_path"],
            verification_keys={"configuration-key": CONFIG_KEY.public_key()},
        )


def test_duplicate_identity_and_protected_evidence_ref_are_rejected(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    request: AITransportRequest = case["request"]
    with pytest.raises(ValueError, match="unambiguous"):
        replace(request, permitted_artifact_ids=("ART-main", "art-MAIN"))
    with pytest.raises(ValueError, match="safe evidence reference"):
        replace(request, endpoint_binding_ref="evidence://patient/123-45-6789")
