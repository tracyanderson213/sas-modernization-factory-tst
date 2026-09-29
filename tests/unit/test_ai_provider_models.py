from __future__ import annotations

import copy
import hashlib
import pickle
from dataclasses import replace

import pytest
from tests.unit.ai_provider_test_support import CONTEXT, make_provider_request

from smf.ai.models import (
    AdvisoryEvidenceReference,
    AIOperation,
    TransientAIProviderBytes,
)


def test_request_is_versioned_strict_and_reconstructable() -> None:
    request = make_provider_request()
    assert request.schema_version == "1.0"
    assert request.bindings()["operation"] == "convert"
    assert (
        request.request_digest
        == hashlib.sha256(
            __import__("json")
            .dumps(request.bindings(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            .encode()
        ).hexdigest()
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("operation", "convertt", "strict enums"),
        ("target", "databricks", "strict enums"),
        ("configuration_state", "approved", "strict enum"),
        ("client_id", "123-45-6789", "non-protected"),
        ("client_id", "patient@example.com", "non-protected"),
        ("sec02_result_ref", "evidence://safe/../foreign", "safe evidence"),
        ("context_digest", "not-a-digest", "canonical SHA-256"),
    ],
)
def test_request_rejects_malformed_enum_identity_reference_and_digest(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(make_provider_request(), **{field: value})


def test_request_rejects_empty_and_duplicate_subject_evidence() -> None:
    with pytest.raises(ValueError, match="non-empty and unambiguous"):
        replace(make_provider_request(), source_artifact_ids=())
    with pytest.raises(ValueError, match="non-empty and unambiguous"):
        replace(make_provider_request(), source_artifact_ids=("Main", "main"))
    with pytest.raises(ValueError, match="must not be empty"):
        replace(make_provider_request(), context_byte_count=0)


def test_advisory_evidence_cannot_cross_client_source_or_policy_boundary() -> None:
    request = make_provider_request()
    advisory = AdvisoryEvidenceReference(
        evidence_ref="evidence://recall/advice-one",
        origin_id="learn-one",
        applicability_id="conversion",
        version="1.0",
        selection_reason_id="exact-construct",
        client_id="other-client",
        source_digest=request.source_closure_digest,
        policy_digest=request.prompt_policy_digest,
        conflict_disposition="none",
    )
    with pytest.raises(ValueError, match="crosses the request boundary"):
        replace(request, advisory_evidence=(advisory,))


def test_transient_bytes_copy_input_and_cannot_be_copied_or_serialized() -> None:
    mutable = bytearray(CONTEXT)
    transient = TransientAIProviderBytes(mutable)
    mutable[:4] = b"xxxx"
    assert transient.value == CONTEXT
    assert "eligible" not in repr(transient)
    with pytest.raises(TypeError):
        copy.copy(transient)
    with pytest.raises(TypeError):
        copy.deepcopy(transient)
    with pytest.raises(TypeError):
        pickle.dumps(transient)


def test_enum_constructor_rejects_unknown_value() -> None:
    with pytest.raises(ValueError):
        AIOperation("convertt")
