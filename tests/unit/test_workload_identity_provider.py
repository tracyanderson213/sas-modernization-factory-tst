import copy
import dataclasses
import json
import logging
import pickle

import pytest

from smf.security import IdentityResponse, SecretResponse, TransientMaterial


def test_transient_material_redacts_refuses_serialization_and_zeroes() -> None:
    material = TransientMaterial(b"token-canary")
    assert "token-canary" not in repr(material)
    with pytest.raises(TypeError):
        pickle.dumps(material)
    with material as active:
        assert bytes(active.view()) == b"token-canary"
    assert material.closed
    with pytest.raises(RuntimeError):
        material.view()


def test_identity_response_is_metadata_plus_transient_input_only() -> None:
    response = IdentityResponse(bytearray(b"token"), "issuer", "audience", "2099-01-01T00:00:00Z")
    assert response.token == bytearray(b"token")
    response.clear()
    assert response.token == bytearray(len(b"token"))


@pytest.mark.parametrize(
    "response",
    [
        IdentityResponse(
            bytearray(b"identity-response-canary"),
            "issuer",
            "audience",
            "2099-01-01T00:00:00Z",
        ),
        SecretResponse(
            bytearray(b"secret-response-canary"),
            "v1",
            "2026-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            False,
        ),
    ],
)
def test_credential_responses_redact_and_refuse_copy_or_serialization(
    response: IdentityResponse | SecretResponse,
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = bytes(response.token if isinstance(response, IdentityResponse) else response.value)
    for rendered in (repr(response), str(response), repr(RuntimeError(response))):
        assert canary.decode() not in rendered
        assert "<redacted>" in rendered
    with pytest.raises(TypeError):
        pickle.dumps(response)
    with pytest.raises(TypeError):
        json.dumps(response)
    with pytest.raises(TypeError):
        dataclasses.asdict(response)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        copy.copy(response)
    with pytest.raises(TypeError):
        copy.deepcopy(response)
    logging.getLogger("credential-test").warning("provider response: %r", response)
    assert canary.decode() not in caplog.text
    assert "<redacted>" in caplog.text
