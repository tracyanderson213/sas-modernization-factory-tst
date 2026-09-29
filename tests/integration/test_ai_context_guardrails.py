from pathlib import Path
from unittest.mock import patch

from tests.unit.ai_context_test_support import make_case

from smf.security.ai_admission import qualify_ai_context


def test_offline_guardrail_has_no_network_or_provider_dependency(tmp_path: Path) -> None:
    policy, request, evidence, manifest = make_case(tmp_path)
    with (
        patch("smf.security.ai_admission.load_manifest", return_value=manifest),
        patch("socket.socket", side_effect=AssertionError("network use is forbidden")),
    ):
        outcome = qualify_ai_context(
            request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=evidence,
        )
    assert outcome.result.context_qualified
    assert not outcome.result.transport_attempted
    assert not outcome.result.submission_authorized
