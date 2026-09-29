from pathlib import Path

import pytest
from tests.unit.ai_context_test_support import write_policy

from smf.security.ai_policy import humana_ai_blockers, load_ai_context_policy


def test_policy_is_digest_bound_and_strict(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    policy = write_policy(path)
    assert policy.status == "active"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("max_context_bytes: 100000", "max_context_bytes: 99999"))
    with pytest.raises(ValueError, match="digest mismatch"):
        load_ai_context_policy(path)


def test_duplicate_policy_keys_and_malformed_enum_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    write_policy(path)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("status: active", "status: active\nstatus: active"))
    with pytest.raises(ValueError, match="Duplicate AI policy key"):
        load_ai_context_policy(path)

    write_policy(path)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("status: active", "status: aproved"))
    with pytest.raises(ValueError, match="Security schema validation failed"):
        load_ai_context_policy(path)


def test_humana_policy_remains_explicitly_blocked() -> None:
    blockers = set(humana_ai_blockers(Path("deployments/humana/security-policy.yaml")))
    assert {
        "endpoint_binding_pending",
        "endpoint_binding_missing",
        "model_binding_missing",
        "field_allowlist_missing",
        "artifact_allowlist_missing",
        "classification_authority_missing",
        "retention_policy_missing",
        "access_policy_missing",
        "submission_authority_missing",
    } <= blockers
