from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.unit.ai_context_test_support import make_case, resign

from smf.security.ai_admission import (
    classification_digest,
    qualify_ai_context,
    sanitize_provider_diagnostic,
)
from smf.security.ai_models import AIAdmissionState, AIContextRequest


def _qualify(tmp_path: Path, **overrides: object):
    policy, request, evidence, manifest = make_case(tmp_path)
    request = overrides.get("request", request)
    evidence = overrides.get("evidence", evidence)
    manifest = overrides.get("manifest", manifest)
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        return qualify_ai_context(
            request,  # type: ignore[arg-type]
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=evidence,  # type: ignore[arg-type]
        )


def test_positive_offline_qualification_is_transient_and_never_authorizes_submission(
    tmp_path: Path,
) -> None:
    outcome = _qualify(tmp_path)
    assert outcome.result.state is AIAdmissionState.QUALIFIED_OFFLINE
    assert outcome.result.context_qualified
    assert not outcome.result.submission_authorized
    assert not outcome.result.transport_attempted
    assert not outcome.result.generated
    assert outcome.context is not None
    assert outcome.context.digest == outcome.result.context_digest
    assert "data output" not in repr(outcome.context)
    original = outcome.context.value
    assert isinstance(original, bytes)
    with pytest.raises(TypeError):
        outcome.context.value[0] = 0  # type: ignore[index]
    assert outcome.context.value == original
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(outcome.context)
    outcome.context.clear()
    assert set(outcome.context.value) == {0}


@pytest.mark.parametrize(
    "field",
    [
        "client_id",
        "deployment_id",
        "environment_id",
        "workload_id",
        "boundary_id",
        "subject_id",
        "run_id",
        "attempt_id",
        "consumer_id",
        "consumer_contract_version",
        "strategy_version",
        "readiness_result_id",
        "context_policy_id",
        "context_policy_version",
        "classification_policy_id",
        "classification_policy_version",
        "provider_id",
        "model_id",
        "endpoint_binding_id",
        "classification_evidence_id",
        "retention_policy_ref",
        "access_policy_ref",
    ],
)
def test_protected_data_in_request_identity_is_rejected_before_hashing(
    tmp_path: Path, field: str
) -> None:
    _, request, _, _ = make_case(tmp_path)
    with pytest.raises(ValueError, match="protected data"):
        replace(request, **{field: "123-45-6789"})


@pytest.mark.parametrize("field", ["requested_artifact_ids", "requested_fields"])
def test_protected_data_in_request_collections_is_rejected_before_hashing(
    tmp_path: Path, field: str
) -> None:
    _, request, _, _ = make_case(tmp_path)
    with pytest.raises(ValueError, match="protected data"):
        replace(request, **{field: ("secret-canary",)})


@pytest.mark.parametrize(
    "content",
    [
        b"this is prose about data bananas, not a SAS program",
        b"data bananas",
        b"data bananas; this is still prose",
        b"proc bananas",
        b"proc bananas; no terminating step",
    ],
)
def test_prose_and_malformed_sas_tokens_never_qualify(tmp_path: Path, content: bytes) -> None:
    import hashlib

    from smf.security.ai_policy import ai_digest

    policy, request, evidence, manifest = make_case(tmp_path)
    (tmp_path / "main.sas").write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    manifest["qualification_input"]["workload"]["artifacts"][0]["checksum"] = digest
    inventory = [
        {
            "artifact_id": "ART-main",
            "kind": "sas_program",
            "logical_path": "main.sas",
            "sha256": digest,
        }
    ]
    request = replace(request, source_closure_digest=ai_digest(inventory))
    bindings = request.safe_bindings()
    bindings.pop("classification_evidence_id")
    bindings.pop("classification_evidence_digest")
    evidence["bindings"] = bindings
    evidence["artifacts"][0]["sha256"] = digest
    resign(evidence)
    request = replace(request, classification_evidence_digest=classification_digest(evidence))
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        outcome = qualify_ai_context(
            request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=evidence,
        )
    assert outcome.result.state is AIAdmissionState.BLOCKED_AMBIGUOUS
    assert "subject_not_meaningful" in outcome.result.blocker_codes


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("pending", AIAdmissionState.BLOCKED_PENDING),
        ("denied", AIAdmissionState.DENIED),
    ],
)
def test_pending_and_denied_remain_distinct(
    tmp_path: Path, state: str, expected: AIAdmissionState
) -> None:
    _, request, evidence, _ = make_case(tmp_path)
    evidence["state"] = state
    resign(evidence)
    request = replace(request, classification_evidence_digest=classification_digest(evidence))
    outcome = _qualify(tmp_path, request=request, evidence=evidence)
    assert outcome.result.state is expected
    assert outcome.context is None


def test_missing_unsigned_untrusted_and_replayed_classification_cannot_qualify(
    tmp_path: Path,
) -> None:
    policy, request, evidence, manifest = make_case(tmp_path)
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        missing = qualify_ai_context(
            request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=None,
        )
    assert missing.result.state is AIAdmissionState.BLOCKED_MISSING

    forged = copy.deepcopy(evidence)
    forged["bindings"]["run_id"] = "another-run"
    resign(forged)
    request = replace(request, classification_evidence_digest=classification_digest(forged))
    replayed = _qualify(tmp_path, request=request, evidence=forged)
    assert replayed.result.state is AIAdmissionState.INVALID_BINDING

    untrusted = copy.deepcopy(evidence)
    untrusted["proof"]["key_id"] = "attacker-key"
    request = replace(request, classification_evidence_digest=classification_digest(untrusted))
    rejected = _qualify(tmp_path, request=request, evidence=untrusted)
    assert rejected.result.state is AIAdmissionState.INVALID_BINDING


@pytest.mark.parametrize(
    "canary",
    [
        "SSN=123-45-6789",
        "email=patient@example.com",
        "DOB=1970-01-02",
        "MRN=ABC12345",
        "password=secret-canary",
        "email%3Dpatient%40example.com",
        "ZW1haWw9cGF0aWVudEBleGFtcGxlLmNvbQ==",
    ],
)
def test_protected_data_canaries_block_without_persisting_values(
    tmp_path: Path, canary: str
) -> None:
    policy, request, evidence, manifest = make_case(tmp_path)
    source = tmp_path / "main.sas"
    source.write_text(f"data output; set input; run; /* {canary} */\n", encoding="utf-8")
    # Even if untrusted readiness and classification claims are adjusted, the scanner blocks.
    import hashlib

    from smf.security.ai_policy import ai_digest

    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest["qualification_input"]["workload"]["artifacts"][0]["checksum"] = digest
    inventory = [
        {
            "artifact_id": "ART-main",
            "kind": "sas_program",
            "logical_path": "main.sas",
            "sha256": digest,
        }
    ]
    request = replace(request, source_closure_digest=ai_digest(inventory))
    bindings = request.safe_bindings()
    bindings.pop("classification_evidence_id")
    bindings.pop("classification_evidence_digest")
    evidence["bindings"] = bindings
    evidence["artifacts"][0]["sha256"] = digest
    resign(evidence)
    request = replace(request, classification_evidence_digest=classification_digest(evidence))
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        outcome = qualify_ai_context(
            request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=evidence,
        )
    assert outcome.result.state is AIAdmissionState.BLOCKED_AMBIGUOUS
    assert canary not in str(outcome.result.to_dict())


def test_toctou_mutation_empty_subject_and_incomplete_closure_fail_closed(tmp_path: Path) -> None:
    policy, request, evidence, manifest = make_case(tmp_path)
    (tmp_path / "main.sas").write_text("data changed; run;\n", encoding="utf-8")
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        mutated = qualify_ai_context(
            request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=evidence,
        )
    assert "artifact_digest_mismatch" in mutated.result.blocker_codes

    policy, request, evidence, manifest = make_case(tmp_path)
    manifest["qualification_input"]["workload"]["boundaries"][0]["artifact_ids"].append(
        "ART-missing"
    )
    incomplete = _qualify(tmp_path, request=request, evidence=evidence, manifest=manifest)
    assert incomplete.result.state is AIAdmissionState.INVALID_BINDING


@pytest.mark.parametrize("content", [b"", b"   \n", b"/* comment only */\n", b"data x;\x00run;\n"])
def test_empty_comments_only_and_opaque_subjects_never_qualify(
    tmp_path: Path, content: bytes
) -> None:
    import hashlib

    from smf.security.ai_policy import ai_digest

    policy, request, evidence, manifest = make_case(tmp_path)
    (tmp_path / "main.sas").write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    manifest["qualification_input"]["workload"]["artifacts"][0]["checksum"] = digest
    inventory = [
        {
            "artifact_id": "ART-main",
            "kind": "sas_program",
            "logical_path": "main.sas",
            "sha256": digest,
        }
    ]
    request = replace(request, source_closure_digest=ai_digest(inventory))
    bindings = request.safe_bindings()
    bindings.pop("classification_evidence_id")
    bindings.pop("classification_evidence_digest")
    evidence["bindings"] = bindings
    evidence["artifacts"][0]["sha256"] = digest
    resign(evidence)
    request = replace(request, classification_evidence_digest=classification_digest(evidence))
    with patch("smf.security.ai_admission.load_manifest", return_value=manifest):
        outcome = qualify_ai_context(
            request,
            readiness_manifest=tmp_path / "readiness.json",
            source_root=tmp_path,
            policy=policy,
            classification_evidence=evidence,
        )
    assert outcome.result.state is AIAdmissionState.BLOCKED_AMBIGUOUS
    assert not outcome.result.context_qualified


def test_duplicate_identity_and_malformed_request_enum_fail_closed(tmp_path: Path) -> None:
    _, request, evidence, manifest = make_case(tmp_path)
    duplicate = copy.deepcopy(manifest["qualification_input"]["workload"]["artifacts"][0])
    duplicate["artifact_id"] = "art-main"
    manifest["qualification_input"]["workload"]["artifacts"].append(duplicate)
    outcome = _qualify(tmp_path, request=request, evidence=evidence, manifest=manifest)
    assert "artifact_identity_ambiguous" in outcome.result.blocker_codes
    with pytest.raises(ValueError, match="Unsupported AI context request contract"):
        AIContextRequest(**{**request.safe_bindings(), "decision_purpose": "aproved"})


def test_provider_diagnostics_are_categorical_only() -> None:
    assert sanitize_provider_diagnostic("email=patient@example.com") == "provider_error_redacted"
    assert sanitize_provider_diagnostic("timeout") == "provider_error_present"
