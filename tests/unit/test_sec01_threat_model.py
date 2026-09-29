from __future__ import annotations

import copy
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

import smf.security.threat_model as threat_model_module
from smf.security.threat_model import load_security_threat_model, threat_model_digest

MODEL = Path("docs/architecture/security-threat-model.yaml")


def _payload() -> dict[str, Any]:
    value = yaml.safe_load(MODEL.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_model(tmp_path: Path, payload: dict[str, Any]) -> Path:
    payload["content_digest"] = threat_model_digest(payload)
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _rejects(tmp_path: Path, mutation: Callable[[dict[str, Any]], None], match: str) -> None:
    payload = copy.deepcopy(_payload())
    mutation(payload)
    with pytest.raises(ValueError, match=match):
        load_security_threat_model(_write_model(tmp_path, payload))


def test_loads_digest_bound_model_with_complete_references() -> None:
    model = load_security_threat_model(MODEL)
    assert model.model_id == "smf-competition-threat-model"
    assert model.content_digest == threat_model_digest(model.payload)
    assert model.snapshot_bytes == MODEL.read_bytes()
    assert {item["id"] for item in model.payload["threats"]} >= {
        "prompt-injection",
        "cross-client-retrieval",
    }
    with pytest.raises(TypeError):
        model.payload["model_id"] = "changed"  # type: ignore[index]
    with pytest.raises(AttributeError):
        model.payload["threats"].append({})


def test_content_mutation_without_digest_update_is_rejected(tmp_path: Path) -> None:
    payload = copy.deepcopy(_payload())
    payload["scope"] += " changed"
    path = tmp_path / "stale-digest.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="content digest mismatch"):
        load_security_threat_model(path)


def test_covers_each_required_trust_boundary_and_keeps_ai_blocked() -> None:
    model = load_security_threat_model(MODEL)
    kinds = {item["kind"] for item in model.payload["boundaries"]}
    assert kinds == {
        "source_ingestion",
        "canonical_evidence",
        "advisory_recall",
        "ai_transport",
        "durable_storage",
        "identity_secrets",
        "runtime",
        "validation",
        "human_approval",
        "engineering_worktree",
    }
    ai = next(item for item in model.payload["boundaries"] if item["kind"] == "ai_transport")
    assert ai["implementation_state"] == "target"
    assert "ai_submission" in ai["blocked_operations"]
    assert model.payload["lifecycle_claim"] == "architecture_evidence_only"


def test_rejects_duplicate_yaml_keys_before_schema_or_digest(tmp_path: Path) -> None:
    text = MODEL.read_text(encoding="utf-8")
    path = tmp_path / "duplicate.yaml"
    duplicate = text.replace(
        'schema_version: "1.0"',
        'schema_version: "1.0"\nschema_version: "1.0"',
        1,
    )
    path.write_text(duplicate)
    with pytest.raises(ValueError, match="Duplicate threat-model key"):
        load_security_threat_model(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "severe"),
        ("residual_status", "ignored"),
        ("review_disposition", "approved"),
    ],
)
def test_malformed_threat_enums_fail_closed(tmp_path: Path, field: str, value: str) -> None:
    _rejects(
        tmp_path,
        lambda payload: payload["threats"][0].__setitem__(field, value),
        "Security schema validation failed",
    )


def test_untrusted_text_cannot_grant_authority(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda payload: payload["flows"][0].__setitem__("grants_authority", True),
        "Untrusted or advisory data cannot grant authority|Security schema validation failed",
    )


def test_self_asserted_pass_cannot_authorize_success(tmp_path: Path) -> None:
    _rejects(
        tmp_path,
        lambda payload: payload["controls"][0].__setitem__("authorizes_success", True),
        "Security schema validation failed",
    )


def test_evidence_cannot_drop_attempt_binding(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["evidence_contract"]["required_identity_bindings"].remove("attempt_id")

    _rejects(tmp_path, mutate, "Evidence contract is missing exact authority bindings")


def test_each_flow_requires_exact_source_policy_and_decision_binding(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["flows"][0]["required_identity_fields"].remove("source_digest")

    _rejects(tmp_path, mutate, "Flow evidence is not bound")


def test_pending_and_denied_cannot_be_collapsed(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["evidence_contract"]["claim_states"].remove("denied")

    _rejects(tmp_path, mutate, "Lifecycle claims must remain separate")


def test_empty_or_nonconvertible_success_invariant_cannot_be_disabled(
    tmp_path: Path,
) -> None:
    _rejects(
        tmp_path,
        lambda payload: payload["evidence_contract"].__setitem__(
            "meaningful_eligible_subject_required", False
        ),
        "Security schema validation failed|mandatory evidence invariant",
    )


def test_skipped_as_success_claims_cannot_be_removed(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["evidence_contract"]["claim_states"].remove("skipped")

    _rejects(tmp_path, mutate, "Lifecycle claims must remain separate")


def test_case_ambiguous_identity_is_rejected(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        duplicate = copy.deepcopy(payload["controls"][0])
        duplicate["id"] = payload["controls"][0]["id"].upper()
        payload["controls"].append(duplicate)

    _rejects(tmp_path, mutate, "Security schema validation failed|case-ambiguous")


def test_unresolved_high_risk_requires_named_operation_blocker(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["threats"][0]["blocked_operations"] = []

    _rejects(tmp_path, mutate, "Residual high-impact threats must fail closed")


def test_partially_mitigated_high_risk_also_requires_blocker(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        threat = next(item for item in payload["threats"] if item["id"] == "forged-attestation")
        threat["blocked_operations"] = []

    _rejects(tmp_path, mutate, "Residual high-impact threats must fail closed")


def test_high_risk_cannot_be_declared_mitigated_by_target_controls(
    tmp_path: Path,
) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        threat = next(item for item in payload["threats"] if item["id"] == "prompt-injection")
        threat["residual_status"] = "mitigated"
        threat["review_disposition"] = "no_blocker"
        threat["blocked_operations"] = []

    _rejects(tmp_path, mutate, "implemented evidence-backed controls")


def test_high_risk_cannot_be_self_accepted_without_governed_approval(
    tmp_path: Path,
) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        threat = next(item for item in payload["threats"] if item["id"] == "weak-validation")
        threat["residual_status"] = "accepted"
        threat["review_disposition"] = "no_blocker"
        threat["blocked_operations"] = []

    _rejects(tmp_path, mutate, "governed risk-acceptance evidence")


@pytest.mark.parametrize(
    "collection,key",
    [
        ("boundaries", "blocked_operations"),
        ("flows", "blocked_operations"),
        ("threats", "blocked_operations"),
        ("unresolved_inputs", "blocks"),
    ],
)
def test_unknown_blocked_operation_fails_closed(tmp_path: Path, collection: str, key: str) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload[collection][0][key] = ["ai_submision"]

    _rejects(tmp_path, mutate, "Security schema validation failed|Unknown blocked operation")


def test_repository_references_cannot_escape(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["controls"][0]["evidence_refs"] = ["../outside.txt"]

    _rejects(tmp_path, mutate, "Security schema validation failed|escapes repository scope")


def test_secret_canary_cannot_enter_durable_model(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["threats"][0]["scenario"] += " secret-canary-redacted"

    _rejects(tmp_path, mutate, "sensitive durable content")


@pytest.mark.parametrize(
    ("location", "unsafe_value"),
    [
        ("scope", "SSN=123-45-6789"),
        ("owner_role", "patient@example.com"),
        ("boundary_name", "DOB=1970-01-02"),
        ("control_description", "password=credential-canary"),
        ("threat_title", "MRN=12345678"),
        ("threat_scenario", "member_id=HUM-123456"),
        ("evidence_requirement", "%53%53%4E%3D123-45-6789"),
        ("evidence_requirement", "U1NOPTEyMy00NS02Nzg5"),
    ],
)
def test_sensitive_content_is_rejected_across_free_text_fields_before_hashing(
    tmp_path: Path, location: str, unsafe_value: str
) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        if location == "scope":
            payload["scope"] += f" {unsafe_value}"
        elif location == "owner_role":
            payload["owners"][0]["role"] += f" {unsafe_value}"
        elif location == "boundary_name":
            payload["boundaries"][0]["name"] += f" {unsafe_value}"
        elif location == "control_description":
            payload["controls"][0]["description"] += f" {unsafe_value}"
        elif location == "threat_title":
            payload["threats"][0]["title"] += f" {unsafe_value}"
        elif location == "threat_scenario":
            payload["threats"][0]["scenario"] += f" {unsafe_value}"
        else:
            payload["threats"][0]["evidence_requirements"].append(unsafe_value)

    payload = copy.deepcopy(_payload())
    mutate(payload)
    payload["content_digest"] = threat_model_digest(payload)
    path = tmp_path / "sensitive-model.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive durable content"):
        load_security_threat_model(path)


def test_sensitive_content_is_inspected_before_digest_calculation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = copy.deepcopy(_payload())
    payload["threats"][0]["scenario"] += " SSN=123-45-6789"
    payload["content_digest"] = "0" * 64
    path = tmp_path / "prehash-sensitive-model.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    def unexpected_digest(_: object) -> str:
        raise AssertionError("unsafe content reached digest calculation")

    monkeypatch.setattr(threat_model_module, "threat_model_digest", unexpected_digest)
    with pytest.raises(ValueError, match="sensitive durable content"):
        load_security_threat_model(path)


def test_advisory_recall_cannot_drop_conflict_provenance(tmp_path: Path) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        payload["advisory_recall"]["required_provenance_fields"].remove("conflicts")

    _rejects(tmp_path, mutate, "Advisory recall provenance or authority is incomplete")


def test_canonical_evidence_and_derived_recovery_invariants_are_mandatory(
    tmp_path: Path,
) -> None:
    for field in ("immutable_canonical_evidence", "idempotent_derived_recovery"):
        payload = copy.deepcopy(_payload())
        payload["evidence_contract"][field] = False
        with pytest.raises(
            ValueError, match="Security schema validation failed|evidence invariant"
        ):
            load_security_threat_model(_write_model(tmp_path, payload))


def test_mutated_bound_configuration_invalidates_model(tmp_path: Path) -> None:
    payload = copy.deepcopy(_payload())
    references: set[str] = set()
    references.update(item["path"] for item in payload["referenced_bindings"])
    for control in payload["controls"]:
        references.update(control["implementation_refs"])
        references.update(control["evidence_refs"])
    for relative in references:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(relative, destination)
    security_policy = tmp_path / "deployments/humana/security-policy.yaml"
    security_policy.write_bytes(security_policy.read_bytes() + b"\n# changed after qualification\n")
    path = _write_model(tmp_path, payload)
    with pytest.raises(ValueError, match="Referenced binding digest changed"):
        load_security_threat_model(path, repository_root=tmp_path)
