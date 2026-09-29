from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.discovery.macro_strategy import (
    STRATEGY_DIGEST,
    STRATEGY_ID,
    STRATEGY_VERSION,
    strategy_snapshot,
)
from smf.readiness import (
    ReadinessClassification,
    ReadinessRequest,
    approval_subject_digest,
    evaluate_readiness,
    load_manifest,
    load_readiness_policy,
    readiness_event,
    write_manifest,
)
from smf.readiness.attestation import attestation_payload
from smf.readiness.policy import (
    canonical_json,
    digest_value,
    readiness_policy_from_dict,
    serialize_readiness_policy,
)
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

POLICY = Path("tests/fixtures/readiness-policy.yaml")


def attest_evidence(records):
    authenticated = sanitize_discovery_value(deepcopy(records))
    assert isinstance(authenticated, list)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    policy_digest = load_readiness_policy(POLICY).policy_digest
    for item in authenticated:
        item["policy_digest"] = policy_digest
        signature = key.sign(attestation_payload(item))
        item["proof"] = {
            "algorithm": "ed25519",
            "key_id": "humana-readiness-v1",
            "value": base64.b64encode(signature).decode("ascii"),
        }
    return tuple(authenticated)


def _workload(workload_id: str = "WL-one") -> dict[str, object]:
    discovery_evidence = [
        {
            "evidence_id": "DISC-1",
            "method": "filesystem",
            "source": "canonical-discovery",
            "confidence": "high",
        }
    ]
    workload: dict[str, object] = {
        "workload_id": workload_id,
        "name": "one",
        "artifacts": [
            {
                "artifact_id": "ART-main",
                "kind": "sas_program",
                "checksum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "evidence": discovery_evidence,
            }
        ],
        "datasets": [
            {"dataset_id": "DATA-in", "kind": "sas_dataset"},
            {"dataset_id": "DATA-out", "kind": "sas_dataset"},
        ],
        "relationships": [
            {"source_id": "ART-main", "kind": "reads", "target_id": "DATA-in"},
            {"source_id": "ART-main", "kind": "writes", "target_id": "DATA-out"},
        ],
        "external_dependencies": [],
        "dependency_graph": {"graph_id": "GRAPH-1", "unresolved": []},
        "outputs": [
            {
                "output_id": "OUT-1",
                "dataset_id": "DATA-out",
                "consumer_resolution": "confirmed",
                "consumer_ids": ["claims-reporting"],
            }
        ],
        "boundaries": [],
    }
    workload["macro_analysis"] = {
        "analysis_id": "pending",
        "discovery_id": "pending",
        "workload_id": workload_id,
        "strategy_id": STRATEGY_ID,
        "strategy_version": STRATEGY_VERSION,
        "strategy_digest": STRATEGY_DIGEST,
        "strategy_snapshot": strategy_snapshot(),
        "expansion_mode": "none",
        "complete": True,
        "source_inventory": [
            {
                "source_artifact_id": "ART-main",
                "source_checksum": "a" * 64,
            }
        ],
        "logical_artifacts": [],
        "observations": [],
        "resolutions": [],
        "blockers": [],
        "limits_applied": strategy_snapshot()["limits"],
    }
    macro = workload["macro_analysis"]
    assert isinstance(macro, dict)
    macro["discovery_id"] = stable_id(
        "MDISC",
        {
            "workload": workload_id,
            "inventory": macro["source_inventory"],
            "strategy": STRATEGY_DIGEST,
        },
    )
    macro["analysis_id"] = stable_id(
        "MAN",
        {
            "discovery": macro["discovery_id"],
            "workload": workload_id,
            "inventory": macro["source_inventory"],
            "strategy": STRATEGY_DIGEST,
            "limits": macro["limits_applied"],
            "logical_artifacts": [],
            "observations": [],
            "resolutions": [],
            "blockers": [],
            "complete": True,
        },
    )
    return workload


def _evidence(
    workload_id: str = "WL-one",
    workload: dict[str, object] | None = None,
    boundary_id: str | None = None,
) -> list[dict[str, object]]:
    now = datetime.now(UTC).isoformat()
    canonical_workload = workload or _workload(workload_id)

    def item(evidence_id: str, kind: str, subject_id: str, **extra: object) -> dict[str, object]:
        record: dict[str, object] = {
            "evidence_id": evidence_id,
            "workload_id": workload_id,
            "subject_id": subject_id,
            "kind": kind,
            "status": "pass",
            "observed_at": now,
        }
        if kind in {"environment", "runtime"}:
            record.update(
                authority="humana-platform-control-plane",
                acquisition_source="readiness-evidence-adapter",
                execution_id=f"CHECK-RUN-{evidence_id}",
            )
        elif kind == "assessment":
            record.update(
                authority="humana-assessment-service",
                acquisition_source="governed-assessment-store",
                execution_id=f"ASSESS-RUN-{evidence_id}",
            )
        record.update(extra)
        return record

    return [
        item(
            "EV-discovery",
            "discovery_snapshot",
            workload_id,
            workload_digest=digest_value(canonical_workload),
            snapshot_uri=f"evidence://discovery/{workload_id}/DISCOVERY-RUN-1",
            authority="smf-discovery-service",
            acquisition_source="governed-discovery-store",
            execution_id="DISCOVERY-RUN-1",
        ),
        item(
            "EV-assess",
            "assessment",
            "ART-main",
            source_checksum="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            complexity="simple",
            risk_factors=[],
            unsupported_constructs=[],
        ),
        item(
            "EV-map-in",
            "dataset_mapping",
            "DATA-in",
            direction="input",
            approved=True,
            target_dataset_id="claims_input",
            target_catalog="humana",
            target_schema="modernized",
            mapping_digest="b" * 64,
            authority="humana-data-governance",
            acquisition_source="governed-mapping-registry",
            decision_id="MAP-DECISION-IN",
        ),
        item(
            "EV-map-out",
            "dataset_mapping",
            "DATA-out",
            direction="output",
            approved=True,
            target_dataset_id="claims_output",
            target_catalog="humana",
            target_schema="modernized",
            mapping_digest="c" * 64,
            authority="humana-data-governance",
            acquisition_source="governed-mapping-registry",
            decision_id="MAP-DECISION-OUT",
        ),
        item(
            "EV-baseline",
            "baseline",
            "DATA-out",
            authority="sas-executed-baseline",
            acquisition_source="governed-baseline-store",
            checksum="d" * 64,
            artifact_uri="evidence://baselines/SAS-RUN-1/DATA-out",
            artifact_digest="d" * 64,
            schema_digest="e" * 64,
            measurement_ids=["row-count", "schema", "content"],
            source_execution_id="SAS-RUN-1",
            workload_digest=digest_value(canonical_workload),
            qualified_boundary_id=boundary_id,
        ),
        item(
            "EV-workspace",
            "environment",
            workload_id,
            check_id="target_workspace_access",
        ),
        item(
            "EV-catalog",
            "environment",
            workload_id,
            check_id="governed_catalog_access",
        ),
        item(
            "EV-runtime",
            "runtime",
            workload_id,
            check_id="target_runtime_compatible",
        ),
    ]


def _approval_record(
    evidence: list[dict[str, object]],
    *,
    workload: dict[str, object] | None = None,
    status: str = "pass",
    run_id: str = "run-1",
    attempt_id: str = "1",
    boundary_id: str | None = None,
) -> dict[str, object]:
    canonical_workload = workload or _workload()
    policy = load_readiness_policy(POLICY)
    signed_technical = attest_evidence(evidence)
    return {
        "evidence_id": "EV-approval" if status == "pass" else "EV-denial",
        "workload_id": canonical_workload["workload_id"],
        "subject_id": boundary_id or canonical_workload["workload_id"],
        "kind": "approval",
        "status": status,
        "observed_at": datetime.now(UTC).isoformat(),
        "authority": "humana-change-governance",
        "acquisition_source": "governed-approval-adapter",
        "decision_id": "DECISION-1",
        "approver_id": "APPROVER-1",
        "approved_run_id": run_id,
        "approved_attempt_id": attempt_id,
        "approved_boundary_id": boundary_id,
        "approved_workload_digest": digest_value(canonical_workload),
        "qualification_subject_digest": approval_subject_digest(
            canonical_workload,
            signed_technical,
            policy_digest=policy.policy_digest,
            run_id=run_id,
            attempt_id=attempt_id,
            boundary_id=boundary_id,
        ),
    }


def _evaluate(evidence: list[dict[str, object]], workload: dict[str, object] | None = None):
    return evaluate_readiness(
        ReadinessRequest(
            workload=workload or _workload(),
            evidence=attest_evidence(evidence),
            run_id="run-1",
            attempt_id="1",
        ),
        load_readiness_policy(POLICY),
    )


def test_fully_evidenced_workload_is_ready_and_telemetry_is_bounded() -> None:
    result = _evaluate(_evidence())

    assert result.classification is ReadinessClassification.READY
    assert not result.blockers
    event = readiness_event(result)
    assert not any(
        event[key]
        for key in ("generated", "executed", "validated", "parity_passed", "human_assisted")
    )


def test_macro_analysis_is_required_and_bound_to_governed_strategy() -> None:
    missing = _workload()
    missing.pop("macro_analysis")
    missing_result = _evaluate(_evidence(workload=missing), missing)
    assert missing_result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "macro-analysis" for item in missing_result.checks)

    mutated = _workload()
    macro = mutated["macro_analysis"]
    assert isinstance(macro, dict)
    macro["strategy_digest"] = "f" * 64
    mutated_result = _evaluate(_evidence(workload=mutated), mutated)
    assert mutated_result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "macro-analysis" for item in mutated_result.checks)


def test_macro_blockers_cannot_authorize_ready_and_unknown_kind_is_rejected() -> None:
    blocked = _workload()
    macro = blocked["macro_analysis"]
    assert isinstance(macro, dict)
    macro["blockers"] = [
        {
            "blocker_id": "MBLK-dynamic",
            "reason": "dynamic",
            "observation_id": None,
            "source_artifact_id": "ART-main",
            "detail": "computed_macro_invocation",
        }
    ]
    result = _evaluate(_evidence(workload=blocked), blocked)
    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "macro:MBLK-dynamic" for item in result.checks)

    malformed = deepcopy(blocked)
    malformed_macro = malformed["macro_analysis"]
    assert isinstance(malformed_macro, dict)
    blockers = malformed_macro["blockers"]
    assert isinstance(blockers, list)
    blockers[0]["reason"] = "dynamc"
    with pytest.raises(ValueError, match="schema validation.*reason"):
        _evaluate(_evidence(workload=malformed), malformed)


@pytest.mark.parametrize(
    ("complexity", "classification"),
    [
        ("simple", ReadinessClassification.READY),
        ("moderate", ReadinessClassification.READY),
        ("complex", ReadinessClassification.READY),
        ("highly_complex", ReadinessClassification.HUMAN_REQUIRED),
    ],
)
def test_canonical_assessment_complexities_enforce_review_policy(
    complexity: str, classification: ReadinessClassification
) -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["complexity"] = complexity

    result = _evaluate(evidence)

    assert result.classification is classification
    assert any(item.check_id == "human-approval" for item in result.checks) is (
        complexity == "highly_complex"
    )


@pytest.mark.parametrize("complexity", ["very_high", "highly-complex", "unknown"])
def test_unknown_assessment_complexity_is_rejected(complexity: str) -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["complexity"] = complexity

    with pytest.raises(ValueError, match="schema validation.*complexity"):
        _evaluate(evidence)


@pytest.mark.parametrize(
    "missing_fields",
    [
        ("complexity",),
        ("risk_factors",),
        ("unsupported_constructs",),
        ("complexity", "risk_factors", "unsupported_constructs"),
    ],
)
def test_incomplete_governed_assessment_needs_evidence(
    missing_fields: tuple[str, ...],
) -> None:
    evidence = _evidence()
    assessment = next(item for item in evidence if item["kind"] == "assessment")
    for field in missing_fields:
        assessment.pop(field)

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    check = next(
        item for item in result.checks if item.check_id == "assessment-completeness:ART-main"
    )
    assert check.status.value == "missing"
    assert check.evidence_ids == ("EV-assess",)
    assert all(field in check.diagnostic for field in missing_fields)


@pytest.mark.parametrize(
    ("assessment_change", "classification"),
    [
        ({"unsupported_constructs": ["PROC MYSTERY"]}, ReadinessClassification.UNSUPPORTED),
        ({"status": "fail"}, ReadinessClassification.BLOCKED),
    ],
)
def test_incomplete_assessment_preserves_stronger_findings(
    assessment_change: dict[str, object],
    classification: ReadinessClassification,
) -> None:
    evidence = _evidence()
    assessment = next(item for item in evidence if item["kind"] == "assessment")
    assessment.update(assessment_change)
    assessment.pop("risk_factors")

    result = _evaluate(evidence)

    assert result.classification is classification
    assert {item.check_id for item in result.checks if item.classification is not None} >= {
        "assessment-completeness:ART-main",
        "assessment:ART-main",
    }


def test_caller_cannot_hide_discovered_lineage_and_still_be_ready() -> None:
    workload = _workload()
    workload["datasets"] = []
    workload["relationships"] = []
    workload["outputs"] = []
    evidence = [item for item in _evidence() if item["kind"] not in {"dataset_mapping", "baseline"}]

    result = _evaluate(evidence, workload)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "discovery-snapshot" for item in result.checks)


@pytest.mark.parametrize("mutation", ["dataset", "relationship", "output", "unresolved_dependency"])
def test_mutating_any_governed_discovery_scope_invalidates_snapshot(mutation: str) -> None:
    workload = _workload()
    evidence = _evidence()
    if mutation == "dataset":
        workload["datasets"] = [
            item
            for item in workload["datasets"]
            if item["dataset_id"] != "DATA-in"  # type: ignore[index]
        ]
        workload["relationships"] = [
            item
            for item in workload["relationships"]
            if item["target_id"] != "DATA-in"  # type: ignore[index]
        ]
        evidence = [item for item in evidence if item["evidence_id"] != "EV-map-in"]
    elif mutation == "relationship":
        workload["relationships"] = workload["relationships"][1:]  # type: ignore[index]
    elif mutation == "output":
        workload["outputs"] = []
    else:
        workload["dependency_graph"]["unresolved"] = [  # type: ignore[index]
            {
                "unresolved_id": "UNRES-new",
                "source_id": "ART-main",
                "reference": "late-bound-member",
                "reason": "dynamic",
            }
        ]

    result = _evaluate(evidence, workload)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    snapshot = next(item for item in result.checks if item.check_id == "discovery-snapshot")
    assert snapshot.status.value == "missing"


def test_confirmed_consumer_assertion_requires_concrete_consumer_identity() -> None:
    workload = _workload()
    workload["outputs"][0].pop("consumer_ids")  # type: ignore[index]

    result = _evaluate(_evidence(workload=workload), workload)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert (
        next(item for item in result.checks if item.check_id == "output-lineage:OUT-1").status.value
        == "missing"
    )


def test_checksum_only_baseline_is_not_reconstructable_evidence() -> None:
    evidence = _evidence()
    baseline = next(item for item in evidence if item["kind"] == "baseline")
    for field in ("artifact_uri", "artifact_digest", "schema_digest", "measurement_ids"):
        baseline.pop(field)
    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    check = next(item for item in result.checks if item.check_id == "baseline:DATA-out")
    assert "retrievable" in check.diagnostic


@pytest.mark.parametrize("mutation", ["source", "workload", "boundary"])
def test_baseline_cannot_be_replayed_across_qualified_workload_revisions(
    mutation: str,
) -> None:
    original_workload = _workload()
    original_signed = attest_evidence(_evidence(workload=original_workload))
    preserved_baseline = deepcopy(
        next(item for item in original_signed if item["kind"] == "baseline")
    )
    workload = deepcopy(original_workload)
    boundary_id = None
    if mutation == "source":
        workload["artifacts"][0]["checksum"] = "f" * 64  # type: ignore[index]
    elif mutation == "workload":
        workload["name"] = "revised-workload"
    else:
        workload["boundaries"] = [
            {
                "boundary_id": "BND-main",
                "artifact_ids": ["ART-main"],
                "dataset_ids": ["DATA-in", "DATA-out"],
                "external_dependency_ids": [],
                "output_ids": ["OUT-1"],
            }
        ]
        boundary_id = "BND-main"

    current = _evidence(workload=workload, boundary_id=boundary_id)
    assessment = next(item for item in current if item["kind"] == "assessment")
    assessment["source_checksum"] = workload["artifacts"][0]["checksum"]  # type: ignore[index]
    current = [item for item in current if item["kind"] != "baseline"]
    current_signed = list(attest_evidence(current))
    current_signed.append(preserved_baseline)

    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=tuple(current_signed),
            run_id="run-1",
            attempt_id="1",
            boundary_id=boundary_id,
        ),
        load_readiness_policy(POLICY),
    )

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    baseline_check = next(item for item in result.checks if item.check_id == "baseline:DATA-out")
    assert baseline_check.status.value == "missing"
    assert "qualified workload" in baseline_check.diagnostic


def test_baseline_with_mismatched_execution_input_identity_needs_evidence() -> None:
    evidence = _evidence()
    baseline = next(item for item in evidence if item["kind"] == "baseline")
    baseline["workload_digest"] = "f" * 64

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    check = next(item for item in result.checks if item.check_id == "baseline:DATA-out")
    assert check.status.value == "missing"
    assert "qualified workload" in check.diagnostic


def test_baseline_cannot_be_replayed_between_boundaries_of_same_workload() -> None:
    workload = _workload()
    shared_scope = {
        "artifact_ids": ["ART-main"],
        "dataset_ids": ["DATA-in", "DATA-out"],
        "external_dependency_ids": [],
        "output_ids": ["OUT-1"],
    }
    workload["boundaries"] = [
        {"boundary_id": "BND-one", **shared_scope},
        {"boundary_id": "BND-two", **shared_scope},
    ]
    evidence = _evidence(workload=workload, boundary_id="BND-one")

    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=attest_evidence(evidence),
            run_id="run-1",
            attempt_id="1",
            boundary_id="BND-two",
        ),
        load_readiness_policy(POLICY),
    )

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    check = next(item for item in result.checks if item.check_id == "baseline:DATA-out")
    assert check.status.value == "missing"


@pytest.mark.parametrize("field", ["workload_digest", "qualified_boundary_id"])
def test_baseline_without_execution_input_identity_is_rejected(field: str) -> None:
    evidence = _evidence()
    baseline = next(item for item in evidence if item["kind"] == "baseline")
    baseline.pop(field)

    with pytest.raises(ValueError, match=f"schema validation.*{field}"):
        _evaluate(evidence)


@pytest.mark.parametrize(
    ("run_id", "attempt_id", "source_checksum", "assessment_execution_id", "workload_name"),
    [
        ("unrelated-run", "1", "a" * 64, "ASSESS-RUN-EV-assess", "one"),
        ("run-1", "999", "a" * 64, "ASSESS-RUN-EV-assess", "one"),
        ("run-1", "1", "f" * 64, "ASSESS-RUN-EV-assess", "one"),
        ("run-1", "1", "a" * 64, "ASSESS-RUN-changed", "one"),
        ("run-1", "1", "a" * 64, "ASSESS-RUN-EV-assess", "changed-workload"),
    ],
)
def test_human_approval_cannot_be_replayed_across_qualification_subjects(
    run_id: str,
    attempt_id: str,
    source_checksum: str,
    assessment_execution_id: str,
    workload_name: str,
) -> None:
    original = _evidence()
    assessment = next(item for item in original if item["kind"] == "assessment")
    assessment["complexity"] = "highly_complex"
    original.append(_approval_record(original))
    signed = attest_evidence(original)
    workload = _workload()
    workload["artifacts"][0]["checksum"] = source_checksum  # type: ignore[index]
    workload["name"] = workload_name
    replayed = [deepcopy(item) for item in signed]
    changed_assessment = next(item for item in replayed if item["kind"] == "assessment")
    if source_checksum != "a" * 64:
        changed_assessment["source_checksum"] = source_checksum
    if source_checksum != "a" * 64 or workload_name != "one":
        discovery = next(item for item in replayed if item["kind"] == "discovery_snapshot")
        discovery["workload_digest"] = digest_value(workload)
        baseline = next(item for item in replayed if item["kind"] == "baseline")
        baseline["workload_digest"] = digest_value(workload)
    changed_assessment["execution_id"] = assessment_execution_id
    # Re-sign changed technical evidence but preserve the exact approval bytes and proof.
    approval = next(item for item in replayed if item["kind"] == "approval")
    replayed = list(attest_evidence([item for item in replayed if item["kind"] != "approval"]))
    replayed.append(approval)

    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=tuple(replayed),
            run_id=run_id,
            attempt_id=attempt_id,
        ),
        load_readiness_policy(POLICY),
    )

    assert result.classification is (
        ReadinessClassification.NEEDS_EVIDENCE
        if source_checksum != "a" * 64
        else ReadinessClassification.HUMAN_REQUIRED
    )
    assert readiness_event(result)["human_assisted"] is False


@pytest.mark.parametrize(
    "collection",
    ["artifacts", "datasets", "relationships", "external_dependencies", "outputs", "boundaries"],
)
def test_malformed_canonical_collection_cannot_fail_open(collection: str) -> None:
    workload = _workload()
    workload[collection] = ["not-a-canonical-object"]

    with pytest.raises(ValueError, match="schema validation"):
        _evaluate(_evidence(), workload)


def test_empty_dependency_graph_cannot_fail_open() -> None:
    workload = _workload()
    workload["dependency_graph"] = {}

    with pytest.raises(ValueError, match="schema validation"):
        _evaluate(_evidence(), workload)


def test_duplicate_canonical_subject_identity_is_rejected() -> None:
    workload = _workload()
    duplicate = deepcopy(workload["artifacts"][0])  # type: ignore[index]
    duplicate["kind"] = "configuration"
    workload["artifacts"].append(duplicate)  # type: ignore[union-attr]

    with pytest.raises(ValueError, match="duplicate canonical identity"):
        _evaluate(_evidence(), workload)


def test_duplicate_unresolved_dependency_identity_is_rejected_before_publication(
    tmp_path: Path,
) -> None:
    workload = _workload()
    workload["dependency_graph"]["unresolved"] = [  # type: ignore[index]
        {
            "unresolved_id": "UNRES-duplicate",
            "source_id": "ART-main",
            "reference": "first-reference",
            "reason": "dynamic",
        },
        {
            "unresolved_id": "UNRES-duplicate",
            "source_id": "DATA-in",
            "reference": "different-reference",
            "reason": "missing",
        },
    ]

    with pytest.raises(ValueError, match="duplicate canonical identity.*UNRES-duplicate"):
        result = _evaluate(_evidence(workload=workload), workload)
        write_manifest(tmp_path, result)

    assert not list(tmp_path.rglob("readiness.manifest.json"))


@pytest.mark.parametrize(
    "canonical_id",
    ["WL-one", "ART-main", "DATA-in", "OUT-1", "GRAPH-1"],
)
def test_unresolved_dependency_identity_cannot_collide_with_workload_identity(
    canonical_id: str,
) -> None:
    workload = _workload()
    workload["dependency_graph"]["unresolved"] = [  # type: ignore[index]
        {
            "unresolved_id": canonical_id,
            "source_id": "ART-main",
            "reference": "late-bound-member",
            "reason": "dynamic",
        }
    ]

    with pytest.raises(ValueError, match="duplicate canonical identity"):
        _evaluate(_evidence(workload=workload), workload)


@pytest.mark.parametrize("collision", ["boundary", "external_dependency"])
def test_unresolved_dependency_identity_cannot_collide_with_scoped_identity(
    collision: str,
) -> None:
    workload = _workload()
    canonical_id = "BND-main" if collision == "boundary" else "DEP-external"
    if collision == "boundary":
        workload["boundaries"] = [
            {
                "boundary_id": canonical_id,
                "artifact_ids": ["ART-main"],
                "dataset_ids": ["DATA-in", "DATA-out"],
                "external_dependency_ids": [],
                "output_ids": ["OUT-1"],
            }
        ]
    else:
        workload["external_dependencies"] = [{"dependency_id": canonical_id}]
    workload["dependency_graph"]["unresolved"] = [  # type: ignore[index]
        {
            "unresolved_id": canonical_id,
            "source_id": "ART-main",
            "reference": "late-bound-member",
            "reason": "dynamic",
        }
    ]

    with pytest.raises(ValueError, match="duplicate canonical identity"):
        evaluate_readiness(
            ReadinessRequest(
                workload=workload,
                evidence=attest_evidence(
                    _evidence(
                        workload=workload,
                        boundary_id="BND-main" if collision == "boundary" else None,
                    )
                ),
                run_id="run-1",
                attempt_id="1",
                boundary_id="BND-main" if collision == "boundary" else None,
            ),
            load_readiness_policy(POLICY),
        )


def test_noncanonical_artifact_checksum_fails_closed() -> None:
    workload = _workload()
    workload["artifacts"][0]["checksum"] = "sha256:not-a-real-digest"  # type: ignore[index]
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["source_checksum"] = (
        "sha256:not-a-real-digest"
    )

    result = _evaluate(evidence, workload)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "discovery:ART-main" for item in result.checks)


def test_assessment_without_source_checksum_is_rejected() -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment").pop("source_checksum")

    with pytest.raises(ValueError, match="schema validation.*source_checksum"):
        _evaluate(evidence)


def test_empty_discovery_provenance_is_rejected() -> None:
    workload = _workload()
    workload["artifacts"][0]["evidence"] = [{}]  # type: ignore[index]

    with pytest.raises(ValueError, match="schema validation"):
        _evaluate(_evidence(), workload)


def test_unknown_relationship_kind_cannot_bypass_mapping_or_baseline_checks() -> None:
    workload = _workload()
    workload["relationships"] = [
        {"source_id": "ART-main", "kind": "readz", "target_id": "DATA-in"},
        {"source_id": "ART-main", "kind": "writse", "target_id": "DATA-out"},
    ]

    with pytest.raises(ValueError, match="schema validation"):
        _evaluate(
            [item for item in _evidence() if item["kind"] not in {"dataset_mapping", "baseline"}],
            workload,
        )


def test_empty_workload_needs_source_evidence() -> None:
    workload = _workload()
    workload.update(artifacts=[], datasets=[], relationships=[], outputs=[])
    evidence = [item for item in _evidence() if item["kind"] in {"environment", "runtime"}]

    result = _evaluate(evidence, workload)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "convertible-source" for item in result.checks)


def test_workload_without_convertible_sas_entry_point_needs_evidence() -> None:
    workload = _workload()
    workload["artifacts"] = [
        {
            "artifact_id": "ART-config",
            "kind": "configuration",
            "checksum": "a" * 64,
            "evidence": workload["artifacts"][0]["evidence"],  # type: ignore[index]
        }
    ]
    workload.update(datasets=[], relationships=[], outputs=[])
    evidence = [item for item in _evidence() if item["kind"] in {"environment", "runtime"}]

    result = _evaluate(evidence, workload)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "convertible-source" for item in result.checks)


@pytest.mark.parametrize(
    "evidence_id",
    [
        "EV-discovery",
        "EV-assess",
        "EV-map-in",
        "EV-map-out",
        "EV-baseline",
        "EV-workspace",
        "EV-catalog",
        "EV-runtime",
    ],
)
def test_each_missing_prerequisite_fails_closed(evidence_id: str) -> None:
    evidence = [item for item in _evidence() if item["evidence_id"] != evidence_id]
    assert _evaluate(evidence).classification is ReadinessClassification.NEEDS_EVIDENCE


@pytest.mark.parametrize("evidence_id", ["EV-map-in", "EV-runtime", "EV-workspace"])
def test_explicit_failed_prerequisite_is_blocked(evidence_id: str) -> None:
    evidence = _evidence()
    next(item for item in evidence if item["evidence_id"] == evidence_id)["status"] = "fail"
    assert _evaluate(evidence).classification is ReadinessClassification.BLOCKED


def test_mapping_assertion_without_governed_target_identity_is_rejected() -> None:
    evidence = _evidence()
    for item in evidence:
        if item["kind"] == "dataset_mapping":
            item.pop("target_dataset_id", None)
            item.pop("target_catalog", None)
            item.pop("target_schema", None)
            item.pop("mapping_digest", None)
            item.pop("authority", None)
            item.pop("acquisition_source", None)
            item.pop("decision_id", None)
    with pytest.raises(ValueError, match="schema validation"):
        _evaluate(evidence)


def test_mapping_with_untrusted_provenance_needs_evidence() -> None:
    evidence = _evidence()
    mapping = next(item for item in evidence if item["kind"] == "dataset_mapping")
    mapping["authority"] = "caller-asserted-authority"

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    check = next(item for item in result.checks if item.check_id == "mapping:input:DATA-in")
    assert check.status.value == "missing"
    assert "policy-trusted provenance" in check.diagnostic


@pytest.mark.parametrize(
    "changed",
    [
        {"decision_id": "MAP-DECISION-IN-2"},
        {"target_dataset_id": "claims_input_alternate"},
        {"target_catalog": "alternate_catalog"},
        {"target_schema": "alternate_schema"},
        {"mapping_digest": "f" * 64},
        {
            "decision_id": "MAP-DECISION-IN-2",
            "target_dataset_id": "claims_input_alternate",
            "target_catalog": "alternate_catalog",
            "target_schema": "alternate_schema",
            "mapping_digest": "f" * 64,
        },
    ],
)
def test_conflicting_governed_mapping_decisions_are_blocked(
    changed: dict[str, object],
) -> None:
    evidence = _evidence()
    duplicate = deepcopy(next(item for item in evidence if item["evidence_id"] == "EV-map-in"))
    duplicate.update(evidence_id="EV-map-in-conflict", **changed)
    evidence.append(duplicate)

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.BLOCKED
    check = next(item for item in result.checks if item.check_id == "mapping:input:DATA-in")
    assert check.status.value == "fail"
    assert check.evidence_ids == ("EV-map-in", "EV-map-in-conflict")
    assert "conflicting governed decisions" in check.diagnostic


def test_duplicate_mapping_evidence_with_identical_governed_decision_is_consistent() -> None:
    evidence = _evidence()
    duplicate = deepcopy(next(item for item in evidence if item["evidence_id"] == "EV-map-in"))
    duplicate["evidence_id"] = "EV-map-in-copy"
    evidence.append(duplicate)

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.READY
    check = next(item for item in result.checks if item.check_id == "mapping:input:DATA-in")
    assert check.evidence_ids == ("EV-map-in", "EV-map-in-copy")


def test_unsupported_precedes_blocked_and_preserves_both_findings() -> None:
    evidence = _evidence()
    assessment = next(item for item in evidence if item["kind"] == "assessment")
    assessment["unsupported_constructs"] = ["PROC MYSTERY"]
    next(item for item in evidence if item["evidence_id"] == "EV-runtime")["status"] = "fail"

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.UNSUPPORTED
    assert {item.classification for item in result.blockers} >= {
        ReadinessClassification.UNSUPPORTED,
        ReadinessClassification.BLOCKED,
    }


def test_human_approval_is_a_new_evidence_requirement() -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["complexity"] = "highly_complex"
    assert _evaluate(evidence).classification is ReadinessClassification.HUMAN_REQUIRED

    evidence.append(_approval_record(evidence))
    approved = _evaluate(evidence)
    assert approved.classification is ReadinessClassification.READY
    assert readiness_event(approved)["human_assisted"] is True


def test_governed_human_denial_is_blocked_not_pending() -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["complexity"] = "highly_complex"
    evidence.append(_approval_record(evidence, status="fail"))

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.BLOCKED
    assert readiness_event(result)["human_assisted"] is False


def test_governed_human_denial_blocks_even_without_automatic_review() -> None:
    evidence = _evidence()
    evidence.append(_approval_record(evidence, status="fail"))

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.BLOCKED
    approval = next(item for item in result.checks if item.check_id == "human-approval")
    assert approval.evidence_ids == ("EV-denial",)
    assert result.terminal_disposition == "not_admitted"
    assert readiness_event(result)["human_assisted"] is False


@pytest.mark.parametrize(
    ("kind", "missing_field"),
    [
        ("environment", "authority"),
        ("environment", "acquisition_source"),
        ("runtime", "execution_id"),
        ("approval", "decision_id"),
        ("approval", "approver_id"),
    ],
)
def test_bare_runtime_environment_and_approval_assertions_are_rejected(
    kind: str, missing_field: str
) -> None:
    evidence = _evidence()
    if kind == "approval":
        next(item for item in evidence if item["kind"] == "assessment")["complexity"] = (
            "highly_complex"
        )
        evidence.append(
            {
                "evidence_id": "EV-approval",
                "workload_id": "WL-one",
                "subject_id": "WL-one",
                "kind": "approval",
                "status": "pass",
                "observed_at": datetime.now(UTC).isoformat(),
                "authority": "humana-change-governance",
                "acquisition_source": "governed-approval-adapter",
                "decision_id": "DECISION-1",
                "approver_id": "APPROVER-1",
            }
        )
    record = next(item for item in evidence if item["kind"] == kind)
    record.pop(missing_field)

    with pytest.raises(ValueError, match="schema validation"):
        _evaluate(evidence)


def test_untrusted_runtime_provenance_needs_evidence() -> None:
    evidence = _evidence()
    runtime = next(item for item in evidence if item["kind"] == "runtime")
    runtime["authority"] = "caller-asserted-authority"

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    check = next(item for item in result.checks if item.check_id.startswith("runtime:"))
    assert check.status.value == "missing"
    assert "policy-trusted provenance" in check.diagnostic


def test_untrusted_approval_cannot_mark_human_assisted() -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["complexity"] = "highly_complex"
    evidence.append(
        {
            "evidence_id": "EV-approval",
            "workload_id": "WL-one",
            "subject_id": "WL-one",
            "kind": "approval",
            "status": "pass",
            "observed_at": datetime.now(UTC).isoformat(),
            "authority": "caller-asserted-authority",
            "acquisition_source": "governed-approval-adapter",
            "decision_id": "DECISION-1",
            "approver_id": "APPROVER-1",
        }
    )

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.HUMAN_REQUIRED
    assert readiness_event(result)["human_assisted"] is False


@pytest.mark.parametrize("resolution", ["unresolved", "partial", None])
def test_unresolved_output_lineage_needs_evidence(resolution: str | None) -> None:
    workload = _workload()
    output = workload["outputs"][0]  # type: ignore[index]
    if resolution is None:
        output.pop("consumer_resolution")
    else:
        output["consumer_resolution"] = resolution

    result = _evaluate(_evidence(), workload)

    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.check_id == "output-lineage:OUT-1" for item in result.checks)


def test_boundary_qualification_excludes_unrelated_workload_facts_and_evidence() -> None:
    workload = _workload()
    workload["artifacts"].append(  # type: ignore[union-attr]
        {
            "artifact_id": "ART-unrelated",
            "kind": "other",
            "checksum": "b" * 64,
            "evidence": workload["artifacts"][0]["evidence"],  # type: ignore[index]
        }
    )
    workload["boundaries"] = [
        {
            "boundary_id": "BND-main",
            "artifact_ids": ["ART-main"],
            "dataset_ids": ["DATA-in", "DATA-out"],
            "external_dependency_ids": [],
            "output_ids": ["OUT-1"],
        },
        {
            "boundary_id": "BND-unrelated",
            "artifact_ids": ["ART-unrelated"],
            "dataset_ids": [],
            "external_dependency_ids": [],
            "output_ids": [],
        },
    ]
    evidence = _evidence(workload=workload, boundary_id="BND-main")
    evidence.append(
        {
            "evidence_id": "EV-unrelated-stale",
            "workload_id": "WL-one",
            "subject_id": "ART-unrelated",
            "kind": "assessment",
            "status": "fail",
            "source_checksum": "b" * 64,
            "observed_at": "2000-01-01T00:00:00+00:00",
            "authority": "humana-assessment-service",
            "acquisition_source": "governed-assessment-store",
            "execution_id": "ASSESS-RUN-unrelated",
        }
    )

    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=attest_evidence(evidence),
            run_id="run-1",
            attempt_id="1",
            boundary_id="BND-main",
        ),
        load_readiness_policy(POLICY),
    )

    assert result.classification is ReadinessClassification.READY
    assert "EV-unrelated-stale" not in result.evidence_ids
    assert all(item.subject_id != "ART-unrelated" for item in result.checks)


def test_boundary_approval_replays_from_exact_persisted_evidence(tmp_path: Path) -> None:
    workload = _workload()
    workload["artifacts"].append(  # type: ignore[union-attr]
        {
            "artifact_id": "ART-other",
            "kind": "sas_program",
            "checksum": "f" * 64,
            "evidence": workload["artifacts"][0]["evidence"],  # type: ignore[index]
        }
    )
    workload["boundaries"] = [
        {
            "boundary_id": "BND-main",
            "artifact_ids": ["ART-main"],
            "dataset_ids": ["DATA-in", "DATA-out"],
            "external_dependency_ids": [],
            "output_ids": ["OUT-1"],
        },
        {
            "boundary_id": "BND-other",
            "artifact_ids": ["ART-other"],
            "dataset_ids": [],
            "external_dependency_ids": [],
            "output_ids": [],
        },
    ]
    macro = workload["macro_analysis"]
    assert isinstance(macro, dict)
    inventory = macro["source_inventory"]
    assert isinstance(inventory, list)
    inventory.append({"source_artifact_id": "ART-other", "source_checksum": "f" * 64})
    macro["discovery_id"] = stable_id(
        "MDISC",
        {
            "workload": "WL-one",
            "inventory": inventory,
            "strategy": STRATEGY_DIGEST,
        },
    )
    macro["analysis_id"] = stable_id(
        "MAN",
        {
            "discovery": macro["discovery_id"],
            "workload": "WL-one",
            "inventory": inventory,
            "strategy": STRATEGY_DIGEST,
            "limits": macro["limits_applied"],
            "logical_artifacts": [],
            "observations": [],
            "resolutions": [],
            "blockers": [],
            "complete": True,
        },
    )
    evidence = _evidence(workload=workload, boundary_id="BND-main")
    next(item for item in evidence if item["kind"] == "assessment")["complexity"] = "highly_complex"
    evidence.append(
        {
            "evidence_id": "EV-assess-other",
            "workload_id": "WL-one",
            "subject_id": "ART-other",
            "kind": "assessment",
            "status": "pass",
            "source_checksum": "f" * 64,
            "complexity": "simple",
            "risk_factors": [],
            "unsupported_constructs": [],
            "observed_at": datetime.now(UTC).isoformat(),
            "authority": "humana-assessment-service",
            "acquisition_source": "governed-assessment-store",
            "execution_id": "ASSESS-RUN-other",
        }
    )
    evidence.append(_approval_record(evidence, workload=workload, boundary_id="BND-main"))
    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=attest_evidence(evidence),
            run_id="run-1",
            attempt_id="1",
            boundary_id="BND-main",
        ),
        load_readiness_policy(POLICY),
    )

    assert result.classification is ReadinessClassification.READY
    assert "EV-assess-other" not in result.evidence_ids
    manifest = write_manifest(tmp_path, result)
    persisted = load_manifest(manifest)
    assert persisted["result_id"] == result.result_id
    assert (
        json.loads(manifest.with_name("readiness.telemetry.json").read_text())[  # noqa: PTH123
            "readiness_result_id"
        ]
        == result.result_id
    )


@pytest.mark.parametrize("statuses", [("fail",), ("pass", "fail")])
def test_failed_or_conflicting_governed_discovery_snapshots_block(
    statuses: tuple[str, ...],
) -> None:
    evidence = [item for item in _evidence() if item["kind"] != "discovery_snapshot"]
    now = datetime.now(UTC).isoformat()
    for index, status in enumerate(statuses, start=1):
        evidence.append(
            {
                "evidence_id": f"EV-discovery-{index}",
                "workload_id": "WL-one",
                "subject_id": "WL-one",
                "kind": "discovery_snapshot",
                "status": status,
                "observed_at": now,
                "workload_digest": digest_value(_workload()),
                "snapshot_uri": f"evidence://discovery/WL-one/DISCOVERY-RUN-{index}",
                "authority": "smf-discovery-service",
                "acquisition_source": "governed-discovery-store",
                "execution_id": f"DISCOVERY-RUN-{index}",
            }
        )

    result = _evaluate(evidence)

    assert result.classification is ReadinessClassification.BLOCKED
    snapshot = next(item for item in result.checks if item.check_id == "discovery-snapshot")
    assert snapshot.status.value == "fail"
    assert set(snapshot.evidence_ids) == {
        f"EV-discovery-{index}" for index in range(1, len(statuses) + 1)
    }


def test_boundary_cannot_omit_a_dataset_referenced_by_its_artifact() -> None:
    workload = _workload()
    workload["boundaries"] = [
        {
            "boundary_id": "BND-incomplete",
            "artifact_ids": ["ART-main"],
            "dataset_ids": ["DATA-out"],
            "external_dependency_ids": [],
            "output_ids": ["OUT-1"],
        }
    ]

    with pytest.raises(ValueError, match="not closed over relationship ART-main -> DATA-in"):
        evaluate_readiness(
            ReadinessRequest(
                workload=workload,
                evidence=attest_evidence(_evidence()),
                run_id="run-1",
                attempt_id="1",
                boundary_id="BND-incomplete",
            ),
            load_readiness_policy(POLICY),
        )


def test_expected_output_cannot_substitute_for_executed_baseline() -> None:
    evidence = _evidence()
    baseline = next(item for item in evidence if item["kind"] == "baseline")
    baseline["authority"] = "synthetic-expected-output"
    baseline.pop("source_execution_id")
    assert _evaluate(evidence).classification is ReadinessClassification.NEEDS_EVIDENCE


def test_attested_baseline_requires_a_canonical_content_digest() -> None:
    evidence = _evidence()
    baseline = next(item for item in evidence if item["kind"] == "baseline")
    baseline["checksum"] = "sha256:baseline"

    assert _evaluate(evidence).classification is ReadinessClassification.BLOCKED


@pytest.mark.parametrize(
    ("reason", "classification"),
    [
        ("dynamic", ReadinessClassification.NEEDS_EVIDENCE),
        ("ambiguous", ReadinessClassification.NEEDS_EVIDENCE),
        ("missing", ReadinessClassification.BLOCKED),
        ("external", ReadinessClassification.NEEDS_EVIDENCE),
    ],
)
def test_unresolved_dependency_policy_is_explicit(
    reason: str, classification: ReadinessClassification
) -> None:
    workload = _workload()
    workload["dependency_graph"] = {
        "graph_id": "GRAPH-1",
        "unresolved": [
            {
                "unresolved_id": f"UNRES-{reason}",
                "source_id": "ART-main",
                "reference": "unknown",
                "reason": reason,
            }
        ],
    }
    assert _evaluate(_evidence(workload=workload), workload).classification is classification


def test_stale_evidence_is_not_accepted() -> None:
    evidence = _evidence()
    evidence[0]["observed_at"] = "2000-01-01T00:00:00+00:00"
    result = _evaluate(evidence)
    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert any(item.category.value == "evidence_integrity" for item in result.blockers)


def test_secret_values_are_sanitized_before_identity_or_persistence(tmp_path: Path) -> None:
    first_evidence = _evidence()
    first_evidence[0]["metadata"] = {"password": "CANARY-FIRST"}
    second_evidence = deepcopy(first_evidence)
    second_evidence[0]["metadata"] = {"password": "CANARY-SECOND"}

    first = _evaluate(first_evidence)
    second = _evaluate(second_evidence)

    assert first.result_id == second.result_id
    manifest = write_manifest(tmp_path, first)
    serialized = manifest.read_text(encoding="utf-8")
    assert "CANARY-FIRST" not in serialized
    assert "CANARY-SECOND" not in serialized


def test_evidence_order_does_not_change_result_identity() -> None:
    evidence = _evidence()
    assert _evaluate(evidence).result_id == _evaluate(list(reversed(evidence))).result_id


def test_cross_workload_and_checksum_mismatch_are_rejected() -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["workload_id"] = "WL-other"
    with pytest.raises(ValueError, match="cross-workload"):
        _evaluate(evidence)

    evidence = _evidence()
    next(item for item in evidence if item["kind"] == "assessment")["source_checksum"] = (
        "sha256:tampered"
    )
    with pytest.raises(ValueError, match="checksum mismatch"):
        _evaluate(evidence)


def test_manifests_are_append_only_and_workload_isolated(tmp_path: Path) -> None:
    first = _evaluate(_evidence())
    first_path = write_manifest(tmp_path, first)
    persisted = load_manifest(first_path)
    assert persisted["result_id"] == first.result_id
    assert persisted["qualification_input"]["workload"] == _workload()
    baseline = next(
        item for item in persisted["qualification_input"]["evidence"] if item["kind"] == "baseline"
    )
    assert baseline["checksum"] == "d" * 64
    assert baseline["source_execution_id"] == "SAS-RUN-1"
    assert baseline["qualified_boundary_id"] is None
    mapping = next(
        item for item in persisted["evidence_references"] if item["evidence_id"] == "EV-map-in"
    )
    assert mapping["target_dataset_id"] == "claims_input"
    assert mapping["target_catalog"] == "humana"
    assert mapping["target_schema"] == "modernized"
    assert mapping["mapping_digest"] == "b" * 64
    assert mapping["decision_id"] == "MAP-DECISION-IN"
    assert persisted["policy_snapshot"]["mappings"]["require_outputs"] is True
    event_path = first_path.with_name("readiness.telemetry.json")
    event = json.loads(event_path.read_text(encoding="utf-8"))
    assert event["readiness_result_id"] == first.result_id
    assert event["stage"] == "readiness"
    assert event["parity_passed"] is False
    assert write_manifest(tmp_path, first) == first_path

    changed = deepcopy(first.to_dict())
    changed["elapsed_ms"] += 1
    from smf.readiness.models import ReadinessResult

    changed.pop("content_digest")
    conflicting = ReadinessResult(**changed, content_digest="0" * 64)
    with pytest.raises((FileExistsError, ValueError)):
        write_manifest(tmp_path, conflicting)

    other = _evaluate(_evidence("WL-two"), _workload("WL-two"))
    other_path = write_manifest(tmp_path, other)
    assert other_path != first_path
    assert first_path.exists()


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    result = _evaluate(_evidence())
    from dataclasses import replace

    with pytest.raises(ValueError, match="Unsafe run_id"):
        write_manifest(tmp_path, replace(result, run_id="../escape"))


def _prerequisite_policy():
    raw = serialize_readiness_policy(load_readiness_policy(POLICY))
    raw["required_environment_checks"] = []
    raw["required_runtime_checks"] = []
    raw["prerequisite_binding"] = {
        "client_id": "humana",
        "deployment_id": "pilot",
        "environment_id": "workspace-one",
        "configuration_digest": "9" * 64,
    }
    raw["prerequisites"] = [
        {
            "prerequisite_id": "network_private_connectivity",
            "domain": "network",
            "evidence_kind": "environment",
            "owner_role": "humana-network-owner",
            "requirement_refs": ["HC-REQ-05"],
            "owner_assignment_ref": "assignment-network-1",
            "max_age_seconds": 86400,
            "next_action": "Verify the approved private connectivity path.",
        }
    ]
    return readiness_policy_from_dict(raw)


def _attest_for_policy(records, policy):
    authenticated = sanitize_discovery_value(deepcopy(records))
    assert isinstance(authenticated, list)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    for item in authenticated:
        item["policy_digest"] = policy.policy_digest
        item["proof"] = {
            "algorithm": "ed25519",
            "key_id": "humana-readiness-v1",
            "value": base64.b64encode(key.sign(attestation_payload(item))).decode("ascii"),
        }
    return tuple(authenticated)


def _prerequisite_evidence(
    *,
    status: str = "pass",
    run_id: str = "run-1",
    attempt_id: str = "1",
    observed_at: datetime | None = None,
) -> dict[str, object]:
    observed = observed_at or datetime.now(UTC)
    record: dict[str, object] = {
        "evidence_id": f"EV-network-{status}",
        "workload_id": "WL-one",
        "subject_id": "WL-one",
        "kind": "environment",
        "status": status,
        "check_id": "network_private_connectivity",
        "prerequisite_id": "network_private_connectivity",
        "client_id": "humana",
        "deployment_id": "pilot",
        "environment_id": "workspace-one",
        "configuration_digest": "9" * 64,
        "workload_digest": digest_value(_workload()),
        "qualified_boundary_id": None,
        "evidence_run_id": run_id,
        "evidence_attempt_id": attempt_id,
        "owner_assignment_ref": "assignment-network-1",
        "authority": "humana-platform-control-plane",
        "acquisition_source": "readiness-evidence-adapter",
        "execution_id": f"CHECK-{status}",
        "result_uri": f"evidence://environment/CHECK-{status}",
        "result_digest": "8" * 64,
        "observed_at": observed.isoformat(),
        "valid_until": (observed + timedelta(hours=12)).isoformat(),
    }
    if status == "fail":
        record["reason_code"] = "access_denied"
    elif status == "pending":
        record["reason_code"] = "approval_pending"
    return record


def _persist_prerequisite_result(root: Path, evidence: dict[str, object]) -> None:
    payload = {
        "schema_version": "1.0",
        "result_id": evidence.get("execution_id") or evidence.get("decision_id"),
        "prerequisite_id": evidence["prerequisite_id"],
        "client_id": evidence["client_id"],
        "deployment_id": evidence["deployment_id"],
        "environment_id": evidence["environment_id"],
        "workload_id": evidence["workload_id"],
        "workload_digest": evidence["workload_digest"],
        "boundary_id": evidence["qualified_boundary_id"],
        "run_id": evidence["evidence_run_id"],
        "attempt_id": evidence["evidence_attempt_id"],
        "configuration_digest": evidence["configuration_digest"],
        "owner_assignment_ref": evidence["owner_assignment_ref"],
        "authority": evidence["authority"],
        "acquisition_source": evidence["acquisition_source"],
        "execution_id": evidence.get("execution_id"),
        "decision_id": evidence.get("decision_id"),
        "checked_target": "humana-private-network-path",
        "status": evidence["status"],
        "reason_code": evidence.get("reason_code"),
        "observed_at": evidence["observed_at"],
        "valid_until": evidence["valid_until"],
    }
    content = canonical_json(payload).encode("utf-8")
    relative = Path("results") / f"{payload['result_id']}.json"
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    evidence["result_uri"] = relative.as_posix()
    evidence["result_digest"] = hashlib.sha256(content).hexdigest()


def _evaluate_prerequisite(records, *, run_id: str = "run-1", result_root: Path | None = None):
    policy = _prerequisite_policy()
    return evaluate_readiness(
        ReadinessRequest(
            workload=_workload(),
            evidence=_attest_for_policy([*_evidence(), *records], policy),
            run_id=run_id,
            attempt_id="1",
            result_root=result_root,
        ),
        policy,
    )


def test_prerequisite_checklist_requires_reconstructable_bound_evidence(tmp_path: Path) -> None:
    evidence = _prerequisite_evidence()
    _persist_prerequisite_result(tmp_path, evidence)
    ready = _evaluate_prerequisite([evidence], result_root=tmp_path)
    assert ready.classification is ReadinessClassification.READY
    entry = ready.prerequisite_checklist[0]
    assert entry.state == "pass"
    assert entry.owner_role == "humana-network-owner"
    assert entry.requirement_refs == ("HC-REQ-05",)
    assert entry.owner_assignment_ref == "assignment-network-1"
    assert entry.result_uris == ("results/CHECK-pass.json",)
    assert readiness_event(ready)["blocked"] is False
    persisted = load_manifest(write_manifest(tmp_path / "out", ready))
    assert persisted["result_id"] == ready.result_id
    assert (
        persisted["qualification_input"]["result_artifacts"][0]["payload"]["checked_target"]
        == "humana-private-network-path"
    )

    self_asserted = _prerequisite_evidence()
    self_asserted.pop("result_uri")
    self_asserted.pop("result_digest")
    unresolved = _evaluate_prerequisite([self_asserted])
    assert unresolved.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert unresolved.prerequisite_checklist[0].state == "missing"
    assert unresolved.prerequisite_checklist[0].blocker_reason_code == "result_unverifiable"
    assert readiness_event(unresolved)["blocked"] is True


@pytest.mark.parametrize(
    "result_uri",
    ["../../protected/result.json", "https://attacker.invalid/self-authored.json", "not-a-uri"],
)
def test_prerequisite_locator_must_resolve_within_authorized_root(
    tmp_path: Path, result_uri: str
) -> None:
    evidence = _prerequisite_evidence()
    evidence["result_uri"] = result_uri
    unresolved = _evaluate_prerequisite([evidence], result_root=tmp_path)
    assert unresolved.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert unresolved.prerequisite_checklist[0].state == "missing"


def test_prerequisite_result_must_exist_match_digest_and_identity(tmp_path: Path) -> None:
    missing = _prerequisite_evidence()
    missing["result_uri"] = "results/missing.json"
    assert (
        _evaluate_prerequisite([missing], result_root=tmp_path).classification
        is ReadinessClassification.NEEDS_EVIDENCE
    )

    mismatched_digest = _prerequisite_evidence()
    _persist_prerequisite_result(tmp_path, mismatched_digest)
    mismatched_digest["result_digest"] = "0" * 64
    assert (
        _evaluate_prerequisite([mismatched_digest], result_root=tmp_path).classification
        is ReadinessClassification.NEEDS_EVIDENCE
    )

    mismatched_identity = _prerequisite_evidence()
    _persist_prerequisite_result(tmp_path, mismatched_identity)
    result_path = tmp_path / str(mismatched_identity["result_uri"])
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["workload_id"] = "WL-other"
    content = canonical_json(payload).encode("utf-8")
    result_path.write_bytes(content)
    mismatched_identity["result_digest"] = hashlib.sha256(content).hexdigest()
    assert (
        _evaluate_prerequisite([mismatched_identity], result_root=tmp_path).classification
        is ReadinessClassification.NEEDS_EVIDENCE
    )


def test_prerequisite_evidence_cannot_be_replayed_across_run_identity() -> None:
    replayed = _evaluate_prerequisite([_prerequisite_evidence()], run_id="run-2")
    assert replayed.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert replayed.prerequisite_checklist[0].state == "missing"
    assert replayed.prerequisite_checklist[0].blocker_reason_code == "binding_mismatch"


def test_prerequisite_denial_pending_expiry_and_conflict_are_distinct(tmp_path: Path) -> None:
    denied_evidence = _prerequisite_evidence(status="fail")
    pending_evidence = _prerequisite_evidence(status="pending")
    expired_evidence = _prerequisite_evidence(observed_at=datetime(2020, 1, 1, tzinfo=UTC))
    for item in (denied_evidence, pending_evidence, expired_evidence):
        _persist_prerequisite_result(tmp_path, item)
    denied = _evaluate_prerequisite([denied_evidence], result_root=tmp_path)
    pending = _evaluate_prerequisite([pending_evidence], result_root=tmp_path)
    expired = _evaluate_prerequisite([expired_evidence], result_root=tmp_path)
    conflict_pass = _prerequisite_evidence()
    conflict_fail = _prerequisite_evidence(status="fail")
    _persist_prerequisite_result(tmp_path, conflict_pass)
    _persist_prerequisite_result(tmp_path, conflict_fail)
    conflicting = _evaluate_prerequisite([conflict_pass, conflict_fail], result_root=tmp_path)
    divergent_pass = _prerequisite_evidence()
    divergent_pass["evidence_id"] = "EV-network-pass-divergent"
    divergent_pass["execution_id"] = "CHECK-pass-divergent"
    _persist_prerequisite_result(tmp_path, divergent_pass)
    divergent = _evaluate_prerequisite([conflict_pass, divergent_pass], result_root=tmp_path)

    assert (denied.classification, denied.prerequisite_checklist[0].state) == (
        ReadinessClassification.BLOCKED,
        "denied",
    )
    assert (pending.classification, pending.prerequisite_checklist[0].state) == (
        ReadinessClassification.HUMAN_REQUIRED,
        "pending",
    )
    assert expired.prerequisite_checklist[0].state == "expired"
    assert (conflicting.classification, conflicting.prerequisite_checklist[0].state) == (
        ReadinessClassification.BLOCKED,
        "conflicting",
    )
    assert divergent.prerequisite_checklist[0].state == "conflicting"


def test_prerequisite_policy_rejects_duplicate_identity_and_unknown_domain() -> None:
    raw = serialize_readiness_policy(_prerequisite_policy())
    raw["prerequisites"].append(deepcopy(raw["prerequisites"][0]))
    with pytest.raises(ValueError, match="prerequisite IDs must be unique"):
        readiness_policy_from_dict(raw)

    malformed = serialize_readiness_policy(_prerequisite_policy())
    malformed["prerequisites"][0]["domain"] = "netwrok"
    with pytest.raises(ValueError, match="prerequisites.0.domain"):
        readiness_policy_from_dict(malformed)


@pytest.mark.parametrize("kind", ["discovery_snapshot", "assessment"])
def test_pending_status_cannot_bypass_non_prerequisite_checks(kind: str) -> None:
    evidence = _evidence()
    next(item for item in evidence if item["kind"] == kind)["status"] = "pending"
    assert _evaluate(evidence).classification is ReadinessClassification.NEEDS_EVIDENCE


def test_humana_policy_inventory_is_complete_and_every_entry_blocks_when_missing() -> None:
    raw = serialize_readiness_policy(
        load_readiness_policy(Path("deployments/humana/readiness-policy.yaml"))
    )
    # Substitute the deterministic test verification key; production private key material is absent.
    raw["verification_keys"] = serialize_readiness_policy(load_readiness_policy(POLICY))[
        "verification_keys"
    ]
    policy = readiness_policy_from_dict(raw)
    expected_ids = {
        "sas_baseline_runtime_access",
        "sas_baseline_acquisition_permission",
        "databricks_workspace_binding",
        "governed_catalog_scratch_output",
        "source_data_read_scope",
        "target_data_write_scope",
        "network_private_connectivity",
        "workload_identity_token_exchange",
        "target_runtime_compatible",
        "resource_quotas",
        "validation_execution_permission",
        "validation_evidence_permission",
        "cleanup_retention_approval",
        "logging_audit_access",
    }
    assert {item["prerequisite_id"] for item in policy.prerequisites} == expected_ids
    assert {item["domain"] for item in policy.prerequisites} == {
        "sas_baseline",
        "databricks",
        "data_scope",
        "network",
        "identity",
        "quota",
        "validation",
        "retention",
        "audit",
    }

    result = evaluate_readiness(
        ReadinessRequest(
            workload=_workload(),
            evidence=_attest_for_policy(_evidence(), policy),
            run_id="run-1",
            attempt_id="1",
        ),
        policy,
    )
    assert result.classification is ReadinessClassification.NEEDS_EVIDENCE
    assert len(result.prerequisite_checklist) == 14
    assert all(item.state == "missing" for item in result.prerequisite_checklist)
    event = readiness_event(result)
    assert event["blocked"] is True
    assert set(event["prerequisite_states"]) == expected_ids
