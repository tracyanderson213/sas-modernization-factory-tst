from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.conversion.format_function_semantics import (
    ClassificationRequest,
    FormatFunctionPolicy,
    InputStatus,
    SemanticDisposition,
    classification_policy,
    classify_format_function_semantics,
    publish_classification_evidence,
    recover_classification_telemetry,
    verify_classification_evidence,
)

ROOT = Path(__file__).parents[2]


def request(**changes: str) -> ClassificationRequest:
    values = {
        "client_id": "client-synthetic",
        "workload_id": "workload-1",
        "subject_id": "program-1",
        "source_artifact_id": "artifact-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "source_snapshot_ref": "snapshot-1",
    }
    values.update(changes)
    return ClassificationRequest(**values)


def classify(source: bytes, **changes: str) -> dict[str, object]:
    return classify_format_function_semantics(source, request(**changes), classification_policy())


def test_policy_is_strict_packaged_and_keeps_all_external_authority_pending() -> None:
    policy = classification_policy()
    payload = policy.to_dict()
    public = json.loads((ROOT / "schemas/sas-format-function-policy.schema.json").read_text())
    packaged = json.loads(
        (ROOT / "src/smf/schemas/sas-format-function-policy.schema.json").read_text()
    )

    assert public == packaged
    Draft202012Validator(public).validate(payload)
    example = json.loads(
        (ROOT / "examples/policies/sas-format-function-classification-v1.json").read_text()
    )
    assert example == payload
    assert policy.executable_mapping_allowlist == ()
    assert {item.status for item in policy.external_inputs} == {InputStatus.PENDING}
    assert {item.name for item in policy.external_inputs} == {
        "sas_runtime",
        "sas_version",
        "session_options",
        "locale",
        "timezone",
        "yearcutoff",
        "oracle_authority",
        "business_tolerances",
        "humana_owner_decisions",
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"executable_mapping_allowlist": ["date9"]}, "allowlist"),
        ({"unknown_label_handling": "skip"}, "Unknown labels"),
        ({"ambiguous_context_handling": "best_effort"}, "Ambiguous contexts"),
        ({"custom_semantics_handling": "qualified"}, "Custom semantics"),
        ({"version": "latest"}, "version"),
    ],
)
def test_policy_cannot_be_widened_by_unknown_enums_or_allowlist(
    mutation: dict[str, object], message: str
) -> None:
    payload = classification_policy().to_dict()
    payload.update(mutation)
    with pytest.raises(ValueError, match=message):
        FormatFunctionPolicy.from_dict(payload)


def test_policy_rejects_caller_attestation_and_duplicate_or_missing_inputs() -> None:
    payload = classification_policy().to_dict()
    payload["approved"] = True
    with pytest.raises(ValueError, match="unknown or missing"):
        FormatFunctionPolicy.from_dict(payload)

    payload = classification_policy().to_dict()
    payload["external_inputs"][0]["name"] = "sas_version"
    with pytest.raises(ValueError, match="missing, duplicated"):
        FormatFunctionPolicy.from_dict(payload)


def test_detects_and_source_locates_format_informat_functions_and_sysfunc() -> None:
    source = (
        b"data out; set in;\n"
        b"format service_date date9.;\n"
        b"informat member_dob yymmdd10.;\n"
        b"x = put(service_date,date9.);\n"
        b"%let y=%sysfunc(today());\n"
        b"run;"
    )
    result = classify(source)
    occurrences = result["occurrences"]

    assert result["disposition"] == SemanticDisposition.BLOCKED.value
    assert {item["kind"] for item in occurrences} >= {
        "format_label",
        "informat_label",
        "sas_function",
        "macro_sysfunc",
    }
    for item in occurrences:
        token = source[item["byte_start"] : item["byte_end"]]
        assert hashlib.sha256(token).hexdigest() == item["source_token_sha256"]
        assert item["line"] >= 1 and item["column"] >= 1
        assert item["underlying_value_separate"] is True
        assert item["formatted_projection_only"] is True


@pytest.mark.parametrize(
    ("function", "argument", "kind"),
    [
        ("put", "DATE9.", "format_argument"),
        ("putc", "$CHAR20.", "format_argument"),
        ("putn", "catalog.customfmt.", "format_argument"),
        ("input", "YYMMDD10.", "informat_argument"),
        ("inputc", "$CHAR20.", "informat_argument"),
        ("inputn", "COMMA12.2", "informat_argument"),
    ],
)
def test_function_format_arguments_have_complete_source_bound_occurrences(
    function: str, argument: str, kind: str
) -> None:
    source = f"data out; result={function}(value,{argument}); run;".encode()

    result = classify(source)
    occurrence = next(item for item in result["occurrences"] if item["kind"] == kind)
    token = source[occurrence["byte_start"] : occurrence["byte_end"]]

    assert token == argument.encode()
    assert occurrence["name"] == argument.lower()
    assert occurrence["source_token_sha256"] == hashlib.sha256(argument.encode()).hexdigest()
    assert occurrence["reason_code"] == (
        "custom_catalog_reference" if argument == "catalog.customfmt." else "unqualified_mapping"
    )
    assert result["disposition"] == "blocked"


@pytest.mark.parametrize(
    "source",
    [
        b"result=put(value,format_variable);",
        b"result=input(value,&informat_name.);",
        b"result=put(value,);",
        b"result=input(value);",
        b"result=put(value,date9.;",
    ],
)
def test_dynamic_or_malformed_function_format_arguments_fail_closed(source: bytes) -> None:
    result = classify(source)

    assert result["disposition"] == "blocked"
    assert any(
        item["kind"] in {"format_argument", "informat_argument"}
        and item["reason_code"] == "ambiguous_format_or_informat_argument"
        for item in result["occurrences"]
    )


def test_statement_format_precision_span_is_not_truncated() -> None:
    source = b"format amount COMMA12.2;"

    result = classify(source)
    occurrence = next(item for item in result["occurrences"] if item["kind"] == "format_label")
    token = source[occurrence["byte_start"] : occurrence["byte_end"]]

    assert token == b"COMMA12.2"
    assert occurrence["source_token_sha256"] == hashlib.sha256(token).hexdigest()


@pytest.mark.parametrize(
    ("source", "kind", "reason"),
    [
        (b"proc format; value risk 1='L'; run;", "proc_format", "custom_format_or_informat"),
        (
            b"proc format; invalue risk 1-5=1; run;",
            "proc_format",
            "overlapping_or_ranged_definition",
        ),
        (b"proc format; value risk(default=8) 1='L'; run;", "proc_format", "unsupported_default"),
        (b"proc fcmp; function score(x); return(x); endsub; run;", "proc_fcmp", "fcmp_function"),
        (b"format x customfmt.;", "format_label", "unqualified_mapping"),
        (b"format x catalog.customfmt.;", "format_label", "custom_catalog_reference"),
        (b"format amount 12.2;", "format_label", "unqualified_mapping"),
        (b"informat x custominf.;", "informat_label", "unqualified_mapping"),
    ],
)
def test_custom_and_unqualified_semantics_never_qualify(
    source: bytes, kind: str, reason: str
) -> None:
    result = classify(source)

    assert result["disposition"] in {"blocked", "unsupported"}
    assert any(
        item["kind"] == kind and item["reason_code"] == reason for item in result["occurrences"]
    )
    assert not any(result["claims"][name] for name in ("generated", "executed", "validated"))
    assert result["claims"]["parity_passed"] is False


@pytest.mark.parametrize(
    "source",
    [
        b"format x &chosen_format.;",
        b"x=&function_name(value);",
        b"format x date9.; /* unterminated",
        b"format x;",
        b"format x comma12.2suffix;",
    ],
)
def test_ambiguous_contexts_fail_closed(source: bytes) -> None:
    result = classify(source)

    assert result["disposition"] == "blocked"
    assert any(
        "ambiguous" in item["reason_code"] or item["reason_code"] == "macro_processing_separate"
        for item in result["occurrences"]
    )


def test_strings_and_comments_do_not_create_false_function_or_format_occurrences() -> None:
    result = classify(
        b"data x; label='put(a,date9.)'; /* format x date9.; */ * x=today(); y=1; run;"
    )

    assert result["disposition"] == "not_applicable"
    assert result["occurrences"] == []
    assert result["terminal_disposition"] == "not_applicable"


def test_macro_processing_and_target_templates_are_not_sas_function_equivalents() -> None:
    result = classify(b"%do_work(value); x={{ helper(value) }}; y=&macro_value;")

    assert {item["kind"] for item in result["occurrences"]} == {
        "macro_processing",
        "target_template",
    }
    assert {item["reason_code"] for item in result["occurrences"]} == {
        "macro_processing_separate",
        "target_template_not_sas",
    }


def test_empty_secret_unsafe_identity_missing_policy_and_bad_encoding_fail_before_hashing() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        classify(b"")
    with pytest.raises(ValueError, match="protected data"):
        classify(b"format x date9.; password=secret-canary")
    with pytest.raises(ValueError, match="Unsafe"):
        classify_format_function_semantics(
            b"format x date9.;", request(workload_id="../escape"), classification_policy()
        )
    with pytest.raises(ValueError, match="Unsafe"):
        classify_format_function_semantics(
            b"format x date9.;",
            request(workload_id="secret-canary-identity"),
            classification_policy(),
        )
    with pytest.raises(ValueError, match="policy"):
        classify_format_function_semantics(b"format x date9.;", request(), None)
    with pytest.raises(ValueError, match="UTF-8"):
        classify(b"format x date9.;\xff")


def test_evidence_is_bound_reconstructable_and_rejects_assertion_or_source_mutation() -> None:
    source = b"format service_date date9.; x=put(service_date,date9.);"
    policy = classification_policy()
    evidence = classify_format_function_semantics(source, request(), policy)

    assert verify_classification_evidence(evidence, source, policy) == evidence
    assert evidence["source_sha256"] == hashlib.sha256(source).hexdigest()
    assert evidence["policy_digest"] == policy.policy_digest
    assert evidence["source_snapshot_ref"] == "snapshot-1"

    asserted = json.loads(json.dumps(evidence))
    asserted["claims"]["validated"] = True
    with pytest.raises(ValueError, match="digest"):
        verify_classification_evidence(asserted, source, policy)
    asserted["evidence_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in asserted.items() if key != "evidence_sha256"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="exact source|unauthorized success"):
        publish_classification_evidence(
            Path("unused"), asserted, source=source, policy=classification_policy()
        )
    with pytest.raises(ValueError, match="exact source"):
        verify_classification_evidence(evidence, source.replace(b"date9", b"date7"), policy)


def test_pending_and_denied_external_inputs_are_distinct_and_denial_requires_evidence() -> None:
    policy = classification_policy()
    denied = replace(
        policy.external_inputs[0], status=InputStatus.DENIED, evidence_ref="owner-denial-1"
    )
    changed = replace(policy, external_inputs=(denied, *policy.external_inputs[1:])).validate()

    assert changed.external_inputs[0].status is InputStatus.DENIED
    with pytest.raises(ValueError, match="requires attributable"):
        replace(policy.external_inputs[0], status=InputStatus.DENIED).validate()


def test_publication_is_isolated_immutable_and_recovers_missing_telemetry(tmp_path: Path) -> None:
    first = classify(b"format x date9.;", workload_id="workload-a")
    second = classify(b"x=today();", workload_id="workload-b")
    policy = classification_policy()
    first_path, first_event = publish_classification_evidence(
        tmp_path, first, source=b"format x date9.;", policy=policy
    )
    second_path, _ = publish_classification_evidence(
        tmp_path, second, source=b"x=today();", policy=policy
    )

    assert first_path != second_path
    assert json.loads(first_path.read_text()) == first
    first_event.unlink()
    recovered = recover_classification_telemetry(first_path)
    event = json.loads(recovered.read_text())
    assert event["workload_id"] == "workload-a"
    assert event["generated"] is False and event["blocked"] is True

    conflict = dict(first)
    conflict["decision_id"] = "decision-conflict"
    with pytest.raises(ValueError, match="digest"):
        publish_classification_evidence(
            tmp_path, conflict, source=b"format x date9.;", policy=policy
        )
    assert json.loads(first_path.read_text()) == first


def test_retry_is_idempotent_and_duplicate_attempt_identity_cannot_change_decision(
    tmp_path: Path,
) -> None:
    evidence = classify(b"format x date9.;")
    policy = classification_policy()
    paths = publish_classification_evidence(
        tmp_path, evidence, source=b"format x date9.;", policy=policy
    )
    assert (
        publish_classification_evidence(
            tmp_path, evidence, source=b"format x date9.;", policy=policy
        )
        == paths
    )

    changed = classify(b"format x date7.;")
    with pytest.raises(FileExistsError):
        publish_classification_evidence(
            tmp_path, changed, source=b"format x date7.;", policy=policy
        )


def test_publication_rejects_symlinked_root_and_intermediate_directory(tmp_path: Path) -> None:
    source = b"format x date9.;"
    evidence = classify(source)
    policy = classification_policy()
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        publish_classification_evidence(linked_root, evidence, source=source, policy=policy)

    root = tmp_path / "output"
    root.mkdir()
    (root / "client-synthetic").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        publish_classification_evidence(root, evidence, source=source, policy=policy)


@pytest.mark.parametrize("target_name", ["evidence", "telemetry"])
def test_publication_rejects_same_byte_symlinked_canonical_targets(
    tmp_path: Path, target_name: str
) -> None:
    source = b"format x date9.;"
    evidence = classify(source)
    policy = classification_policy()
    evidence_path, telemetry_path = publish_classification_evidence(
        tmp_path, evidence, source=source, policy=policy
    )
    target = evidence_path if target_name == "evidence" else telemetry_path
    outside = tmp_path / f"outside-{target_name}.json"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(outside)

    with pytest.raises(ValueError, match="symlink|regular file"):
        if target_name == "telemetry":
            recover_classification_telemetry(evidence_path)
        else:
            publish_classification_evidence(tmp_path, evidence, source=source, policy=policy)


def test_recovery_rejects_mutated_or_traversing_canonical_evidence(tmp_path: Path) -> None:
    source = b"format x date9.;"
    evidence = classify(source)
    evidence_path, telemetry_path = publish_classification_evidence(
        tmp_path, evidence, source=source, policy=classification_policy()
    )
    telemetry_path.unlink()
    mutated = json.loads(evidence_path.read_text(encoding="utf-8"))
    mutated["decision_id"] = "decision-mutated"
    evidence_path.write_text(json.dumps(mutated), encoding="utf-8")

    with pytest.raises(ValueError, match="digest"):
        recover_classification_telemetry(evidence_path)
    assert not telemetry_path.exists()

    traversing = evidence_path.parent / ".." / evidence_path.parent.name / evidence_path.name
    with pytest.raises(ValueError, match="traversal"):
        recover_classification_telemetry(traversing)


def test_publication_rejects_non_regular_canonical_evidence(tmp_path: Path) -> None:
    source = b"format x date9.;"
    evidence = classify(source)
    directory = tmp_path.joinpath("client-synthetic", "workload-1", "run-1", "attempt-1")
    (directory / "sas-semantics.evidence.json").mkdir(parents=True)

    with pytest.raises(ValueError, match="regular file"):
        publish_classification_evidence(
            tmp_path, evidence, source=source, policy=classification_policy()
        )


def test_duplicate_occurrence_identity_is_rejected_before_publication(tmp_path: Path) -> None:
    source = b"format x date9.;"
    policy = classification_policy()
    evidence = classify_format_function_semantics(source, request(), policy)
    evidence["occurrences"].append(dict(evidence["occurrences"][0]))
    content = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    evidence["evidence_sha256"] = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()

    with pytest.raises(ValueError, match="exact source|duplicate"):
        publish_classification_evidence(tmp_path, evidence, source=source, policy=policy)


def test_evidence_matches_strict_schema() -> None:
    evidence = classify(b"format x comma12.2; x=put(value,date9.); y=input(raw,yymmdd10.);")
    schema = json.loads((ROOT / "schemas/sas-format-function-evidence.schema.json").read_text())
    packaged_schema = json.loads(
        (ROOT / "src/smf/schemas/sas-format-function-evidence.schema.json").read_text()
    )
    policy_schema = json.loads(
        (ROOT / "schemas/sas-format-function-policy.schema.json").read_text()
    )
    assert schema == packaged_schema
    registry = Registry().with_resource(
        "sas-format-function-policy.schema.json", Resource.from_contents(policy_schema)
    )
    Draft202012Validator(schema, registry=registry).validate(evidence)
