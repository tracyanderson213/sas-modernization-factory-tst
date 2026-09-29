from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from importlib.resources import files
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from smf.library_binding import (
    BindingPolicy,
    BindingRequest,
    RuntimeBindingEvidence,
    SourceDocument,
    evaluate_library_bindings,
    publish_library_bindings,
    runtime_evidence_digest,
    runtime_evidence_signing_payload,
)

_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY = base64.b64encode(
    _PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode()


def _request(source: str, *, runtime: tuple[RuntimeBindingEvidence, ...] = ()) -> BindingRequest:
    content = source.encode()
    return BindingRequest(
        workload_id="workload-1",
        source_closure_digest="a" * 64,
        documents=(
            SourceDocument("artifact-1", "job.sas", content, hashlib.sha256(content).hexdigest()),
        ),
        policy=BindingPolicy(
            "base06",
            "1",
            "synthetic-client",
            (("sas-trace", "1"),),
            ("fixture-authority",),
            (("fixture-key", _PUBLIC_KEY),),
        ),
        runtime_evidence=runtime,
        run_id="run-1",
        attempt_id="attempt-1",
        evaluated_at="2026-09-20T12:00:00+00:00",
    )


def _signed_evidence(
    request: BindingRequest,
    initial: dict[str, object],
    *,
    libref: str,
    occurrence_id: str,
    observed_at: str = "2026-09-20T11:30:00+00:00",
) -> RuntimeBindingEvidence:
    evidence = RuntimeBindingEvidence(
        f"evidence-{libref}",
        request.policy.client_id,
        request.workload_id,
        request.source_closure_digest,
        str(initial["policy_digest"]),
        request.run_id,
        request.attempt_id,
        libref,
        occurrence_id,
        (f"/observed/{libref}",),
        "sas-trace",
        "1",
        observed_at,
        "fixture-authority",
        "fixture-key",
        "",
        "",
    )
    evidence = replace(evidence, evidence_digest=runtime_evidence_digest(evidence))
    return replace(
        evidence,
        signature=base64.b64encode(
            _PRIVATE_KEY.sign(runtime_evidence_signing_payload(evidence))
        ).decode(),
    )


def _resign(evidence: RuntimeBindingEvidence) -> RuntimeBindingEvidence:
    evidence = replace(evidence, evidence_digest=runtime_evidence_digest(evidence), signature="")
    return replace(
        evidence,
        signature=base64.b64encode(
            _PRIVATE_KEY.sign(runtime_evidence_signing_payload(evidence))
        ).decode(),
    )


def test_documented_literal_forms_are_source_located_without_path_authority() -> None:
    result = evaluate_library_bindings(
        _request(
            "libname one '/safe/one';\n"
            'libname TWO base "/safe/two";\n'
            "libname many ('/safe/a' \"/safe/b\");\n"
        )
    ).result

    assert [item["state"] for item in result["bindings"]] == ["literal"] * 3
    assert result["bindings"][0]["claims"] == {
        "authoritative_logical_binding": True,
        "path_exists": False,
        "path_authorized": False,
        "credentials_resolved": False,
        "connectivity_validated": False,
    }
    assert result["occurrences"][0]["source_path"] == "job.sas"
    assert result["occurrences"][0]["line"] == 1
    assert result["claims"]["customer_paths_accessed"] is False


def test_comments_and_quoted_libname_text_are_excluded() -> None:
    result = evaluate_library_bindings(
        _request(
            "/* libname bad '/secret'; */\n"
            "   * libname also_bad '/secret';\n"
            "%* libname macro_bad '/secret';\n"
            "data _null_; x=\"libname quoted '/secret';\"; run;\n"
            "libname good '/fixture';\n"
        )
    ).result

    assert [item["libref"] for item in result["bindings"]] == ["good"]


def test_dynamic_missing_macro_and_unsupported_engine_fail_closed() -> None:
    result = evaluate_library_bindings(
        _request('libname dyn "&missing./data"; libname db oracle user=u password=p;')
    ).result
    by_ref = {item["libref"]: item for item in result["bindings"]}

    assert by_ref["dyn"]["state"] == "dynamic"
    assert "missing_macro" in by_ref["dyn"]["blockers"]
    assert by_ref["db"]["state"] == "unresolved"
    assert by_ref["db"]["logical_paths"] == []
    assert all(not item["claims"]["credentials_resolved"] for item in by_ref.values())


def test_reassignment_and_clear_do_not_select_a_binding() -> None:
    reassigned = evaluate_library_bindings(_request("libname x '/one'; libname x '/two';")).result[
        "bindings"
    ][0]
    cleared = evaluate_library_bindings(_request("libname x '/one'; libname x clear;")).result[
        "bindings"
    ][0]

    assert reassigned["state"] == "ambiguous"
    assert reassigned["logical_paths"] == []
    assert "reassigned" in reassigned["blockers"]
    assert cleared["state"] == "cleared"
    assert cleared["claims"]["authoritative_logical_binding"] is False


def test_governed_runtime_evidence_can_select_reassignment() -> None:
    request = _request("libname x '/one'; libname x '/two';")
    initial = evaluate_library_bindings(request).result
    selected = initial["occurrences"][1]["occurrence_id"]
    evidence = _signed_evidence(request, initial, libref="x", occurrence_id=selected)

    binding = evaluate_library_bindings(replace(request, runtime_evidence=(evidence,))).result[
        "bindings"
    ][0]
    assert binding["state"] == "runtime_observed"
    assert binding["logical_paths"] == ["/observed/x"]
    assert binding["selected_occurrence_id"] == selected
    assert binding["claims"]["path_authorized"] is False


@pytest.mark.parametrize(
    "field", ["workload_id", "source_closure_digest", "policy_digest", "run_id"]
)
def test_runtime_evidence_cross_boundary_mutations_are_rejected(field: str) -> None:
    request = _request("libname x '/one';")
    initial = evaluate_library_bindings(request).result
    evidence = _signed_evidence(
        request,
        initial,
        libref="x",
        occurrence_id=initial["occurrences"][0]["occurrence_id"],
    )
    mutated = replace(evidence, **{field: "b" * 64 if "digest" in field else "other"})
    mutated = _resign(mutated)

    with pytest.raises(ValueError, match="outside the governed request"):
        evaluate_library_bindings(replace(request, runtime_evidence=(mutated,)))


def test_runtime_evidence_digest_and_source_mutation_are_rejected() -> None:
    request = _request("libname x '/one';")
    bad_document = replace(request.documents[0], content=b"libname x '/two';")
    with pytest.raises(ValueError, match="checksum mismatch"):
        evaluate_library_bindings(replace(request, documents=(bad_document,)))

    initial = evaluate_library_bindings(request).result
    evidence = _signed_evidence(
        request,
        initial,
        libref="x",
        occurrence_id=initial["occurrences"][0]["occurrence_id"],
    )
    evidence = replace(evidence, evidence_digest="bad")
    with pytest.raises(ValueError, match="digest mismatch"):
        evaluate_library_bindings(replace(request, runtime_evidence=(evidence,)))


def test_runtime_evidence_cannot_select_another_libref_or_clear_occurrence() -> None:
    request = _request("libname x '/one'; libname y '/two'; libname z clear;")
    initial = evaluate_library_bindings(request).result
    by_ref = {item["libref"]: item for item in initial["occurrences"]}
    for libref, selected in (("x", by_ref["y"]), ("z", by_ref["z"])):
        evidence = _signed_evidence(
            request,
            initial,
            libref=libref,
            occurrence_id=selected["occurrence_id"],
        )
        with pytest.raises(ValueError, match="outside the governed request"):
            evaluate_library_bindings(replace(request, runtime_evidence=(evidence,)))


def test_runtime_evidence_cannot_revive_superseded_occurrence() -> None:
    request = _request("libname x '/one'; libname x '/two';")
    initial = evaluate_library_bindings(request).result
    evidence = _signed_evidence(
        request,
        initial,
        libref="x",
        occurrence_id=initial["occurrences"][0]["occurrence_id"],
    )
    with pytest.raises(ValueError, match="outside the governed request"):
        evaluate_library_bindings(replace(request, runtime_evidence=(evidence,)))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"signature": ""}, "proof is invalid"),
        ({"authority": "caller"}, "authority is not trusted"),
        ({"provider_version": "2"}, "outside the governed request"),
        ({"observed_at": "2026-09-20T10:00:00+00:00"}, "stale"),
        ({"observed_at": "2026-09-20T13:00:00+00:00"}, "from the future"),
        ({"observed_at": "not-a-time"}, "proof is invalid"),
    ],
)
def test_runtime_proof_authority_revision_and_time_fail_closed(
    mutation: dict[str, str], message: str
) -> None:
    request = _request("libname x '/one';")
    initial = evaluate_library_bindings(request).result
    evidence = _signed_evidence(
        request,
        initial,
        libref="x",
        occurrence_id=initial["occurrences"][0]["occurrence_id"],
    )
    mutated = replace(evidence, **mutation)
    if "signature" not in mutation:
        mutated = _resign(mutated)
    with pytest.raises(ValueError, match=message):
        evaluate_library_bindings(replace(request, runtime_evidence=(mutated,)))


def test_result_validates_against_strict_schema_and_is_deterministic() -> None:
    request = _request("libname x '/one';")
    first = evaluate_library_bindings(request)
    second = evaluate_library_bindings(request)

    assert first == second
    schema = json.loads(
        files("smf.schemas")
        .joinpath("sas-library-binding-evidence.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(first.result)
    assert first.projection["result_id"] == first.result["result_id"]


def test_publication_is_restart_safe_and_detects_mutation(tmp_path: Path) -> None:
    request = _request("libname x '/one';")
    prepared = evaluate_library_bindings(request)
    paths = publish_library_bindings(prepared, request, tmp_path)

    assert publish_library_bindings(prepared, request, tmp_path) == paths
    paths[0].write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="schema violation|differs from prepared evidence"):
        publish_library_bindings(prepared, request, tmp_path)


def test_publication_recomputes_before_first_write_and_closes_nested_schema(tmp_path: Path) -> None:
    from smf.library_binding.publication import _validate_result

    request = _request("libname x '/one';")
    prepared = evaluate_library_bindings(request)
    tampered_result = {**prepared.result, "run_id": "other-run"}
    tampered = replace(prepared, result=tampered_result)
    with pytest.raises(ValueError, match="does not match authoritative inputs"):
        publish_library_bindings(tampered, request, tmp_path)
    assert not (tmp_path / "library-bindings").exists()

    unknown = json.loads(json.dumps(prepared.result))
    unknown["occurrences"][0]["caller_authorized"] = True
    with pytest.raises(ValueError, match="schema violation"):
        _validate_result(unknown)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_closure_digest", "password=secret-canary-value"),
        ("evaluated_at", "password=secret-canary-value"),
    ],
)
def test_protected_request_fields_are_rejected_without_echo(field: str, value: str) -> None:
    request = replace(_request("libname x '/one';"), **{field: value})
    with pytest.raises(ValueError) as error:
        evaluate_library_bindings(request)
    assert "secret-canary-value" not in str(error.value)


def test_secret_canary_is_not_persisted() -> None:
    with pytest.raises(ValueError, match="contains protected data") as error:
        evaluate_library_bindings(_request("libname x '/tmp/password=secret-canary-value';"))
    assert "secret-canary-value" not in str(error.value)
