from pathlib import Path
from typing import Any

from smf.corpus import load_corpus_manifest
from smf.discovery import discover_source
from smf.discovery.sas_static import SasStaticFindings, analyze_sas_source
from smf.workload.models import EvidenceMethod, RelationshipKind

_CORPUS_ROOT = Path(__file__).parents[1] / "corpus"
_MANIFEST_ROOT = _CORPUS_ROOT / "manifests"


def _values(items: tuple[Any, ...]) -> set[str]:
    return {str(item.value) for item in items}


def _assert_manifest_discovery(manifest_name: str) -> SasStaticFindings:
    manifest = load_corpus_manifest(_MANIFEST_ROOT / manifest_name)
    sas_artifact = next(item for item in manifest.artifacts if item.role == "sas-program")
    findings = analyze_sas_source(sas_artifact.path.read_text(encoding="utf-8"))
    expected = manifest.expected["discovery"]

    for field in ("reads", "writes", "libraries"):
        if field in expected:
            assert _values(getattr(findings, field)) == set(expected[field])
    for field in (
        "by_variables",
        "macro_definitions",
        "macro_invocations",
        "macro_variables",
        "dynamic_dataset_references",
    ):
        if field in expected:
            assert set(getattr(findings, field)) == set(expected[field])
    return findings


def test_semantic_merge_fixture_discovers_manifest_lineage() -> None:
    _assert_manifest_discovery("semantic-merge-by.yaml")


def test_semantic_proc_sql_fixture_discovers_manifest_lineage() -> None:
    _assert_manifest_discovery("semantic-proc-sql-lineage.yaml")


def test_semantic_macro_fixture_preserves_manifest_dynamic_references() -> None:
    findings = _assert_manifest_discovery("semantic-macro-generation.yaml")
    assert not findings.reads
    assert not findings.writes


def test_macro_triggers_resolve_in_double_but_not_single_quoted_strings() -> None:
    findings = analyze_sas_source(
        'title "%helper(); &resolved";\ntitle \'%ignored(); &ignored\';\ntitle "%&selected;";\n'
    )

    assert [(item.value, item.line) for item in findings.macro_invocation_references] == [
        ("helper", 1)
    ]
    assert findings.dynamic_macro_invocations[0].value == "&selected"
    assert findings.dynamic_macro_invocations[0].line == 3
    assert set(findings.macro_variables) == {"resolved", "selected"}


def test_multiline_statement_comment_preserves_macro_invocation_line() -> None:
    findings = analyze_sas_source("* first\n second;\n%actual;\n")

    assert [(item.value, item.line) for item in findings.macro_invocation_references] == [
        ("actual", 3)
    ]


def test_parameterless_macro_call_without_semicolon_is_discovered() -> None:
    findings = analyze_sas_source(
        "%macro helper; %mend;\n%helper\n%if 1 %then %do;\n  %put ready;\n%end;\n%finished_label:\n"
    )

    assert [(item.value, item.line) for item in findings.macro_invocation_references] == [
        ("helper", 2)
    ]


def test_statement_comment_after_semicolon_does_not_create_macro_invocation() -> None:
    findings = analyze_sas_source(
        "data x; * %commented_helper; run;\n"
        "data y; value = left * right; run;\n"
        "%* %macro_commented_helper;\n"
        "%actual;\n"
    )

    assert [(item.value, item.line) for item in findings.macro_invocation_references] == [
        ("actual", 4)
    ]


def test_nrstr_payload_does_not_create_macro_references() -> None:
    findings = analyze_sas_source("%let literal=%nrstr(%helper(&argument));\n%actual;\n")

    assert [(item.value, item.line) for item in findings.macro_invocation_references] == [
        ("nrstr", 1),
        ("actual", 2),
    ]
    assert findings.macro_variables == ()


def test_nrstr_text_inside_single_quotes_does_not_mask_later_macro_call() -> None:
    findings = analyze_sas_source("title '%nrstr(';\n%actual;\n")

    assert [(item.value, item.line) for item in findings.macro_invocation_references] == [
        ("actual", 2)
    ]


def test_dataset_option_macro_variables_are_not_dynamic_dataset_references() -> None:
    findings = analyze_sas_source(
        'data work.output(label="&label");\n'
        "  set work.input(obs=&limit where=(member_id=&member_id));\n"
        "run;\n"
    )

    assert _values(findings.writes) == {"work.output"}
    assert _values(findings.reads) == {"work.input"}
    assert findings.dynamic_dataset_references == ()


def test_dynamic_proc_data_and_out_references_are_preserved() -> None:
    findings = analyze_sas_source(
        "proc sort data=&input. out=&output.;\n"
        "proc print data=work.literal(where=(id=&member_id));\n"
    )

    assert findings.dynamic_dataset_references == ("&input.", "&output.")
    assert [(item.value, item.line) for item in findings.dynamic_dataset_reference_details] == [
        ("&input.", 1),
        ("&output.", 1),
    ]
    assert _values(findings.reads) == {"work.literal"}


def test_public_sas_access_fixture_discovers_manifest_references() -> None:
    _assert_manifest_discovery("public-sas-access-odbc-bulkload.yaml")


def test_filesystem_discovery_normalizes_static_facts_into_workload_graph(
    tmp_path: Path,
) -> None:
    sas = tmp_path / "claims.sas"
    sas.write_text(
        "data work.out; set source.claims; by member_id; run;\n",
        encoding="utf-8",
    )

    result = discover_source(tmp_path, provider="filesystem", namespace="test")
    workload = result.workloads[0]
    datasets = {dataset.name: dataset for dataset in workload.datasets}
    artifact = next(item for item in workload.artifacts if item.name == "claims.sas")

    assert set(datasets) == {"source.claims", "work.out"}
    static_metadata = artifact.metadata["sas_static"]
    assert isinstance(static_metadata, dict)
    assert static_metadata["by_variables"] == ["member_id"]

    relationships = {
        (relationship.kind, target.name)
        for relationship in workload.relationships
        for target in workload.datasets
        if relationship.target_id == target.dataset_id
    }
    assert (RelationshipKind.READS, "source.claims") in relationships
    assert (RelationshipKind.WRITES, "work.out") in relationships
    assert all(
        evidence.method is EvidenceMethod.STATIC_ANALYSIS
        for relationship in workload.relationships
        for evidence in relationship.evidence
    )
