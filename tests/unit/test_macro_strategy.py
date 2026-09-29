import hashlib
from pathlib import Path

from smf.discovery import discover_source
from smf.discovery.macro_strategy import (
    STRATEGY_DIGEST,
    analyze_macro_workload,
    strategy_snapshot,
)
from smf.workload.models import (
    MacroArtifactType,
    MacroConstructFamily,
    MacroObservationKind,
    MacroResolutionKind,
    RelationshipKind,
)


def _discover(root: Path, namespace: str = "macro-strategy"):
    return discover_source(root, provider="filesystem", namespace=namespace).workloads[0]


def test_unique_resolution_is_byte_bound_and_never_claims_expansion(tmp_path: Path) -> None:
    source = "/* café */\n%macro Claims(member=); %put &member.; %mend;\n%claims(member=1);\n"
    (tmp_path / "main.sas").write_text(source, encoding="utf-8")

    workload = _discover(tmp_path)
    analysis = workload.macro_analysis
    assert analysis is not None
    assert analysis.expansion_mode == "none"
    assert analysis.strategy_digest == STRATEGY_DIGEST
    assert analysis.complete is True
    payload = workload.to_dict()["macro_analysis"]
    assert payload["expansion_mode"] == "none"
    assert "expanded_source" not in payload
    assert "expansion_succeeded" not in payload

    definition = next(
        item
        for item in analysis.logical_artifacts
        if item.artifact_type is MacroArtifactType.SAS_MACRO_DEFINITION
    )
    call = next(
        item
        for item in analysis.observations
        if item.kind is MacroObservationKind.LITERAL_INVOCATION
        and item.normalized_identity == "claims"
    )
    resolution = next(
        item for item in analysis.resolutions if item.observation_id == call.observation_id
    )
    assert resolution.kind is MacroResolutionKind.UNIQUE_STATIC_DEFINITION
    assert resolution.target_definition_id == definition.logical_artifact_id
    raw = source.encode()
    assert (
        hashlib.sha256(raw[call.location.byte_start : call.location.byte_end]).hexdigest()
        == call.location.span_digest
    )
    assert call.location.line == 3
    assert call.location.column == 1
    assert call.location.source_checksum == hashlib.sha256(raw).hexdigest()

    edge = next(item for item in workload.relationships if item.kind is RelationshipKind.CALLS)
    assert edge.metadata["macro_resolution_id"] == resolution.resolution_id
    assert edge.metadata["macro_strategy_digest"] == STRATEGY_DIGEST


def test_duplicate_occurrences_in_one_artifact_are_ambiguous(tmp_path: Path) -> None:
    (tmp_path / "duplicate.sas").write_text(
        "%macro helper; %mend;\n%macro HELPER; %mend;\n%helper;\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    analysis = workload.macro_analysis
    assert analysis is not None
    definitions = [
        item for item in analysis.logical_artifacts if item.normalized_identity == "helper"
    ]
    assert len(definitions) == 2
    assert len({item.logical_artifact_id for item in definitions}) == 2
    call = next(
        item
        for item in analysis.observations
        if item.kind is MacroObservationKind.LITERAL_INVOCATION
    )
    resolution = next(
        item for item in analysis.resolutions if item.observation_id == call.observation_id
    )
    assert resolution.kind is MacroResolutionKind.AMBIGUOUS
    assert len(resolution.candidate_definition_ids) == 2
    assert not any(item.kind is RelationshipKind.CALLS for item in workload.relationships)


def test_unreferenced_workload_macro_is_not_invented_as_visible(tmp_path: Path) -> None:
    (tmp_path / "autocall.sas").write_text("%macro helper; %mend;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text("%helper;\n", encoding="utf-8")

    workload = _discover(tmp_path)
    analysis = workload.macro_analysis
    assert analysis is not None
    call = next(
        item
        for item in analysis.observations
        if item.kind is MacroObservationKind.LITERAL_INVOCATION
    )
    resolution = next(
        item for item in analysis.resolutions if item.observation_id == call.observation_id
    )
    assert resolution.kind is MacroResolutionKind.MISSING
    assert resolution.candidate_definition_ids == ()
    assert not any(item.kind is RelationshipKind.CALLS for item in workload.relationships)


def test_missing_dynamic_recursive_and_cyclic_calls_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "calls.sas").write_text(
        "%macro self; %self; %mend;\n"
        "%macro left; %right; %mend;\n"
        "%macro right; %left; %mend;\n"
        "%missing;\n%&selected;\n",
        encoding="utf-8",
    )

    analysis = _discover(tmp_path).macro_analysis
    assert analysis is not None
    kinds = {item.kind for item in analysis.resolutions}
    assert {
        MacroResolutionKind.MISSING,
        MacroResolutionKind.DYNAMIC,
        MacroResolutionKind.RECURSIVE,
        MacroResolutionKind.CYCLIC,
        MacroResolutionKind.RUNTIME_DEPENDENT,
    }.issubset(kinds)
    assert {item.reason for item in analysis.blockers}.issuperset(
        {
            MacroResolutionKind.MISSING,
            MacroResolutionKind.DYNAMIC,
            MacroResolutionKind.RECURSIVE,
            MacroResolutionKind.CYCLIC,
        }
    )


def test_comments_literals_intrinsics_and_construct_families_do_not_cross_resolve(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.sas").write_text(
        "/* %phantom; &phantom; */\n"
        "title '%ignored; &ignored';\n"
        "%let literal=%nrstr(%protected(&protected));\n"
        "%put %eval(1+1);\n"
        "proc format; value helper 1='one'; run;\n"
        "x = {{ helper() }};\n"
        "%helper;\n",
        encoding="utf-8",
    )

    analysis = _discover(tmp_path).macro_analysis
    assert analysis is not None
    identities = {item.normalized_identity for item in analysis.observations}
    assert not {"phantom", "ignored", "protected"} & identities
    helper_call = next(
        item
        for item in analysis.observations
        if item.kind is MacroObservationKind.LITERAL_INVOCATION
        and item.normalized_identity == "helper"
    )
    resolution = next(
        item for item in analysis.resolutions if item.observation_id == helper_call.observation_id
    )
    assert resolution.kind is MacroResolutionKind.MISSING
    families = {item.construct_family for item in analysis.logical_artifacts}
    assert MacroConstructFamily.SAS_PROC_FORMAT in families
    assert MacroConstructFamily.TARGET_TEMPLATE in families
    assert {
        MacroArtifactType.PROC_FORMAT_DEFINITION,
        MacroArtifactType.TARGET_TEMPLATE_DEFINITION,
    }.issubset({item.artifact_type for item in analysis.logical_artifacts})
    eval_observation = next(
        item for item in analysis.observations if item.normalized_identity == "eval"
    )
    eval_resolution = next(
        item
        for item in analysis.resolutions
        if item.observation_id == eval_observation.observation_id
    )
    assert eval_resolution.kind is MacroResolutionKind.INTRINSIC_SYSTEM


def test_include_resolution_and_boundary_escape_are_explicit(tmp_path: Path) -> None:
    (tmp_path / "inc.sas").write_text("%macro included; %mend;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text(
        "%include 'inc.sas';\n%include '../outside.sas';\n%include \"&chosen\";\n",
        encoding="utf-8",
    )

    analysis = _discover(tmp_path).macro_analysis
    assert analysis is not None
    include_observations = {
        item.normalized_identity: item
        for item in analysis.observations
        if item.kind is MacroObservationKind.INCLUDE_REFERENCE
    }
    include_kinds = {
        name: next(
            item.kind
            for item in analysis.resolutions
            if item.observation_id == observation.observation_id
        )
        for name, observation in include_observations.items()
    }
    assert include_kinds == {
        "inc.sas": MacroResolutionKind.UNIQUE_STATIC_DEFINITION,
        "../outside.sas": MacroResolutionKind.UNSUPPORTED,
        "&chosen": MacroResolutionKind.DYNAMIC,
    }


def test_in_root_parent_include_uses_canonical_resolution_contract(tmp_path: Path) -> None:
    jobs = tmp_path / "jobs"
    includes = tmp_path / "includes"
    jobs.mkdir()
    includes.mkdir()
    (jobs / "main.sas").write_text('%include "../includes/common.sas";\n', encoding="utf-8")
    (includes / "common.sas").write_text("%macro included; %mend;\n", encoding="utf-8")

    workload = _discover(tmp_path)
    analysis = workload.macro_analysis
    assert analysis is not None
    observation = next(
        item
        for item in analysis.observations
        if item.kind is MacroObservationKind.INCLUDE_REFERENCE
    )
    resolution = next(
        item for item in analysis.resolutions if item.observation_id == observation.observation_id
    )
    relationship = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )

    assert resolution.kind is MacroResolutionKind.UNIQUE_STATIC_DEFINITION
    assert resolution.target_artifact_id == relationship.target_id
    assert resolution.resolution_id == relationship.metadata["include_resolution_id"]


def test_include_cycle_blocks_macro_visibility(tmp_path: Path) -> None:
    (tmp_path / "a.sas").write_text('%include "b.sas";\n%from_b;\n', encoding="utf-8")
    (tmp_path / "b.sas").write_text('%include "a.sas";\n%macro from_b; %mend;\n', encoding="utf-8")

    analysis = _discover(tmp_path).macro_analysis
    assert analysis is not None
    include_resolutions = [
        item
        for item in analysis.resolutions
        if item.relationship_kind.value == "sas_include_reference"
    ]
    call = next(
        item
        for item in analysis.observations
        if item.kind is MacroObservationKind.LITERAL_INVOCATION
        and item.normalized_identity == "from_b"
    )
    call_resolution = next(
        item for item in analysis.resolutions if item.observation_id == call.observation_id
    )

    assert {item.kind for item in include_resolutions} == {MacroResolutionKind.CYCLIC}
    assert call_resolution.kind is MacroResolutionKind.MISSING


def test_invalid_utf8_is_not_replacement_character_analyzed(tmp_path: Path) -> None:
    raw = b"%macro valid; %mend;\n\xff%valid;\n"
    (tmp_path / "invalid.sas").write_bytes(raw)

    analysis = _discover(tmp_path).macro_analysis
    assert analysis is not None
    assert analysis.complete is False
    assert analysis.observations == ()
    assert any(item.detail == "unsupported_utf8_encoding" for item in analysis.blockers)
    assert analysis.source_inventory[0]["source_checksum"] == hashlib.sha256(raw).hexdigest()


def test_source_change_invalidates_analysis_and_strategy_snapshot_is_isolated(
    tmp_path: Path,
) -> None:
    path = tmp_path / "main.sas"
    path.write_text("%missing;\n", encoding="utf-8")
    first = _discover(tmp_path, "stable").macro_analysis
    path.write_text("%other_missing;\n", encoding="utf-8")
    second = _discover(tmp_path, "stable").macro_analysis
    assert first is not None and second is not None
    assert first.analysis_id != second.analysis_id
    assert first.discovery_id != second.discovery_id

    mutated = strategy_snapshot()
    mutated["expansion_mode"] = "executable"
    assert strategy_snapshot()["expansion_mode"] == "none"
    assert (
        hashlib.sha256(
            __import__("json")
            .dumps(strategy_snapshot(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            .encode()
        ).hexdigest()
        == STRATEGY_DIGEST
    )


def test_macro_nesting_limit_is_fail_closed_without_recursive_traversal_crash(
    tmp_path: Path,
) -> None:
    chain_root = tmp_path / "long-chain"
    chain_root.mkdir()
    macro_count = 1_100
    chain_root.joinpath("chain.sas").write_text(
        "".join(
            f"%macro m{index}; "
            + (f"%m{index + 1}; " if index < macro_count - 1 else "")
            + "%mend;\n"
            for index in range(macro_count)
        ),
        encoding="utf-8",
    )

    workload = _discover(chain_root, "long-chain")
    first = workload.macro_analysis
    source_artifact = next(item for item in workload.artifacts if item.logical_path == "chain.sas")
    second = analyze_macro_workload(
        workload, {source_artifact.artifact_id: chain_root.joinpath("chain.sas").read_bytes()}
    ).macro_analysis
    assert first is not None and second is not None
    assert first.analysis_id == second.analysis_id
    assert first.complete is False
    assert any(item.kind is MacroResolutionKind.LIMIT_EXCEEDED for item in first.resolutions)
    assert any(
        item.reason is MacroResolutionKind.LIMIT_EXCEEDED
        and item.detail == "max_macro_nesting_depth"
        for item in first.blockers
    )
    assert not any(item.kind is MacroResolutionKind.CYCLIC for item in first.resolutions)

    independent_root = tmp_path / "independent"
    independent_root.mkdir()
    independent_root.joinpath("main.sas").write_text("%macro ok; %mend;\n%ok;\n", encoding="utf-8")
    independent = _discover(independent_root, "independent").macro_analysis
    assert independent is not None
    assert independent.complete is True
