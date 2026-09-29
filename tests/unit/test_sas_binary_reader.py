from __future__ import annotations

import hashlib
import importlib
import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

try:
    pyreadstat = importlib.import_module("pyreadstat")
except ModuleNotFoundError as exc:
    if os.environ.get("SMF_REQUIRE_SAS_READER") == "1":
        raise RuntimeError(
            "BASE-08 confidence requires the pinned conversion extra: "
            "python -m pip install -e '.[dev,conversion]'"
        ) from exc
    pytest.skip(
        "optional BASE-08 provider is not installed; run make base08-confidence",
        allow_module_level=True,
    )

from smf.sas_reader import (
    PyreadstatProvider,
    ReaderConfig,
    ReaderRequest,
    provider_distribution_digest,
    publish_reader_result,
    read_sas7bdat,
    verify_reader_result,
)
from smf.upstream.crypto import digest_value

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "sas_reader"
FIXTURE = FIXTURE_ROOT / "sample_bincompressed.sas7bdat"
FIXTURE_SHA = "641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c"


def _provider() -> PyreadstatProvider:
    return PyreadstatProvider()


def _config(provider: PyreadstatProvider, **overrides: Any) -> ReaderConfig:
    values: dict[str, Any] = {
        "provider_distribution_digest": provider.runtime_identity()["distribution_record_sha256"],
        "chunk_rows": 2,
        "max_source_bytes": 1024 * 1024,
        "max_rows": 100,
    }
    values.update(overrides)
    return ReaderConfig(**values)


def test_distribution_digest_has_stable_public_entrypoint() -> None:
    assert (
        provider_distribution_digest()
        == _provider().runtime_identity()["distribution_record_sha256"]
    )


def test_runtime_dependency_design_is_pinned_and_fail_closed() -> None:
    repository = Path(__file__).parents[2]
    design = json.loads(
        (repository / "config/dependencies/sas-reader-runtime.json").read_text(encoding="utf-8")
    )
    assert design["provider"]["version"] == "1.3.6"
    assert design["provider"]["release_tag_source_revision"] == (
        "ae4bfa5d84ed1ceaf847ab242118da730a4084ec"
    )
    assert design["provider"]["evaluated_upstream_revision"] == (
        "12cc1495d468ae8a170c57cce7557c147b972eac"
    )
    assert len(design["provider"]["artifacts"]) == 3
    assert design["runtime_dependencies"] == [
        {
            "distribution": "narwhals",
            "version": "2.26.0",
            "offline_artifact_sha256": None,
            "qualification_state": "pending-pkg-qual-01",
        },
        {
            "distribution": "numpy",
            "version": "2.4.6",
            "python": ">=3.11,<3.12",
            "offline_artifact_sha256": None,
            "qualification_state": "pending-pkg-qual-01",
        },
        {
            "distribution": "numpy",
            "version": "2.5.3",
            "python": ">=3.12,<3.13",
            "offline_artifact_sha256": None,
            "qualification_state": "pending-pkg-qual-01",
        },
    ]
    assert not any(design["claims"].values())


def _request(**overrides: Any) -> ReaderRequest:
    values: dict[str, Any] = {
        "client_id": "public-upstream",
        "workload_id": "pyreadstat-basic",
        "source_id": "sample-bincompressed",
        "run_id": "base08-run",
        "attempt_id": "attempt-1",
        "relative_path": FIXTURE.name,
        "source_sha256": FIXTURE_SHA,
        "source_byte_count": FIXTURE.stat().st_size,
    }
    values.update(overrides)
    return ReaderRequest(**values)


def test_real_binary_compressed_fixture_reads_raw_underlying_values() -> None:
    provider = _provider()
    execution = read_sas7bdat(
        _request(), authorized_root=FIXTURE_ROOT, config=_config(provider), provider=provider
    )

    assert execution.result["state"] == "complete"
    assert execution.result["source"] == {
        "sha256": FIXTURE_SHA,
        "byte_count": FIXTURE.stat().st_size,
        "snapshot_verified": True,
    }
    descriptor = execution.result["descriptor"]
    assert descriptor["observed_row_count"] == descriptor["declared_row_count"] == 5
    assert descriptor["observed_column_count"] == descriptor["declared_column_count"] == 7
    assert descriptor["file_encoding"] == "UTF-8"
    assert descriptor["table_name"] == "BINCOMPRESSED"
    assert descriptor["declared_keys"] == []
    assert descriptor["key_authority"] == "unavailable_not_inferred"
    by_name = {column["name"]: column for column in descriptor["columns"]}
    assert by_name["mydate"]["declared"]["format"] == "YYMMDD10"
    assert by_name["dtime"]["declared"]["format"] == "DATETIME"
    assert by_name["mytime"]["declared"]["format"] == "TIME20.3"
    assert by_name["dtime"]["observed"]["normalized_type"] == "float"
    assert by_name["mydate"]["observed"]["null_count"] == 1
    assert by_name["dtime"]["observed"]["null_count"] == 1
    assert by_name["mytime"]["observed"]["null_count"] == 1
    assert by_name["mydate"]["observed"]["nullable"] is True
    assert execution.chunks[0][0][0:2] == ("a", 1.1)
    assert isinstance(execution.chunks[0][0][2], float)
    assert [item["row_count"] for item in execution.result["chunks"]] == [2, 2, 1]
    assert not any(execution.result["claims"].values())


def test_fixture_and_license_provenance_are_byte_exact() -> None:
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA
    license_path = FIXTURE_ROOT / "LICENSE.pyreadstat"
    assert hashlib.sha256(license_path.read_bytes()).hexdigest() == (
        "07487bc4080297d9c65ffa3f66e3c405f9fd08e4af990cd54212d373eb28debc"
    )
    readme = (FIXTURE_ROOT / "README.md").read_text(encoding="utf-8")
    assert "12cc1495d468ae8a170c57cce7557c147b972eac" in readme
    assert "Apache-2.0" in readme and "ReadStat" in readme and "MIT" in readme


def test_source_snapshot_mismatch_fails_without_rows() -> None:
    provider = _provider()
    execution = read_sas7bdat(
        _request(source_sha256="0" * 64),
        authorized_root=FIXTURE_ROOT,
        config=_config(provider),
        provider=provider,
    )
    assert execution.result["state"] == "failed"
    assert execution.result["blockers"] == ["source_snapshot_mismatch"]
    assert execution.chunks == ()


def test_corrupt_and_unsupported_encoding_are_explicit(tmp_path: Path) -> None:
    provider = _provider()
    corrupt = tmp_path / "bad.sas7bdat"
    corrupt.write_bytes(FIXTURE.read_bytes()[:128])
    request = _request(
        relative_path=corrupt.name,
        source_sha256=hashlib.sha256(corrupt.read_bytes()).hexdigest(),
        source_byte_count=corrupt.stat().st_size,
    )
    result = read_sas7bdat(
        request, authorized_root=tmp_path, config=_config(provider), provider=provider
    ).result
    assert result["state"] == "unsupported"
    assert result["blockers"] == ["corrupt_encoding_or_provider_unsupported"]
    assert result["diagnostic"] in {"provider_error_present", "provider_error_redacted"}

    encoded = read_sas7bdat(
        _request(),
        authorized_root=FIXTURE_ROOT,
        config=_config(provider, encoding="definitely-not-an-encoding"),
        provider=provider,
    ).result
    assert encoded["state"] == "unsupported"
    assert encoded["blockers"] == ["corrupt_encoding_or_provider_unsupported"]


class _EncryptedBackend:
    __version__ = "1.3.6"

    def read_sas7bdat(self, path: str, **kwargs: Any) -> tuple[Any, Any]:
        raise RuntimeError("password protected dataset: secret-canary must never persist")


class _DelegatingBackend:
    __version__ = "1.3.6"

    def __init__(self, *, mutate_source: Path | None = None, special_missing: bool = False) -> None:
        self.mutate_source = mutate_source
        self.special_missing = special_missing

    def read_sas7bdat(self, path: str, **kwargs: Any) -> tuple[Any, Any]:
        rows, metadata = pyreadstat.read_sas7bdat(path, **kwargs)
        if self.special_missing:
            metadata.missing_user_values = {"mynum": ["A"]}
        if self.mutate_source is not None:
            self.mutate_source.write_bytes(self.mutate_source.read_bytes() + b"changed")
        return rows, metadata


class _ForgingBackend:
    __version__ = "1.3.6"

    def read_sas7bdat(self, path: str, **kwargs: Any) -> tuple[Any, Any]:
        rows, metadata = pyreadstat.read_sas7bdat(path, **kwargs)
        rows["mynum"][0] = 999999.0
        return rows, metadata


def test_encrypted_provider_failure_is_classified_and_redacted() -> None:
    provider = PyreadstatProvider(_EncryptedBackend())
    result = read_sas7bdat(
        _request(), authorized_root=FIXTURE_ROOT, config=_config(provider), provider=provider
    ).result
    assert result["state"] == "unsupported"
    assert result["blockers"] == ["encrypted_or_password_protected_unsupported"]
    assert result["diagnostic"] == "provider_error_redacted"
    assert "secret-canary" not in json.dumps(result)


def test_special_missing_metadata_blocks_until_semantically_qualified() -> None:
    provider = PyreadstatProvider(_DelegatingBackend(special_missing=True))
    result = read_sas7bdat(
        _request(), authorized_root=FIXTURE_ROOT, config=_config(provider), provider=provider
    ).result
    assert result["state"] == "unsupported"
    assert result["blockers"] == ["special_missing_values_require_semantic_qualification"]


def test_version_claiming_custom_backend_cannot_complete_or_publish(tmp_path: Path) -> None:
    provider = PyreadstatProvider(_ForgingBackend())
    config = _config(provider)
    request = _request()
    execution = read_sas7bdat(
        request, authorized_root=FIXTURE_ROOT, config=config, provider=provider
    )
    assert execution.result["state"] == "blocked"
    assert execution.result["blockers"] == ["synthetic_provider_cannot_authorize_completion"]
    assert execution.result["runtime"]["provider_authority"] == "synthetic_test_double"
    assert execution.chunks == ()
    with pytest.raises(ValueError, match="cannot be published"):
        publish_reader_result(
            tmp_path / "evidence",
            request,
            execution,
            authorized_root=FIXTURE_ROOT,
            config=config,
            provider=provider,
        )


def test_source_mutation_during_provider_execution_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / FIXTURE.name
    source.write_bytes(FIXTURE.read_bytes())
    provider = PyreadstatProvider(_DelegatingBackend(mutate_source=source))
    result = read_sas7bdat(
        _request(), authorized_root=tmp_path, config=_config(provider), provider=provider
    ).result
    assert result["state"] == "failed"
    assert result["blockers"] == ["source_mutated_during_read"]


def test_symlink_traversal_nonregular_and_bounds_fail_closed(tmp_path: Path) -> None:
    provider = _provider()
    (tmp_path / "linked.sas7bdat").symlink_to(FIXTURE)
    with pytest.raises(ValueError, match="symlinked|unsafe"):
        read_sas7bdat(
            _request(relative_path="linked.sas7bdat"),
            authorized_root=tmp_path,
            config=_config(provider),
            provider=provider,
        )
    with pytest.raises(ValueError, match="unsafe or unsupported"):
        _request(relative_path="../sample_bincompressed.sas7bdat").validate()
    directory = tmp_path / "directory.sas7bdat"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        read_sas7bdat(
            _request(relative_path=directory.name),
            authorized_root=tmp_path,
            config=_config(provider),
            provider=provider,
        )
    bounded = read_sas7bdat(
        _request(),
        authorized_root=FIXTURE_ROOT,
        config=_config(provider, max_source_bytes=1),
        provider=provider,
    )
    assert bounded.result["state"] == "blocked"
    assert bounded.result["blockers"] == ["source_exceeds_bounded_local_limit"]


def test_distribution_and_request_contracts_are_strict() -> None:
    provider = _provider()
    with pytest.raises(ValueError, match="distribution"):
        read_sas7bdat(
            _request(),
            authorized_root=FIXTURE_ROOT,
            config=ReaderConfig(provider_distribution_digest="0" * 64),
            provider=provider,
        )
    with pytest.raises(TypeError):
        ReaderConfig(  # type: ignore[call-arg]
            provider_distribution_digest="0" * 64, caller_approved=True
        )
    with pytest.raises(ValueError, match="Unsafe SAS reader client_id"):
        _request(client_id="secret-canary").validate()


def test_immutable_publication_replay_mutation_and_isolation(tmp_path: Path) -> None:
    provider = _provider()
    config = _config(provider)
    request = _request()
    execution = read_sas7bdat(
        request, authorized_root=FIXTURE_ROOT, config=config, provider=provider
    )
    evidence_root = tmp_path / "evidence"
    path = publish_reader_result(
        evidence_root,
        request,
        execution,
        authorized_root=FIXTURE_ROOT,
        config=config,
        provider=provider,
    )
    assert (
        publish_reader_result(
            evidence_root,
            request,
            execution,
            authorized_root=FIXTURE_ROOT,
            config=config,
            provider=provider,
        )
        == path
    )
    replay = verify_reader_result(
        path,
        evidence_root=evidence_root,
        request=request,
        authorized_root=FIXTURE_ROOT,
        config=config,
        provider=provider,
    )
    assert replay.result == execution.result
    assert replay.chunks == execution.chunks

    different = _request(workload_id="other-workload")
    with pytest.raises(ValueError, match="path|binding"):
        verify_reader_result(
            path,
            evidence_root=evidence_root,
            request=different,
            authorized_root=FIXTURE_ROOT,
            config=config,
            provider=provider,
        )

    forged = deepcopy(execution)
    forged.result["descriptor"]["observed_row_count"] = 99
    forged.result["content_digest"] = "0" * 64
    with pytest.raises(ValueError, match="digest|reconstruct"):
        publish_reader_result(
            tmp_path / "forged",
            request,
            forged,
            authorized_root=FIXTURE_ROOT,
            config=config,
            provider=provider,
        )

    forged_nested = deepcopy(execution)
    forged_nested.result["descriptor"]["columns"][0]["caller_approved"] = True
    forged_nested.result["content_digest"] = digest_value(
        {**forged_nested.result, "content_digest": ""}
    )
    with pytest.raises(ValueError, match="descriptor"):
        publish_reader_result(
            tmp_path / "forged-nested",
            request,
            forged_nested,
            authorized_root=FIXTURE_ROOT,
            config=config,
            provider=provider,
        )

    tampered = deepcopy(execution.result)
    tampered["descriptor"]["observed_row_count"] = 99
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="content digest"):
        verify_reader_result(
            path,
            evidence_root=evidence_root,
            request=request,
            authorized_root=FIXTURE_ROOT,
            config=config,
            provider=provider,
        )
