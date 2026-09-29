from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml
from jsonschema import ValidationError

from smf.corpus.isolation import (
    load_private_corpus_manifest,
    load_private_corpus_policy,
    validate_shared_corpus_boundary,
)
from smf.corpus.loader import load_corpus_manifest


def _write_policy(path: Path, storage_root: Path, *, client_id: str = "acme") -> Path:
    payload = {
        "schema_version": 1,
        "client_id": client_id,
        "storage": {
            "root": str(storage_root),
            "repository_storage_prohibited": True,
            "encryption_required": True,
        },
        "access": {
            "allowed_principals": ["engineer@example.test"],
            "cross_client_access_prohibited": True,
            "least_privilege_required": True,
        },
        "retention": {"max_days": 30, "delete_on_engagement_end": True},
        "execution": {
            "workspace_id": "client-workspace",
            "network_boundary": "client-vnet",
            "shared_execution_prohibited": True,
        },
        "promotion": {
            "shared_bytes_prohibited": True,
            "independent_reproduction_required": True,
            "sanitization_review_required": True,
        },
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
    return path


def _write_manifest(root: Path, *, client_id: str = "acme") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    artifact = root / "program.sas"
    artifact.write_text("data work.private; x=1; run;\n")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = {
        "schema_version": 1,
        "scenario_id": "private-case",
        "name": "Private client case",
        "domain": "client",
        "description": "Private evidence used only inside a client boundary.",
        "source": {
            "source_id": f"client:{client_id}",
            "origin": "private-client",
            "license": "client-confidential",
        },
        "artifacts": [{"path": "program.sas", "role": "sas-program", "sha256": digest}],
    }
    path = root / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    return path


def test_shared_loader_rejects_private_client_manifest(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path / "private")
    with pytest.raises(ValueError, match="shared corpus loader"):
        load_corpus_manifest(manifest)


def test_policy_rejects_storage_inside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    policy_path = _write_policy(tmp_path / "policy.yaml", repo / "private")
    with pytest.raises(ValueError, match="outside the repository"):
        load_private_corpus_policy(policy_path, repository_root=repo)


def test_private_loader_requires_authorized_principal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    storage = tmp_path / "client-store"
    policy = load_private_corpus_policy(
        _write_policy(tmp_path / "policy.yaml", storage), repository_root=repo
    )
    manifest = _write_manifest(storage)
    with pytest.raises(PermissionError, match="not authorized"):
        load_private_corpus_manifest(manifest, policy=policy, principal="other@example.test")


def test_private_loader_rejects_manifest_outside_client_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    storage = tmp_path / "client-store"
    policy = load_private_corpus_policy(
        _write_policy(tmp_path / "policy.yaml", storage), repository_root=repo
    )
    manifest = _write_manifest(tmp_path / "other-store")
    with pytest.raises(ValueError, match="configured client storage root"):
        load_private_corpus_manifest(manifest, policy=policy, principal="engineer@example.test")


def test_private_loader_binds_manifest_to_client_id(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    storage = tmp_path / "client-store"
    policy = load_private_corpus_policy(
        _write_policy(tmp_path / "policy.yaml", storage), repository_root=repo
    )
    manifest = _write_manifest(storage, client_id="different-client")
    with pytest.raises(ValueError, match="bind evidence to its client boundary"):
        load_private_corpus_manifest(manifest, policy=policy, principal="engineer@example.test")


def test_private_loader_accepts_client_scoped_external_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    storage = tmp_path / "client-store"
    policy = load_private_corpus_policy(
        _write_policy(tmp_path / "policy.yaml", storage), repository_root=repo
    )
    manifest_path = _write_manifest(storage)
    manifest = load_private_corpus_manifest(
        manifest_path, policy=policy, principal="engineer@example.test"
    )
    assert manifest.source.origin == "private-client"
    assert manifest.source.source_id == "client:acme"
    assert manifest.artifacts[0].path.is_relative_to(storage)


def test_policy_schema_fails_open_controls(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    storage = tmp_path / "client-store"
    policy_path = _write_policy(tmp_path / "policy.yaml", storage)
    payload = yaml.safe_load(policy_path.read_text())
    payload["promotion"]["shared_bytes_prohibited"] = False
    policy_path.write_text(yaml.safe_dump(payload, sort_keys=False))
    with pytest.raises(ValidationError):
        load_private_corpus_policy(policy_path, repository_root=repo)


def test_repository_shared_corpus_boundary_is_clean() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    validate_shared_corpus_boundary(repository_root)


def test_shared_corpus_boundary_rejects_private_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shared = repo / "tests" / "corpus" / "workloads" / "public" / "leak"
    _write_manifest(shared)
    with pytest.raises(ValueError, match="private-client corpus manifest"):
        validate_shared_corpus_boundary(repo)


def test_shared_corpus_boundary_rejects_forbidden_private_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    forbidden = repo / "tests" / "corpus" / "private"
    forbidden.mkdir(parents=True)
    (forbidden / "client.sas").write_text("data work.private; run;\n")
    with pytest.raises(ValueError, match="forbidden private corpus path"):
        validate_shared_corpus_boundary(repo)
