from __future__ import annotations

import os
from pathlib import Path

import pytest

from smf.conversion.manifest import publish_bytes, publish_json

PAYLOAD = {"binding": "canonical", "generated": False}


def test_shared_publisher_rejects_symlinked_output_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "output"
    root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink|non-directory"):
        publish_json(root / "evidence.json", PAYLOAD, "evidence", root=root)
    assert not (outside / "evidence.json").exists()


@pytest.mark.parametrize("component_kind", ["symlink", "file"])
def test_shared_publisher_rejects_unsafe_intermediate_component(
    tmp_path: Path, component_kind: str
) -> None:
    root = tmp_path / "output"
    root.mkdir()
    intermediate = root / "runs"
    if component_kind == "symlink":
        outside = tmp_path / "outside"
        outside.mkdir()
        intermediate.symlink_to(outside, target_is_directory=True)
    else:
        intermediate.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError, match="symlink|non-directory"):
        publish_json(intermediate / "run-1" / "evidence.json", PAYLOAD, "evidence", root=root)


@pytest.mark.parametrize(
    "filename,label",
    [
        ("sas-semantics.evidence.json", "canonical evidence"),
        ("temporal-mappings.json", "temporal mappings"),
        ("value-mappings.json", "value mappings"),
        ("conversion.telemetry.json", "telemetry"),
    ],
)
def test_shared_publisher_rejects_same_byte_symlinked_targets(
    tmp_path: Path, filename: str, label: str
) -> None:
    root = tmp_path / "output"
    target = root / filename
    canonical = publish_json(target, PAYLOAD, label, root=root).read_bytes()
    outside = tmp_path / f"outside-{filename}"
    outside.write_bytes(canonical)
    target.unlink()
    target.symlink_to(outside)

    with pytest.raises(ValueError, match="symlink|regular file"):
        publish_json(target, PAYLOAD, label, root=root)


def test_shared_publisher_rejects_non_regular_target_and_traversal(tmp_path: Path) -> None:
    root = tmp_path / "output"
    target = root / "evidence.json"
    target.mkdir(parents=True)
    with pytest.raises(ValueError, match="regular file"):
        publish_json(target, PAYLOAD, "evidence", root=root)

    with pytest.raises(ValueError, match="traversal"):
        publish_json(root / ".." / "escaped.json", PAYLOAD, "evidence", root=root)


def test_shared_publisher_allows_only_same_byte_in_root_replay(tmp_path: Path) -> None:
    root = tmp_path / "output"
    target = root / "mapping.json"
    first = publish_json(target, PAYLOAD, "mapping", root=root)

    assert publish_json(target, PAYLOAD, "mapping", root=root) == first
    with pytest.raises(FileExistsError, match="different bytes"):
        publish_json(target, {**PAYLOAD, "generated": True}, "mapping", root=root)


@pytest.mark.parametrize(
    "filename",
    [
        "sas-semantics.evidence.json",
        "conversion.telemetry.json",
        "temporal-mappings.json",
        "conversion.manifest.json",
        "generated.py",
    ],
)
def test_shared_publisher_parent_swap_never_writes_to_attacker_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    root = tmp_path / "output"
    parent = root / "runs" / "run-1"
    displaced = tmp_path / "displaced-semantic"
    outside = tmp_path / "outside-semantic"
    outside.mkdir()
    target = parent / filename
    real_link = os.link
    swapped = False

    def swap_parent_then_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(displaced)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr("smf.conversion.manifest.os.link", swap_parent_then_link)

    if filename == "generated.py":
        publish_bytes(target, b"generated = False\n", "generated artifact", root=root)
    else:
        publish_json(target, PAYLOAD, "semantic artifact", root=root)

    assert not (outside / filename).exists()
