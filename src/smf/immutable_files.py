"""Descriptor-relative helpers for immutable, root-confined file publication."""

from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any


def _absolute_lexical(path: Path, label: str) -> Path:
    if ".." in path.parts:
        raise ValueError(f"Immutable {label} contains traversal")
    return Path(os.path.abspath(os.fspath(path)))


def _relative_target(root: Path, path: Path, label: str) -> tuple[Path, Path]:
    absolute_root = _absolute_lexical(root, "authorized root")
    absolute_path = _absolute_lexical(path, label)
    try:
        relative = absolute_path.relative_to(absolute_root)
    except ValueError as exc:
        raise ValueError(f"Immutable {label} escapes the authorized root") from exc
    if not relative.parts:
        raise ValueError(f"Immutable {label} target must be a file under the authorized root")
    return absolute_root, relative


def _open_directory(parent_fd: int, component: str, *, create: bool, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        with suppress(FileExistsError):
            os.mkdir(component, mode=0o700, dir_fd=parent_fd)
        try:
            return os.open(component, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError(
                f"Immutable {label} contains a symlink or non-directory component"
            ) from exc
    except OSError as exc:
        raise ValueError(
            f"Immutable {label} contains a symlink or non-directory component"
        ) from exc


@contextmanager
def _parent_descriptor(
    root: Path, path: Path, label: str, *, create: bool
) -> Iterator[tuple[int, str]]:
    absolute_root, relative = _relative_target(root, path, label)
    descriptor = os.open(absolute_root.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in (*absolute_root.parts[1:], *relative.parts[:-1]):
            replacement = _open_directory(descriptor, component, create=create, label=label)
            os.close(descriptor)
            descriptor = replacement
        yield descriptor, relative.name
    finally:
        os.close(descriptor)


def ensure_directory(path: Path, *, root: Path) -> Path:
    sentinel = path / ".directory-boundary"
    with _parent_descriptor(root, sentinel, "output directory", create=True):
        pass
    return path


def _open_regular(parent_fd: int, name: str, label: str) -> int:
    try:
        mode = os.stat(name, dir_fd=parent_fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        raise
    if not stat.S_ISREG(mode):
        raise ValueError(f"Immutable {label} is symlinked or not a regular file")
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(f"Immutable {label} is symlinked or not a regular file") from exc
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"Immutable {label} is not a regular file")
    return descriptor


def read_published_bytes(path: Path, *, root: Path, label: str) -> bytes:
    with _parent_descriptor(root, path, label, create=False) as (parent_fd, name):
        descriptor = _open_regular(parent_fd, name, label)
        with os.fdopen(descriptor, "rb") as handle:
            return handle.read()


def read_published_json(path: Path, *, root: Path, label: str) -> Any:
    try:
        return json.loads(read_published_bytes(path, root=root, label=label))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Immutable {label} is invalid JSON") from exc


def published_file_exists(path: Path, *, root: Path, label: str) -> bool:
    try:
        with _parent_descriptor(root, path, label, create=False) as (parent_fd, name):
            descriptor = _open_regular(parent_fd, name, label)
            os.close(descriptor)
    except FileNotFoundError:
        return False
    return True


@contextmanager
def open_lock_file(path: Path, *, root: Path) -> Iterator[int]:
    with _parent_descriptor(root, path, "lock file", create=True) as (parent_fd, name):
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                descriptor = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
            except FileExistsError:
                descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError("Immutable lock file is symlinked or unsafe") from exc
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("Immutable lock file is not a regular file")
        try:
            yield descriptor
        finally:
            os.close(descriptor)


def publish_json(
    path: Path, payload: dict[str, Any], label: str, *, root: Path | None = None
) -> Path:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return publish_bytes(path, encoded, label, root=root)


def publish_bytes(path: Path, payload: bytes, label: str, *, root: Path | None = None) -> Path:
    authorized_root = path.parent if root is None else root
    with _parent_descriptor(authorized_root, path, label, create=True) as (parent_fd, name):
        try:
            existing = _open_regular(parent_fd, name, label)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            with os.fdopen(existing, "rb") as handle:
                if handle.read() == payload:
                    return path
            raise FileExistsError(f"Immutable {label} already exists with different bytes: {path}")
        temporary_name = f".immutable-{secrets.token_hex(16)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(
                    temporary_name,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                collision = _open_regular(parent_fd, name, label)
                with os.fdopen(collision, "rb") as handle:
                    if handle.read() != payload:
                        raise FileExistsError(
                            f"Immutable {label} publication collision: {path}"
                        ) from None
            os.fsync(parent_fd)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_fd)
    return path
