"""Qualified, bounded wrapper around pyreadstat/ReadStat.

This module deliberately contains no SAS parser.  It admits a root-confined file descriptor,
executes the governed pyreadstat provider, and returns transient rows plus a durable evidence
envelope that contains only schema/metadata and chunk digests.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, datetime, time
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast

from smf.security.ai_admission import contains_protected_data, sanitize_provider_diagnostic
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

PYREADSTAT_VERSION = "1.3.6"
PYREADSTAT_RELEASE_REVISION = "ae4bfa5d84ed1ceaf847ab242118da730a4084ec"
PYREADSTAT_EVALUATED_REVISION = "12cc1495d468ae8a170c57cce7557c147b972eac"
# Backward-compatible name for the evaluated upstream head, not the wheel's release source.
PYREADSTAT_REVISION = PYREADSTAT_EVALUATED_REVISION
READSTAT_REVISION = "5850fb57dfc0301f62c745c547763610e5a6c347"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReaderBackend(Protocol):
    """Narrow provider surface used by the SMF adapter and test doubles."""

    __version__: str

    def read_sas7bdat(self, path: str, **kwargs: Any) -> tuple[Any, Any]: ...


@dataclass(frozen=True)
class ReaderRequest:
    client_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    relative_path: str
    source_sha256: str
    source_byte_count: int

    def validate(self) -> None:
        for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id"):
            value = cast(str, getattr(self, field))
            if (
                not _SAFE_ID.fullmatch(value)
                or value in {".", ".."}
                or contains_protected_data(value)
            ):
                raise ValueError(f"Unsafe SAS reader {field}")
        relative = PurePosixPath(self.relative_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.suffix.lower() != ".sas7bdat"
            or contains_protected_data(self.relative_path)
        ):
            raise ValueError("SAS reader source path is unsafe or unsupported")
        if not _SHA256.fullmatch(self.source_sha256):
            raise ValueError("SAS reader source digest is invalid")
        if self.source_byte_count <= 0:
            raise ValueError("SAS reader source byte count must be positive")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class ReaderConfig:
    provider_distribution_digest: str
    chunk_rows: int = 10_000
    max_source_bytes: int = 512 * 1024 * 1024
    max_rows: int = 5_000_000
    encoding: str | None = None

    def validate(self) -> None:
        if not _SHA256.fullmatch(self.provider_distribution_digest):
            raise ValueError("SAS reader provider distribution digest is invalid")
        if not 1 <= self.chunk_rows <= 1_000_000:
            raise ValueError("SAS reader chunk_rows is outside the bounded local range")
        if not 1 <= self.max_source_bytes <= 8 * 1024 * 1024 * 1024:
            raise ValueError("SAS reader max_source_bytes is outside the bounded local range")
        if not 1 <= self.max_rows <= 50_000_000:
            raise ValueError("SAS reader max_rows is outside the bounded local range")
        if self.encoding is not None and (
            not self.encoding.isascii() or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", self.encoding)
        ):
            raise ValueError("SAS reader encoding is invalid")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class ReaderExecution:
    """One provider result and transient, ordered row chunks.

    Rows are intentionally absent from ``result`` so immutable evidence cannot accidentally become
    a customer-data store.  Each durable chunk record binds its transient values by SHA-256.
    """

    result: dict[str, Any]
    chunks: tuple[tuple[tuple[Any, ...], ...], ...]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def provider_distribution_digest(distribution: str = "pyreadstat") -> str:
    """Fingerprint the installed distribution RECORD, not a caller-authored version label."""

    dist = importlib.metadata.distribution(distribution)
    record = dist.read_text("RECORD")
    if not record:
        raise ValueError("pyreadstat distribution RECORD is unavailable")
    return hashlib.sha256(record.encode()).hexdigest()


def _runtime_identity(backend: ReaderBackend, *, qualified_module: bool) -> dict[str, Any]:
    installed = importlib.metadata.version("pyreadstat")
    if installed != PYREADSTAT_VERSION or backend.__version__ != PYREADSTAT_VERSION:
        raise ValueError("Unsupported pyreadstat version")
    dependencies = []
    numpy_version = "2.5.3" if sys.version_info >= (3, 12) else "2.4.6"
    for name, required in (("narwhals", "2.26.0"), ("numpy", numpy_version)):
        observed = importlib.metadata.version(name)
        if observed != required:
            raise ValueError(f"Unsupported pyreadstat runtime dependency {name}")
        dependencies.append(
            {
                "distribution": name,
                "version": observed,
                "distribution_record_sha256": provider_distribution_digest(name),
            }
        )
    return {
        "provider": "pyreadstat",
        "provider_version": installed,
        "provider_release_revision": PYREADSTAT_RELEASE_REVISION,
        "evaluated_upstream_revision": PYREADSTAT_EVALUATED_REVISION,
        "provider_authority": (
            "qualified_installed_module" if qualified_module else "synthetic_test_double"
        ),
        "transitive_parser": "ReadStat",
        "transitive_revision": READSTAT_REVISION,
        "distribution_record_sha256": provider_distribution_digest(),
        "runtime_dependencies": dependencies,
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "byte_order": sys.byteorder,
    }


def _open_confined(root: Path, relative_name: str) -> int:
    relative = PurePosixPath(relative_name)
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    if root.is_symlink() or not lexical_root.is_dir() or lexical_root.resolve() != lexical_root:
        raise ValueError("SAS reader authorized root is missing or unsafe")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    descriptor = os.open(lexical_root, directory_flags)
    try:
        for part in relative.parts[:-1]:
            replacement = os.open(part, directory_flags, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(replacement).st_mode):
                os.close(replacement)
                raise ValueError("SAS reader path contains a non-directory component")
            os.close(descriptor)
            descriptor = replacement
        file_flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        source = os.open(relative.name, file_flags, dir_fd=descriptor)
        if not stat.S_ISREG(os.fstat(source).st_mode):
            os.close(source)
            raise ValueError("SAS reader source is not a regular file")
        return source
    except OSError as exc:
        raise ValueError("SAS reader source is missing, symlinked, or unsafe") from exc
    finally:
        os.close(descriptor)


@contextmanager
def _private_provider_path(descriptor: int, expected_digest: str) -> Iterator[str]:
    """Stage verified bytes privately for providers whose native API requires a pathname."""

    with tempfile.TemporaryDirectory(prefix="smf-sas-reader-") as directory:
        path = Path(directory) / "source.sas7bdat"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        target = os.open(path, flags, 0o600)
        try:
            offset = 0
            while True:
                chunk = os.pread(descriptor, 1024 * 1024, offset)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(target, view)
                    view = view[written:]
                offset += len(chunk)
            os.fsync(target)
        finally:
            os.close(target)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
            raise ValueError("Private SAS reader staging copy failed identity verification")
        yield os.fspath(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
            raise ValueError("Private SAS reader staging bytes changed during provider execution")


def _file_digest(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _identity_tuple(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _normalize(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, datetime):
        return {"logical_type": "datetime", "value": value.isoformat(timespec="microseconds")}
    if isinstance(value, date):
        return {"logical_type": "date", "value": value.isoformat()}
    if isinstance(value, time):
        return {"logical_type": "time", "value": value.isoformat(timespec="microseconds")}
    if isinstance(value, bool | str | int):
        return value
    if isinstance(value, float):
        # Raw pyreadstat output uses NaN for ordinary SAS numeric missing values.
        if math.isnan(value):
            return None
        if math.isinf(value):
            raise ValueError("SAS reader produced a non-finite numeric value")
        return value
    item = getattr(value, "item", None)
    if callable(item):
        return _normalize(item())
    raise ValueError(f"SAS reader produced unsupported value type {type(value).__name__}")


def _column_observed_type(values: Sequence[Any]) -> str:
    names = sorted({type(value).__name__ for value in values if value is not None})
    return "null" if not names else "|".join(names)


def _safe_metadata(value: Any, label: str) -> Any:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, str) and not contains_protected_data(value):
        return value
    raise ValueError(f"SAS reader {label} contains protected or unsupported metadata")


def _descriptor(metadata: Any, columns: Mapping[str, Sequence[Any]]) -> dict[str, Any]:
    names = list(metadata.column_names)
    if names != list(columns):
        raise ValueError("pyreadstat column order differs between metadata and rows")
    described: list[dict[str, Any]] = []
    for position, name in enumerate(names):
        values = columns[name]
        described.append(
            {
                "position": position,
                "name": _safe_metadata(name, "column name"),
                "declared": {
                    "label": _safe_metadata(metadata.column_names_to_labels.get(name), "label"),
                    "format": _safe_metadata(metadata.original_variable_types.get(name), "format"),
                    "informat": _safe_metadata(
                        metadata.original_variable_informats.get(name), "informat"
                    ),
                    "value_label_set": _safe_metadata(
                        metadata.variable_to_label.get(name), "value label set"
                    ),
                    "storage_width": metadata.variable_storage_width.get(name),
                    "nullable": None,
                    "unit": None,
                    "key": None,
                },
                "observed": {
                    "readstat_type": _safe_metadata(
                        metadata.readstat_variable_types.get(name), "ReadStat type"
                    ),
                    "normalized_type": _column_observed_type(values),
                    "null_count": sum(value is None for value in values),
                    "nullable": any(value is None for value in values),
                },
            }
        )
    return {
        "file_format": _safe_metadata(metadata.file_format, "file format"),
        "file_encoding": _safe_metadata(metadata.file_encoding, "file encoding"),
        "table_name": _safe_metadata(metadata.table_name, "table name"),
        "file_label": _safe_metadata(metadata.file_label, "file label"),
        "declared_row_count": metadata.number_rows,
        "observed_row_count": len(next(iter(columns.values()), [])),
        "declared_column_count": metadata.number_columns,
        "observed_column_count": len(columns),
        "declared_keys": [],
        "key_authority": "unavailable_not_inferred",
        "creation_time": metadata.creation_time.isoformat() if metadata.creation_time else None,
        "modification_time": (
            metadata.modification_time.isoformat() if metadata.modification_time else None
        ),
        "columns": described,
    }


def _rows(columns: Mapping[str, Sequence[Any]]) -> tuple[tuple[Any, ...], ...]:
    names = list(columns)
    counts = {len(columns[name]) for name in names}
    if len(counts) > 1:
        raise ValueError("pyreadstat returned columns with inconsistent row counts")
    count = counts.pop() if counts else 0
    return tuple(tuple(columns[name][index] for name in names) for index in range(count))


def _normalized_columns(
    columns: Mapping[str, Sequence[Any]],
) -> dict[str, tuple[Any, ...]]:
    return {name: tuple(_normalize(value) for value in values) for name, values in columns.items()}


def _chunk_rows(
    rows: tuple[tuple[Any, ...], ...], chunk_rows: int
) -> tuple[tuple[tuple[Any, ...], ...], ...]:
    return tuple(rows[index : index + chunk_rows] for index in range(0, len(rows), chunk_rows))


def _outcome(
    request: ReaderRequest,
    config: ReaderConfig,
    runtime: dict[str, Any],
    source: dict[str, Any],
    *,
    state: str,
    descriptor: dict[str, Any] | None,
    chunks: tuple[tuple[tuple[Any, ...], ...], ...],
    blockers: list[str],
    diagnostic: str | None = None,
) -> ReaderExecution:
    chunk_evidence = [
        {
            "index": index,
            "row_offset": sum(len(item) for item in chunks[:index]),
            "row_count": len(chunk),
            "content_sha256": hashlib.sha256(_canonical(chunk)).hexdigest(),
        }
        for index, chunk in enumerate(chunks)
    ]
    request_binding = request.binding()
    request_binding["relative_path"] = hashlib.sha256(
        request.relative_path.encode("utf-8")
    ).hexdigest()
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": stable_id(
            "SASREAD",
            {
                "request": request_binding,
                "config": config.binding(),
                "runtime": runtime,
                "source": source,
            },
        ),
        "request": request_binding,
        "request_digest": digest_value(request.binding()),
        "config": config.binding(),
        "config_digest": digest_value(config.binding()),
        "runtime": runtime,
        "runtime_digest": digest_value(runtime),
        "source": source,
        "state": state,
        "blockers": sorted(set(blockers)),
        "diagnostic": diagnostic,
        "descriptor": descriptor,
        "chunks": chunk_evidence,
        "claims": {
            "migration_complete": False,
            "semantic_parity": False,
            "humana_validated": False,
            "databricks_validated": False,
            "production_ready": False,
        },
        "content_digest": "",
    }
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    return ReaderExecution(result=payload, chunks=chunks)


class PyreadstatProvider:
    """Exact-version provider wrapper.  Dependency loading is explicit and fail closed."""

    def __init__(self, backend: ReaderBackend | None = None) -> None:
        try:
            imported = cast(ReaderBackend, __import__("pyreadstat"))
        except ImportError as exc:
            raise ValueError("pyreadstat provider is unavailable") from exc
        if backend is None:
            backend = imported
        self.backend = backend
        self._qualified_module = backend is imported

    def runtime_identity(self) -> dict[str, Any]:
        return _runtime_identity(self.backend, qualified_module=self._qualified_module)


def read_sas7bdat(
    request: ReaderRequest,
    *,
    authorized_root: Path,
    config: ReaderConfig,
    provider: PyreadstatProvider | None = None,
) -> ReaderExecution:
    """Read one exact SAS7BDAT snapshot through pyreadstat with bounded local semantics."""

    request.validate()
    config.validate()
    active = provider or PyreadstatProvider()
    runtime = active.runtime_identity()
    if runtime["distribution_record_sha256"] != config.provider_distribution_digest:
        raise ValueError("Installed pyreadstat distribution does not match governed configuration")
    descriptor = _open_confined(authorized_root, request.relative_path)
    try:
        before = os.fstat(descriptor)
        digest_before = _file_digest(descriptor)
        source = {
            "sha256": digest_before,
            "byte_count": before.st_size,
            "snapshot_verified": digest_before == request.source_sha256
            and before.st_size == request.source_byte_count,
        }
        if not source["snapshot_verified"]:
            return _outcome(
                request,
                config,
                runtime,
                source,
                state="failed",
                descriptor=None,
                chunks=(),
                blockers=["source_snapshot_mismatch"],
            )
        if before.st_size > config.max_source_bytes:
            return _outcome(
                request,
                config,
                runtime,
                source,
                state="blocked",
                descriptor=None,
                chunks=(),
                blockers=["source_exceeds_bounded_local_limit"],
            )
        try:
            kwargs: dict[str, Any] = {
                "output_format": "dict",
                # Preserve underlying SAS numerics.  Semantic conversion is BASE-02 scope and
                # pre-1960 values (the qualified fixture includes year 1583) can overflow target
                # timestamp runtimes before an approved mapping policy exists.
                "disable_datetime_conversion": True,
                # Preserve any special-missing metadata so unqualified semantics can block.
                "user_missing": True,
            }
            if config.encoding is not None:
                kwargs["encoding"] = config.encoding
            with _private_provider_path(descriptor, digest_before) as provider_path:
                raw_columns, metadata = active.backend.read_sas7bdat(provider_path, **kwargs)
            if not isinstance(raw_columns, Mapping):
                raise ValueError("pyreadstat returned an unsupported row container")
            if metadata.missing_user_values or metadata.missing_ranges:
                return _outcome(
                    request,
                    config,
                    runtime,
                    source,
                    state="unsupported",
                    descriptor=None,
                    chunks=(),
                    blockers=["special_missing_values_require_semantic_qualification"],
                )
            columns = _normalized_columns(cast(Mapping[str, Sequence[Any]], raw_columns))
            rows = _rows(columns)
            if len(rows) > config.max_rows:
                return _outcome(
                    request,
                    config,
                    runtime,
                    source,
                    state="blocked",
                    descriptor=None,
                    chunks=(),
                    blockers=["row_count_exceeds_bounded_local_limit"],
                )
            dataset_descriptor = _descriptor(metadata, columns)
            if dataset_descriptor["declared_row_count"] not in {None, len(rows)}:
                raise ValueError("SAS declared row count conflicts with provider observations")
            if dataset_descriptor["declared_column_count"] != len(columns):
                raise ValueError("SAS declared column count conflicts with provider observations")
            chunks = _chunk_rows(rows, config.chunk_rows)
        except Exception as exc:
            message = str(exc).lower()
            blocker = (
                "encrypted_or_password_protected_unsupported"
                if any(token in message for token in ("encrypt", "password", "protected"))
                else "corrupt_encoding_or_provider_unsupported"
            )
            return _outcome(
                request,
                config,
                runtime,
                source,
                state="unsupported",
                descriptor=None,
                chunks=(),
                blockers=[blocker],
                diagnostic=sanitize_provider_diagnostic(exc),
            )
        after = os.fstat(descriptor)
        digest_after = _file_digest(descriptor)
        if _identity_tuple(before) != _identity_tuple(after) or digest_before != digest_after:
            return _outcome(
                request,
                config,
                runtime,
                source,
                state="failed",
                descriptor=None,
                chunks=(),
                blockers=["source_mutated_during_read"],
            )
        if runtime["provider_authority"] != "qualified_installed_module":
            return _outcome(
                request,
                config,
                runtime,
                source,
                state="blocked",
                descriptor=None,
                chunks=(),
                blockers=["synthetic_provider_cannot_authorize_completion"],
            )
        return _outcome(
            request,
            config,
            runtime,
            source,
            state="complete",
            descriptor=dataset_descriptor,
            chunks=chunks,
            blockers=[],
        )
    finally:
        os.close(descriptor)
