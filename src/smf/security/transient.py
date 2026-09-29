"""Non-serializable, zeroing containers for credential material."""

from __future__ import annotations

from typing import Any


class TransientMaterial:
    __slots__ = ("_buffer", "_closed")

    def __init__(self, value: bytes | bytearray) -> None:
        if not value:
            raise ValueError("Transient material cannot be empty")
        self._buffer = bytearray(value)
        self._closed = False

    def __enter__(self) -> TransientMaterial:
        if self._closed:
            raise RuntimeError("Transient material is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def view(self) -> memoryview:
        if self._closed:
            raise RuntimeError("Transient material is closed")
        return memoryview(self._buffer).toreadonly()

    def close(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def __repr__(self) -> str:
        return "TransientMaterial(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> Any:
        raise TypeError("Transient material cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("Transient material cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("Transient material cannot be serialized")
