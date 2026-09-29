"""Provider boundary for baseline acquisition."""

from __future__ import annotations

from typing import Any, Protocol

from smf.baseline.models import BaselineAcquisitionRequest
from smf.baseline.policy import BaselineAcquisitionPolicy


class BaselineAcquisitionProvider(Protocol):
    def acquire(
        self, request: BaselineAcquisitionRequest, policy: BaselineAcquisitionPolicy
    ) -> dict[str, Any]: ...
