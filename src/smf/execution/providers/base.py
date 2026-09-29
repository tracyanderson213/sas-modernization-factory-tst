from __future__ import annotations

from abc import ABC, abstractmethod

from smf.execution.models import ExecutionRequest, ExecutionResult


class ExecutionProvider(ABC):
    name: str

    @abstractmethod
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a generated artifact in a validation environment."""
