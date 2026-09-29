from __future__ import annotations

from smf.execution.models import ExecutionRequest, ExecutionResult
from smf.execution.providers.base import ExecutionProvider


class DatabricksExecutionProvider(ExecutionProvider):
    """Databricks execution provider boundary.

    V2 establishes credential/configuration validation and a durable provider
    contract. Remote job submission is intentionally feature-gated until a
    validation workspace, compute policy, catalog, and write boundaries are
    explicitly configured.
    """

    name = "databricks"

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        # DBX-02 deliberately does not consume environment variables or SDK default
        # profiles. Authentication is a separate governed evidence boundary and no
        # remote submission adapter exists yet.
        return ExecutionResult(
            source_file=str(request.source_file),
            generated_file=str(request.generated_file),
            target=request.target,
            provider=self.name,
            status="blocked",
            duration_seconds=0.0,
            stderr=(
                "Governed Databricks authentication evidence and remote submission are required."
            ),
            warnings=[
                "Environment credentials and personal access tokens are never accepted.",
                "Authentication qualification does not prove execution or parity.",
            ],
            evidence={
                "remote_submission_enabled": False,
                "reason_code": "remote_submission_disabled",
                "authentication_required": True,
                "compute_policy_required": True,
                "allow_writes": request.allow_writes,
            },
        )
