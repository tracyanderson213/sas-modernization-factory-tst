"""Execution validation for SAS Modernization Factory."""

from smf.execution.databricks_auth import (
    authenticate_databricks,
    build_databricks_authentication_request,
    request_from_governed_deployment,
)
from smf.execution.databricks_auth_models import (
    DatabricksAuthenticationRequest,
    DatabricksAuthenticationResult,
)
from smf.execution.databricks_compute import (
    build_compute_selection_request,
    select_validation_compute,
    verify_compute_admission,
    verify_compute_result,
    verify_result_availability,
)
from smf.execution.databricks_compute_models import (
    ComputeSelectionRequest,
    ComputeSelectionResult,
    ValidationComputePolicy,
)
from smf.execution.databricks_remote import (
    CurrentRemoteEvidence,
    RemoteExecutionRequest,
    SyntheticScenario,
    exercise_synthetic_transport,
    prepare_remote_execution_plan,
    publish_remote_execution_plan,
    verify_remote_execution_plan,
)
from smf.execution.engine import execute_validation
from smf.execution.models import ExecutionRequest, ExecutionResult
from smf.execution.runtime_evidence import (
    CurrentExecutionPlanEvidence,
    OutputReference,
    RuntimeEvidenceRequest,
    SyntheticRuntimeObservation,
    TaskObservation,
    prepare_runtime_evidence,
    publish_runtime_evidence,
    verify_runtime_evidence,
)

__all__ = [
    "DatabricksAuthenticationRequest",
    "DatabricksAuthenticationResult",
    "ComputeSelectionRequest",
    "ComputeSelectionResult",
    "CurrentRemoteEvidence",
    "CurrentExecutionPlanEvidence",
    "ExecutionRequest",
    "ExecutionResult",
    "RemoteExecutionRequest",
    "RuntimeEvidenceRequest",
    "OutputReference",
    "SyntheticScenario",
    "SyntheticRuntimeObservation",
    "TaskObservation",
    "authenticate_databricks",
    "build_compute_selection_request",
    "build_databricks_authentication_request",
    "execute_validation",
    "exercise_synthetic_transport",
    "prepare_remote_execution_plan",
    "prepare_runtime_evidence",
    "publish_remote_execution_plan",
    "publish_runtime_evidence",
    "request_from_governed_deployment",
    "select_validation_compute",
    "ValidationComputePolicy",
    "verify_compute_admission",
    "verify_compute_result",
    "verify_result_availability",
    "verify_remote_execution_plan",
    "verify_runtime_evidence",
]
