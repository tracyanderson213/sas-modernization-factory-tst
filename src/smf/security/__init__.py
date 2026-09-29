"""Portable offline workload-identity and secret-provider contracts."""

from smf.security.admission import request_from_readiness_manifest
from smf.security.ai_admission import (
    classification_digest,
    classification_payload,
    qualify_ai_context,
    sanitize_provider_diagnostic,
)
from smf.security.ai_manifest import load_ai_context_result, write_ai_context_result
from smf.security.ai_models import (
    AIAdmissionOutcome,
    AIAdmissionState,
    AIContextAdmissionResult,
    AIContextRequest,
    QualifiedAIContext,
)
from smf.security.ai_policy import (
    AIContextPolicy,
    ai_digest,
    humana_ai_blockers,
    load_ai_context_policy,
)
from smf.security.ai_transport import guarded_ai_transport
from smf.security.ai_transport_attestation import (
    attestation_digest,
    attestation_payload,
    verify_runtime_evidence,
    verify_submission_evidence,
)
from smf.security.ai_transport_manifest import (
    load_transport_preparation,
    load_transport_result,
    recover_transport_telemetry,
    transport_evidence_dir,
)
from smf.security.ai_transport_models import (
    AITransportCancelled,
    AITransportRequest,
    AITransportResponse,
    AITransportResult,
    AITransportState,
    TransientAIBytes,
)
from smf.security.ai_transport_policy import (
    AIEndpointBinding,
    AITransportPolicy,
    load_ai_endpoint_binding,
    load_ai_transport_policy,
)
from smf.security.attestation import activation_digest, activation_payload, verify_activation
from smf.security.configuration import SecurityConfiguration, load_security_configuration
from smf.security.identity import EntraWorkloadIdentityProvider, WorkloadIdentityProvider
from smf.security.manifest import load_receipt, write_receipt
from smf.security.models import (
    BindingStatus,
    IdentityResponse,
    ReasonCode,
    ResolutionState,
    SecretResolutionReceipt,
    SecretResolutionRequest,
    SecretResponse,
)
from smf.security.secrets import HashiCorpVaultSecretProvider, SecretProvider
from smf.security.threat_model import (
    SecurityThreatModel,
    load_security_threat_model,
    threat_model_digest,
)
from smf.security.transient import TransientMaterial

__all__ = [
    "AIAdmissionOutcome",
    "AIAdmissionState",
    "AIContextAdmissionResult",
    "AIContextPolicy",
    "AIContextRequest",
    "AIEndpointBinding",
    "AITransportCancelled",
    "AITransportPolicy",
    "AITransportRequest",
    "AITransportResponse",
    "AITransportResult",
    "AITransportState",
    "BindingStatus",
    "EntraWorkloadIdentityProvider",
    "HashiCorpVaultSecretProvider",
    "IdentityResponse",
    "QualifiedAIContext",
    "ReasonCode",
    "ResolutionState",
    "SecretProvider",
    "SecretResolutionReceipt",
    "SecretResolutionRequest",
    "SecretResponse",
    "SecurityConfiguration",
    "SecurityThreatModel",
    "TransientMaterial",
    "TransientAIBytes",
    "WorkloadIdentityProvider",
    "activation_digest",
    "activation_payload",
    "attestation_digest",
    "attestation_payload",
    "ai_digest",
    "classification_digest",
    "classification_payload",
    "humana_ai_blockers",
    "load_ai_context_policy",
    "load_ai_context_result",
    "load_ai_endpoint_binding",
    "load_ai_transport_policy",
    "load_transport_result",
    "load_transport_preparation",
    "load_receipt",
    "load_security_configuration",
    "load_security_threat_model",
    "request_from_readiness_manifest",
    "qualify_ai_context",
    "guarded_ai_transport",
    "recover_transport_telemetry",
    "sanitize_provider_diagnostic",
    "verify_activation",
    "verify_runtime_evidence",
    "verify_submission_evidence",
    "write_receipt",
    "write_ai_context_result",
    "transport_evidence_dir",
    "threat_model_digest",
]
