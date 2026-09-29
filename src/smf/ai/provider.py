"""Provider interface and fail-closed result derivation."""

from __future__ import annotations

import hashlib
import re
import time
from abc import ABC, abstractmethod
from datetime import datetime

from smf.ai.models import (
    AIConfigurationState,
    AIEvidenceClass,
    AIFinishReason,
    AIProviderOutcome,
    AIProviderRequest,
    AIProviderResponse,
    AIProviderResult,
    AIProviderState,
    TransientAIProviderBytes,
)
from smf.ai.prerequisites import (
    AIProviderPrerequisites,
    AIProviderVerifierConfiguration,
    verify_provider_prerequisites,
)
from smf.security.ai_admission import contains_protected_data
from smf.security.ai_policy import ai_digest

_CONTROL_INSTRUCTION = re.compile(
    rb"(?i)(?:ignore|override|bypass|disable|change)\s+(?:the\s+)?"
    rb"(?:endpoint|model|policy|approval|access|protected[- ]path|validation)"
)
_MEANINGFUL = re.compile(rb"(?i)(?:data\s+|proc\s+|select\s+|create\s+|spark\.|def\s+|from\s+)")
_SAS_ENTRY = re.compile(
    rb"(?i)(?:^|;)\s*(?:data\s+[A-Za-z_%][A-Za-z0-9_.%]*|"
    rb"proc\s+[A-Za-z][A-Za-z0-9_]*)"
)
_SAS_BLOCK_COMMENT = re.compile(rb"/\*.*?\*/", re.DOTALL)
_SAS_STATEMENT_COMMENT = re.compile(rb"(^|;)\s*\*[^;]*;", re.MULTILINE)
_SAS_QUOTED_TEXT = re.compile(rb"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"")


class AIProviderTimeout(Exception):
    """Provider timed out without a trustworthy response."""


class AIProviderCancelled(Exception):
    """Provider invocation was explicitly cancelled."""


class AIProviderUnsupported(Exception):
    """Provider does not support the requested operation/target."""


class AIProviderFailure(Exception):
    """Provider failed without returning an acceptable response."""


class AIProvider(ABC):
    """No-network provider-neutral invocation boundary."""

    provider_id: str
    evidence_class: AIEvidenceClass

    @abstractmethod
    def invoke(self, request: AIProviderRequest, transient_input: bytes) -> AIProviderResponse:
        """Return untrusted candidate output for validation by the boundary."""


def provider_decision_id(request: AIProviderRequest) -> str:
    return "aip-" + ai_digest({"contract": "smf-ai-provider-v1", "request": request.bindings()})


def provider_input_issue(
    request: AIProviderRequest, transient_input: TransientAIProviderBytes
) -> str | None:
    """Return a safe categorical input defect without retaining source text."""

    input_bytes = transient_input.value
    decoded = input_bytes.decode("utf-8", errors="replace")
    if contains_protected_data(decoded):
        return "protected_data_detected"
    if (
        len(input_bytes) != request.context_byte_count
        or hashlib.sha256(input_bytes).hexdigest() != request.context_digest
    ):
        return "context_binding_mismatch"
    executable = _SAS_BLOCK_COMMENT.sub(b" ", input_bytes)
    executable = _SAS_QUOTED_TEXT.sub(b"''", executable)
    while True:
        without_comments = _SAS_STATEMENT_COMMENT.sub(rb"\1", executable)
        if without_comments == executable:
            break
        executable = without_comments
    if not _SAS_ENTRY.search(executable):
        return "nonconvertible_subject"
    return None


def _result(
    request: AIProviderRequest,
    provider: AIProvider,
    state: AIProviderState,
    blockers: tuple[str, ...],
    evidence_refs: tuple[str, ...],
    *,
    invoked: bool = False,
    elapsed_ms: int = 0,
    response: AIProviderResponse | None = None,
) -> AIProviderResult:
    return AIProviderResult(
        schema_version="1.0",
        decision_id=provider_decision_id(request),
        request=request.bindings(),
        state=state,
        blocker_codes=blockers,
        evidence_refs=evidence_refs,
        evidence_class=provider.evidence_class,
        response_digest=(hashlib.sha256(response.content).hexdigest() if response else None),
        response_byte_count=(len(response.content) if response else None),
        finish_reason=(response.finish_reason if response else None),
        input_tokens=(response.input_tokens if response else 0),
        output_tokens=(response.output_tokens if response else 0),
        elapsed_ms=max(0, elapsed_ms),
        provider_invoked=invoked,
    )


def invoke_ai_provider(
    request: AIProviderRequest,
    transient_input: TransientAIProviderBytes,
    provider: AIProvider,
    *,
    prerequisites: AIProviderPrerequisites | None = None,
    verifier_configuration: AIProviderVerifierConfiguration | None = None,
    now: datetime | None = None,
    _expected_prerequisite_snapshots: tuple[bytes, ...] | None = None,
) -> AIProviderOutcome:
    """Fail closed when a request caller also supplies its trust roots.

    A future authenticated composition layer may call the internal verified
    core.  AIP-01 deliberately exposes no public trust-root selection path.
    """

    if verifier_configuration is not None:
        transient_input.clear()
        return AIProviderOutcome(
            _result(
                request,
                provider,
                AIProviderState.BLOCKED_MISSING,
                ("governed_verifier_unavailable",),
                (),
            ),
            None,
        )
    return _invoke_ai_provider(
        request,
        transient_input,
        provider,
        prerequisites=prerequisites,
        now=now,
        _expected_prerequisite_snapshots=_expected_prerequisite_snapshots,
    )


def _invoke_ai_provider(
    request: AIProviderRequest,
    transient_input: TransientAIProviderBytes,
    provider: AIProvider,
    *,
    prerequisites: AIProviderPrerequisites | None = None,
    verifier_configuration: AIProviderVerifierConfiguration | None = None,
    now: datetime | None = None,
    _expected_prerequisite_snapshots: tuple[bytes, ...] | None = None,
) -> AIProviderOutcome:
    """Invoke once after exact binding checks; never infer downstream success."""

    evidence_refs = (
        request.sec02_result_ref,
        request.prompt_policy_ref,
        request.prompt_template_ref,
        request.transport_policy_ref,
        request.configuration_ref,
        request.retention_policy_ref,
        request.access_policy_ref,
    )
    config_states = {
        AIConfigurationState.MISSING: (AIProviderState.BLOCKED_MISSING, "configuration_missing"),
        AIConfigurationState.PENDING: (AIProviderState.BLOCKED_PENDING, "configuration_pending"),
        AIConfigurationState.DENIED: (AIProviderState.DENIED, "configuration_denied"),
    }
    if request.configuration_state in config_states:
        state, blocker = config_states[request.configuration_state]
        transient_input.clear()
        return AIProviderOutcome(_result(request, provider, state, (blocker,), evidence_refs), None)
    if provider.provider_id != request.provider_id:
        transient_input.clear()
        return AIProviderOutcome(
            _result(
                request,
                provider,
                AIProviderState.INVALID_BINDING,
                ("provider_binding_mismatch",),
                evidence_refs,
            ),
            None,
        )
    if provider.evidence_class is AIEvidenceClass.OPERATIONAL_VERIFIED:
        transient_input.clear()
        return AIProviderOutcome(
            _result(
                request,
                provider,
                AIProviderState.BLOCKED_MISSING,
                ("operational_provider_verifier_unavailable",),
                evidence_refs,
            ),
            None,
        )
    input_issue = provider_input_issue(request, transient_input)
    if input_issue is not None:
        transient_input.clear()
        return AIProviderOutcome(
            _result(
                request,
                provider,
                (
                    AIProviderState.INVALID_BINDING
                    if input_issue == "context_binding_mismatch"
                    else AIProviderState.FAILED
                ),
                (input_issue,),
                evidence_refs,
            ),
            None,
        )
    prerequisite_check = verify_provider_prerequisites(
        request,
        prerequisites,
        verifier_configuration=verifier_configuration,
        now=now,
    )
    if prerequisite_check.state is not None:
        transient_input.clear()
        return AIProviderOutcome(
            _result(
                request,
                provider,
                prerequisite_check.state,
                (str(prerequisite_check.blocker_code),),
                prerequisite_check.evidence_refs,
            ),
            None,
        )
    if (
        _expected_prerequisite_snapshots is not None
        and prerequisite_check.snapshots != _expected_prerequisite_snapshots
    ):
        transient_input.clear()
        return AIProviderOutcome(
            _result(
                request,
                provider,
                AIProviderState.INVALID_BINDING,
                ("trusted_prerequisite_changed_before_invocation",),
                prerequisite_check.evidence_refs,
            ),
            None,
        )
    input_bytes = transient_input.value
    started = time.monotonic_ns()
    try:
        response = provider.invoke(request, input_bytes)
        elapsed = (time.monotonic_ns() - started) // 1_000_000
        if not isinstance(response, AIProviderResponse):
            raise AIProviderFailure("malformed response")
        if response.finish_reason is not AIFinishReason.STOP:
            state = (
                AIProviderState.UNSUPPORTED
                if response.finish_reason is AIFinishReason.REFUSAL
                else AIProviderState.FAILED
            )
            return AIProviderOutcome(
                _result(
                    request,
                    provider,
                    state,
                    (f"finish_reason_{response.finish_reason.value}",),
                    evidence_refs,
                    invoked=True,
                    elapsed_ms=elapsed,
                ),
                None,
            )
        stripped = response.content.strip()
        if (
            not stripped
            or not _MEANINGFUL.search(stripped)
            or _CONTROL_INSTRUCTION.search(stripped)
            or contains_protected_data(stripped.decode("utf-8", errors="replace"))
        ):
            return AIProviderOutcome(
                _result(
                    request,
                    provider,
                    AIProviderState.FAILED,
                    ("unsafe_or_nonmeaningful_response",),
                    evidence_refs,
                    invoked=True,
                    elapsed_ms=elapsed,
                ),
                None,
            )
        canonical = AIProviderResponse(
            content=bytes(stripped),
            finish_reason=response.finish_reason,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        output = TransientAIProviderBytes(canonical.content)
        return AIProviderOutcome(
            _result(
                request,
                provider,
                AIProviderState.SUCCEEDED,
                (),
                evidence_refs,
                invoked=True,
                elapsed_ms=elapsed,
                response=canonical,
            ),
            output,
        )
    except AIProviderTimeout:
        state, blocker = AIProviderState.TIMED_OUT, "provider_timeout"
    except AIProviderCancelled:
        state, blocker = AIProviderState.CANCELLED, "provider_cancelled"
    except AIProviderUnsupported:
        state, blocker = AIProviderState.UNSUPPORTED, "provider_unsupported"
    except (AIProviderFailure, ValueError, TypeError):
        state, blocker = AIProviderState.FAILED, "provider_failure"
    except Exception:
        # Provider SDK failures are untrusted diagnostics.  Preserve only a safe,
        # categorical terminal result while allowing process-control BaseException
        # subclasses to retain their normal semantics.
        state, blocker = AIProviderState.FAILED, "provider_failure"
    finally:
        transient_input.clear()
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    return AIProviderOutcome(
        _result(
            request,
            provider,
            state,
            (blocker,),
            evidence_refs,
            invoked=True,
            elapsed_ms=elapsed,
        ),
        None,
    )
