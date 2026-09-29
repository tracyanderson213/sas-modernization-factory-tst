"""Discovery acquisition orchestration."""

from pathlib import Path

from smf.discovery.base import DiscoveryRequest
from smf.discovery.content_assessment import (
    SasContentAssessmentDiscoveryProvider,
    is_content_assessment_source,
)
from smf.discovery.filesystem import FilesystemDiscoveryProvider
from smf.discovery.models import DiscoveryResult

_PROVIDER_AUTO = "auto"
_PROVIDER_FILESYSTEM = "filesystem"
_PROVIDER_CONTENT_ASSESSMENT = "sas-content-assessment"
SUPPORTED_PROVIDERS = (
    _PROVIDER_AUTO,
    _PROVIDER_FILESYSTEM,
    _PROVIDER_CONTENT_ASSESSMENT,
)


def discover_source(
    source: Path,
    *,
    provider: str = _PROVIDER_AUTO,
    namespace: str = "default",
    logical_name: str | None = None,
    source_locator: str | None = None,
) -> DiscoveryResult:
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported discovery provider: {provider}")

    resolved = source.expanduser().resolve()
    selected = provider
    if provider == _PROVIDER_AUTO:
        selected = (
            _PROVIDER_CONTENT_ASSESSMENT
            if is_content_assessment_source(resolved)
            else _PROVIDER_FILESYSTEM
        )

    request = DiscoveryRequest(
        source=resolved,
        namespace=namespace,
        logical_name=logical_name,
        source_locator=source_locator,
    )
    if selected == _PROVIDER_CONTENT_ASSESSMENT:
        workloads = SasContentAssessmentDiscoveryProvider().discover(request)
    else:
        workloads = FilesystemDiscoveryProvider().discover(request)

    return DiscoveryResult(
        provider=selected,
        source=str(resolved),
        workloads=workloads,
    )
