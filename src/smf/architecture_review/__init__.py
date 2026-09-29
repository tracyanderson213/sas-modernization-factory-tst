"""Offline, non-authorizing architecture/security review packets."""

from smf.architecture_review.engine import assemble_packet
from smf.architecture_review.manifest import load_packet, write_packet
from smf.architecture_review.models import ArchitectureReviewRequest


def require_execution_authority(_: object) -> None:
    """Reject review packets at execution admission; consume signed HENV-01 evidence directly."""

    raise ValueError(
        "Architecture review packets are non-authorizing; verify signed HENV-01 activation evidence"
    )


__all__ = [
    "ArchitectureReviewRequest",
    "assemble_packet",
    "load_packet",
    "require_execution_authority",
    "write_packet",
]
