"""Allowlist-only projections of a canonical architecture review packet."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from smf.architecture_review.schema import validate
from smf.readiness.policy import digest_value


def internal_projection(packet: dict[str, Any]) -> dict[str, Any]:
    validate("architecture-review-packet.schema.json", packet)
    projection = {
        "schema_version": "1.0",
        "projection_type": "controlled_internal",
        "canonical_packet_id": packet["packet_id"],
        "canonical_packet_digest": packet["content_digest"],
        "recipient_class": packet["evidence_handling"]["recipient_class"],
        "disclosure_policy_revision": packet["evidence_handling"]["disclosure_policy_revision"],
        "retention_policy_ref": packet["evidence_handling"]["retention_policy_ref"],
        "payload": deepcopy(packet),
        "content_digest": "",
    }
    projection["content_digest"] = digest_value({**projection, "content_digest": ""})
    validate("architecture-review-projection.schema.json", projection)
    return projection


def shared_projection(packet: dict[str, Any]) -> dict[str, Any] | None:
    validate("architecture-review-packet.schema.json", packet)
    handling = packet["evidence_handling"]
    if handling.get("disclosure_decision", {}).get("state") != "verified":
        return None
    safe_packet = {
        "packet_kind": packet["packet_kind"],
        "authority": packet["authority"],
        "assessed_revision": packet["assessed_revision"],
        "identity": deepcopy(packet["identity"]),
        "source": {
            key: packet["source"][key]
            for key in (
                "entry_artifact_id",
                "source_closure_digest",
                "workload_digest",
                "discovery_digest",
            )
        },
        "configuration": {
            key: packet["configuration"][key]
            for key in (
                "configuration_digest",
                "bundle_digest",
                "threat_model_digest",
                "requirements_digest",
            )
        },
        "approval_summary": [
            {
                "requirement_refs": deepcopy(item["requirement_refs"]),
                "decision_state": item["decision_state"],
            }
            for item in packet["approval_requests"]
        ],
        "henv01_state": packet["protected_execution_decision"]["state"],
        "terminal_disposition": packet["terminal_disposition"],
        "lifecycle": deepcopy(packet["lifecycle"]),
    }
    projection = {
        "schema_version": "1.0",
        "projection_type": "shared",
        "canonical_packet_id": packet["packet_id"],
        "canonical_packet_digest": packet["content_digest"],
        "recipient_class": handling["recipient_class"],
        "disclosure_policy_revision": handling["disclosure_policy_revision"],
        "retention_policy_ref": handling["retention_policy_ref"],
        "payload": safe_packet,
        "content_digest": "",
    }
    projection["content_digest"] = digest_value({**projection, "content_digest": ""})
    validate("architecture-review-projection.schema.json", projection)
    return projection
