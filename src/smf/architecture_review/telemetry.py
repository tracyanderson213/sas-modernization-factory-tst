"""Bounded telemetry that cannot imply runtime or acceptance success."""

from __future__ import annotations

from typing import Any


def packet_event(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event": "architecture_review_packet_assembled",
        "packet_id": packet["packet_id"],
        "packet_digest": packet["content_digest"],
        **packet["identity"],
        **packet["lifecycle"],
        "terminal_disposition": packet["terminal_disposition"],
        "blocker_count": len(packet["blockers"]),
    }
