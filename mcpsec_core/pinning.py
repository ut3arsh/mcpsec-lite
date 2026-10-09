"""Tool-description pinning and integrity checking."""

from __future__ import annotations

from typing import Any

from mcpsec_core.models import Decision


def check_pinning(server_id: str, tools_snapshot: Any) -> Decision:
    """Check whether tool definitions match pinned hashes.

    TODO(week-2): Implement SHA-256 canonical JSON tool-description pinning and diffing.
    """
    return Decision(
        decision="allow",
        layer="pinning",
        reason="pinning check passed (stub)",
    )
