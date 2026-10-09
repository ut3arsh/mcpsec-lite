"""Flow control checking based on session taint and tool capabilities."""

from __future__ import annotations

from typing import Any

from mcpsec_core.models import Decision, SessionState, ToolCall


def check_flow(session_state: SessionState, call: ToolCall, policy: Any) -> Decision:
    """Evaluate flow rules against current session taint and tool capabilities.

    TODO(week-2): Implement session taint flow rules evaluation against capabilities.
    """
    return Decision(
        decision="allow",
        layer="flow",
        reason="flow check passed (stub)",
    )
