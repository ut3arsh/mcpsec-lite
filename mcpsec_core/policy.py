"""Policy evaluation and allowlist enforcement."""

from __future__ import annotations

from typing import Any

from mcpsec_core.models import Decision, ToolCall


def check_policy(call: ToolCall, policy: Any) -> Decision:
    """Evaluate per-agent tool, path, and domain allowlists.

    TODO(week-2): Implement per-agent allowlists, path normalization, domain matching,
    and default-deny rules.
    """
    return Decision(
        decision="allow",
        layer="policy",
        reason="policy check passed (stub)",
    )
