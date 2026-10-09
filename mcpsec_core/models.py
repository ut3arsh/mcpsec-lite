"""Data models and audit event types for mcpsec-lite.

This module provides pure dataclasses and Pydantic models for core decisions,
session state, tool calls, and spec-compliant audit log events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# --- Core Lifecycle Enums & Models ---


class DecisionType(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class EffectiveDecision(StrEnum):
    FORWARDED = "forwarded"
    BLOCKED = "blocked"
    HELD = "held"


class DecisionLayer(StrEnum):
    PINNING = "pinning"
    POLICY = "policy"
    FLOW = "flow"
    APPROVAL = "approval"
    NONE = "none"


class PinStatus(StrEnum):
    PINNED = "pinned"
    UNPINNED = "unpinned"
    CHANGED = "changed"


@dataclass
class Decision:
    """Represents a policy or flow control decision."""

    decision: Literal["allow", "deny", "require_approval"]
    layer: Literal["pinning", "policy", "flow", "approval", "none"] = "none"
    reason: str = ""
    rule_id: str | None = None

    @property
    def is_allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def is_denied(self) -> bool:
        return self.decision == "deny"

    @property
    def requires_approval(self) -> bool:
        return self.decision == "require_approval"


@dataclass
class SessionState:
    """Tracks session-level state including labels/taints and counters."""

    session_id: str
    taint: set[str] = field(default_factory=set)
    call_count: int = 0
    deny_count: int = 0
    agent_id: str = "*"
    mode: Literal["audit", "enforce"] = "enforce"


@dataclass
class ToolCall:
    """Represents a tool call invocation before and during policy evaluation."""

    call_id: str
    session_id: str
    agent_id: str
    server: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)


# --- Audit Log Event Models (docs/audit_log_schema.md v1) ---


class ResponseSummary(BaseModel):
    """Summary of upstream response (never raw content)."""

    model_config = ConfigDict(extra="ignore")

    status: Literal["ok", "error"]
    bytes: int
    content_type: str | None = None


class LatencyMs(BaseModel):
    """Latency breakdown in milliseconds."""

    model_config = ConfigDict(extra="ignore")

    proxy: float
    upstream: float | None = None


class BaseAuditEvent(BaseModel):
    """Common fields present across all audit events."""

    model_config = ConfigDict(extra="ignore")

    schema_version: int = 1
    event_type: str
    timestamp: str
    seq: int
    session_id: str | None = None
    prev_hash: str | None = None


class PolicyLoadedEvent(BaseAuditEvent):
    """Emitted when proxy starts and loads policy."""

    event_type: Literal["policy_loaded"] = "policy_loaded"
    session_id: str | None = None
    policy_path: str
    policy_hash: str
    warnings: list[str] = Field(default_factory=list)


class SessionStartEvent(BaseAuditEvent):
    """Emitted when an agent connects."""

    event_type: Literal["session_start"] = "session_start"
    session_id: str
    agent_id: str
    client_info: dict[str, Any] | None = None
    policy_hash: str
    mode: Literal["audit", "enforce"] = "enforce"


class SessionEndEvent(BaseAuditEvent):
    """Emitted when an agent disconnects or proxy shuts down."""

    event_type: Literal["session_end"] = "session_end"
    session_id: str
    reason: Literal["disconnect", "shutdown", "error"]
    final_taint: list[str]
    call_count: int
    deny_count: int


class ToolCallEvent(BaseAuditEvent):
    """Emitted for every tool call (allowed or not)."""

    event_type: Literal["tool_call"] = "tool_call"
    session_id: str
    call_id: str
    agent_id: str
    server: str
    tool: str
    capabilities: list[str] = Field(default_factory=list)
    args: Any  # dict | str | {"sha256": ...}
    decision: Literal["allow", "deny", "require_approval"]
    effective_decision: Literal["forwarded", "blocked", "held"]
    decision_layer: Literal["pinning", "policy", "flow", "approval", "none"]
    decision_reason: str
    rule_id: str | None = None
    taint_before: list[str] = Field(default_factory=list)
    taint_after: list[str] = Field(default_factory=list)
    pin_status: Literal["pinned", "unpinned", "changed"] = "pinned"
    flags: list[str] = Field(default_factory=list)
    risk_score: float | None = None
    response_summary: ResponseSummary | None = None
    latency_ms: LatencyMs
    error: str | None = None


class ApprovalEvent(BaseAuditEvent):
    """Emitted on approval actions (call approval/rejection or taint clearance)."""

    event_type: Literal["approval"] = "approval"
    session_id: str
    call_id: str | None = None
    action: Literal["approved", "denied", "timeout", "clear_taint"]
    cleared_labels: list[str] = Field(default_factory=list)
    approver: str
    taint_before: list[str] = Field(default_factory=list)
    taint_after: list[str] = Field(default_factory=list)
    note: str | None = None


class PinEvent(BaseAuditEvent):
    """Emitted when a tool or server is pinned or changed."""

    event_type: Literal["pin_event"] = "pin_event"
    session_id: str | None = None
    server: str
    tool: str | None = None
    action: Literal["first_seen", "changed", "approved", "list_changed_received"]
    old_hash: str | None = None
    new_hash: str | None = None
    diff_summary: str | None = None
    mode: Literal["audit", "strict"]
    effective_decision: Literal["logged", "blocked_until_approved", "accepted"]


AuditEvent = (
    PolicyLoadedEvent
    | SessionStartEvent
    | SessionEndEvent
    | ToolCallEvent
    | ApprovalEvent
    | PinEvent
)


def parse_audit_event(raw: dict[str, Any] | str) -> AuditEvent:
    """Parse and validate an audit event against schema v1."""
    import json

    data: dict[str, Any] = json.loads(raw) if isinstance(raw, str) else raw

    schema_version = data.get("schema_version")
    if schema_version != 1:
        raise ValueError(f"Unsupported schema_version: {schema_version}")

    event_type = data.get("event_type")
    match event_type:
        case "policy_loaded":
            return PolicyLoadedEvent.model_validate(data)
        case "session_start":
            return SessionStartEvent.model_validate(data)
        case "session_end":
            return SessionEndEvent.model_validate(data)
        case "tool_call":
            return ToolCallEvent.model_validate(data)
        case "approval":
            return ApprovalEvent.model_validate(data)
        case "pin_event":
            return PinEvent.model_validate(data)
        case _:
            raise ValueError(f"Unknown event_type: {event_type}")
