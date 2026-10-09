"""Audit logging for mcpsec-lite.

Provides single-writer append-only JSONL logging conforming to docs/audit_log_schema.md v1.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from mcpsec_core.models import (
    ApprovalEvent,
    AuditEvent,
    LatencyMs,
    PinEvent,
    PolicyLoadedEvent,
    ResponseSummary,
    SessionEndEvent,
    SessionStartEvent,
    ToolCallEvent,
)

DEFAULT_NEVER_LOG_FIELDS = [
    "password",
    "token",
    "authorization",
    "secret",
    "api_key",
    "apikey",
]
DEFAULT_REDACTION_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{36}",
]


def format_rfc3339_utc(dt: datetime | None = None) -> str:
    """Format datetime as RFC 3339 UTC with millisecond precision."""
    if dt is None:
        dt = datetime.now(UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def canonical_json_bytes(obj: Any) -> bytes:
    """Generate canonical JSON bytes (sorted keys, compact separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def canonical_json_hash(obj: Any) -> str:
    """Compute SHA-256 hash of canonical JSON representation."""
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


class Redactor:
    """Handles argument and error message redaction according to policy."""

    def __init__(
        self,
        mode: Literal["full", "redacted", "hash_only"] = "redacted",
        patterns: list[str] | None = None,
        never_log_fields: list[str] | None = None,
    ) -> None:
        self.mode = mode
        fields = never_log_fields if never_log_fields is not None else DEFAULT_NEVER_LOG_FIELDS
        self.never_log_fields = {f.lower() for f in fields}
        compiled_patterns = patterns if patterns is not None else DEFAULT_REDACTION_PATTERNS
        self._compiled_regexes = [re.compile(p) for p in compiled_patterns]

    def redact_text(self, text: str) -> str:
        """Redact regex pattern matches in a text string."""
        if self.mode == "full":
            return text
        result = text
        for pattern in self._compiled_regexes:
            result = pattern.sub("[REDACTED]", result)
        return result

    def redact_args(self, args: Any) -> Any:
        """Redact tool arguments according to configured mode."""
        if self.mode == "full":
            return args

        if self.mode == "hash_only":
            return {"sha256": canonical_json_hash(args)}

        return self._redact_recursive(args)

    def _redact_recursive(self, val: Any) -> Any:
        if isinstance(val, dict):
            new_dict: dict[str, Any] = {}
            for k, v in val.items():
                if str(k).lower() in self.never_log_fields:
                    new_dict[k] = "[REDACTED]"
                else:
                    new_dict[k] = self._redact_recursive(v)
            return new_dict
        elif isinstance(val, list):
            return [self._redact_recursive(item) for item in val]
        elif isinstance(val, str):
            return self.redact_text(val)
        return val


class AuditLogger:
    """Single-writer append-only JSONL audit logger."""

    def __init__(
        self,
        log_path: str | Path | None = None,
        log_args: Literal["full", "redacted", "hash_only"] = "redacted",
        patterns: list[str] | None = None,
        never_log_fields: list[str] | None = None,
        tamper_evident: bool = False,
        fsync: bool = False,
    ) -> None:
        self.log_path = Path(log_path) if log_path else None
        self.redactor = Redactor(
            mode=log_args,
            patterns=patterns,
            never_log_fields=never_log_fields,
        )
        self.tamper_evident = tamper_evident
        self.fsync = fsync
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash: str | None = None

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            # If log file exists, scan to recover the last seq and prev_hash
            if self.log_path.exists() and self.log_path.stat().st_size > 0:
                self._recover_seq_and_hash()

    def _recover_seq_and_hash(self) -> None:
        """Read existing log file to resume seq monotonicity and hash chain."""
        assert self.log_path is not None
        try:
            with open(self.log_path, "rb") as f:
                last_line = b""
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
                if last_line:
                    try:
                        data = json.loads(last_line.decode("utf-8"))
                        self._seq = int(data.get("seq", 0))
                    except Exception:
                        pass
                    if self.tamper_evident:
                        self._prev_hash = hashlib.sha256(last_line).hexdigest()
        except Exception:
            pass

    def log_event(self, event: AuditEvent) -> AuditEvent:
        """Write a typed audit event to the log."""
        with self._lock:
            self._seq += 1
            event.seq = self._seq
            if self.tamper_evident:
                event.prev_hash = self._prev_hash

            line_str = event.model_dump_json(exclude_none=False)
            line_bytes = line_str.encode("utf-8")

            if self.tamper_evident:
                self._prev_hash = hashlib.sha256(line_bytes).hexdigest()

            if self.log_path:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line_str + "\n")
                    f.flush()
                    if self.fsync:
                        os.fsync(f.fileno())

            return event

    def log_policy_loaded(
        self,
        policy_path: str,
        policy_hash: str,
        warnings: list[str] | None = None,
        timestamp: str | None = None,
    ) -> PolicyLoadedEvent:
        """Log a policy_loaded event."""
        event = PolicyLoadedEvent(
            schema_version=1,
            event_type="policy_loaded",
            timestamp=timestamp or format_rfc3339_utc(),
            seq=0,  # Will be assigned under lock in log_event
            policy_path=policy_path,
            policy_hash=policy_hash,
            warnings=warnings or [],
        )
        self.log_event(event)
        return event

    def log_session_start(
        self,
        session_id: str,
        agent_id: str,
        policy_hash: str,
        client_info: dict[str, Any] | None = None,
        mode: Literal["audit", "enforce"] = "enforce",
        timestamp: str | None = None,
    ) -> SessionStartEvent:
        """Log a session_start event."""
        event = SessionStartEvent(
            schema_version=1,
            event_type="session_start",
            timestamp=timestamp or format_rfc3339_utc(),
            seq=0,
            session_id=session_id,
            agent_id=agent_id,
            client_info=client_info,
            policy_hash=policy_hash,
            mode=mode,
        )
        self.log_event(event)
        return event

    def log_session_end(
        self,
        session_id: str,
        reason: Literal["disconnect", "shutdown", "error"],
        final_taint: list[str],
        call_count: int,
        deny_count: int,
        timestamp: str | None = None,
    ) -> SessionEndEvent:
        """Log a session_end event."""
        event = SessionEndEvent(
            schema_version=1,
            event_type="session_end",
            timestamp=timestamp or format_rfc3339_utc(),
            seq=0,
            session_id=session_id,
            reason=reason,
            final_taint=final_taint,
            call_count=call_count,
            deny_count=deny_count,
        )
        self.log_event(event)
        return event

    def log_tool_call(
        self,
        session_id: str,
        call_id: str,
        agent_id: str,
        server: str,
        tool: str,
        capabilities: list[str],
        raw_args: Any,
        decision: Literal["allow", "deny", "require_approval"],
        effective_decision: Literal["forwarded", "blocked", "held"],
        decision_layer: Literal["pinning", "policy", "flow", "approval", "none"],
        decision_reason: str,
        latency_ms: LatencyMs | dict[str, Any],
        rule_id: str | None = None,
        taint_before: list[str] | None = None,
        taint_after: list[str] | None = None,
        pin_status: Literal["pinned", "unpinned", "changed", "unchecked"] = "unchecked",
        flags: list[str] | None = None,
        risk_score: float | None = None,
        response_summary: ResponseSummary | dict[str, Any] | None = None,
        error: str | None = None,
        timestamp: str | None = None,
    ) -> ToolCallEvent:
        """Log a tool_call event with redacted args and summary."""
        redacted_args = self.redactor.redact_args(raw_args)
        redacted_error = self.redactor.redact_text(error) if error is not None else None

        if isinstance(latency_ms, dict):
            latency_ms_model = LatencyMs.model_validate(latency_ms)
        else:
            latency_ms_model = latency_ms

        response_summary_model: ResponseSummary | None
        if isinstance(response_summary, dict):
            response_summary_model = ResponseSummary.model_validate(response_summary)
        else:
            response_summary_model = response_summary

        event = ToolCallEvent(
            schema_version=1,
            event_type="tool_call",
            timestamp=timestamp or format_rfc3339_utc(),
            seq=0,
            session_id=session_id,
            call_id=call_id,
            agent_id=agent_id,
            server=server,
            tool=tool,
            capabilities=capabilities,
            args=redacted_args,
            decision=decision,
            effective_decision=effective_decision,
            decision_layer=decision_layer,
            decision_reason=decision_reason,
            rule_id=rule_id,
            taint_before=taint_before or [],
            taint_after=taint_after or [],
            pin_status=pin_status,
            flags=flags or [],
            risk_score=risk_score,
            response_summary=response_summary_model,
            latency_ms=latency_ms_model,
            error=redacted_error,
        )
        self.log_event(event)
        return event

    def log_approval(
        self,
        session_id: str,
        action: Literal["approved", "denied", "timeout", "clear_taint"],
        approver: str,
        taint_before: list[str],
        taint_after: list[str],
        call_id: str | None = None,
        cleared_labels: list[str] | None = None,
        note: str | None = None,
        timestamp: str | None = None,
    ) -> ApprovalEvent:
        """Log an approval event."""
        event = ApprovalEvent(
            schema_version=1,
            event_type="approval",
            timestamp=timestamp or format_rfc3339_utc(),
            seq=0,
            session_id=session_id,
            call_id=call_id,
            action=action,
            cleared_labels=cleared_labels or [],
            approver=approver,
            taint_before=taint_before,
            taint_after=taint_after,
            note=note,
        )
        self.log_event(event)
        return event

    def log_pin_event(
        self,
        server: str,
        action: Literal["first_seen", "changed", "approved", "list_changed_received"],
        mode: Literal["audit", "strict"],
        effective_decision: Literal["logged", "blocked_until_approved", "accepted"],
        session_id: str | None = None,
        tool: str | None = None,
        old_hash: str | None = None,
        new_hash: str | None = None,
        diff_summary: str | None = None,
        timestamp: str | None = None,
    ) -> PinEvent:
        """Log a pin_event."""
        event = PinEvent(
            schema_version=1,
            event_type="pin_event",
            timestamp=timestamp or format_rfc3339_utc(),
            seq=0,
            session_id=session_id,
            server=server,
            tool=tool,
            action=action,
            old_hash=old_hash,
            new_hash=new_hash,
            diff_summary=diff_summary,
            mode=mode,
            effective_decision=effective_decision,
        )
        self.log_event(event)
        return event
