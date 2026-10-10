"""Audit logging for mcpsec-lite.

Provides single-writer append-only JSONL logging conforming to docs/audit_log_schema.md v1.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Sequence
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


def verify_hash_chain(file_paths: Sequence[Path | str]) -> tuple[bool, str | None]:
    """Verify the integrity of a hash-chained audit log across one or more rotated files."""
    last_line_hash: str | None = None

    for file_idx, fpath in enumerate(file_paths):
        path = Path(fpath)
        if not path.exists():
            return False, f"File {path} does not exist"

        expected_seq = 1
        with open(path, "rb") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line_bytes = raw_line.rstrip(b"\r\n")
                if not line_bytes:
                    continue

                try:
                    data = json.loads(line_bytes.decode("utf-8"))
                except Exception as exc:
                    return False, f"Invalid JSON on line {line_no} of {path}: {exc}"

                seq = data.get("seq")
                if seq != expected_seq:
                    return (
                        False,
                        f"Sequence gap in {path} at line {line_no}: expected {expected_seq}, got {seq}",
                    )
                expected_seq += 1

                prev_hash = data.get("prev_hash")
                if file_idx == 0 and line_no == 1:
                    # Very first event in first log file has no prev_hash (or None)
                    if prev_hash is not None:
                        # If it has a prev_hash from older file, that's fine if tracking across restarts
                        pass
                else:
                    if prev_hash != last_line_hash:
                        return (
                            False,
                            f"Hash chain broken in {path} at line {line_no}: expected {last_line_hash}, got {prev_hash}",
                        )

                last_line_hash = hashlib.sha256(line_bytes).hexdigest()

    return True, None


class AuditLogger:
    """Single-writer append-only JSONL audit logger with rotation and tamper-evident chaining."""

    def __init__(
        self,
        log_path: str | Path | None = None,
        log_args: Literal["full", "redacted", "hash_only"] = "redacted",
        patterns: list[str] | None = None,
        never_log_fields: list[str] | None = None,
        tamper_evident: bool = False,
        fsync: bool = False,
        max_bytes: int | None = None,
        queue_size: int | None = None,
    ) -> None:
        self.log_path = Path(log_path) if log_path else None
        self.redactor = Redactor(
            mode=log_args,
            patterns=patterns,
            never_log_fields=never_log_fields,
        )
        self.tamper_evident = tamper_evident
        self.fsync = fsync
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash: str | None = None
        self.rotated_files: list[Path] = []

        # Optional bounded writer queue with backpressure
        self._queue: Any = None
        self._writer_thread: threading.Thread | None = None
        self._stopping = False
        if queue_size is not None and queue_size > 0:
            import queue

            self._queue = queue.Queue(maxsize=queue_size)
            self._writer_thread = threading.Thread(
                target=self._writer_worker,
                daemon=True,
                name="audit-logger-writer",
            )
            self._writer_thread.start()

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            # If log file exists, scan to recover the last seq and prev_hash
            if self.log_path.exists() and self.log_path.stat().st_size > 0:
                self._recover_seq_and_hash()

    def _writer_worker(self) -> None:
        """Background worker thread draining the audit log queue."""
        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            event, done_event = item
            try:
                self._write_event_to_disk(event)
            finally:
                if done_event is not None:
                    done_event.set()
                self._queue.task_done()

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

    def _maybe_rotate_unlocked(self, new_bytes_len: int) -> None:
        """Rotate the log file if max_bytes is exceeded."""
        if not self.log_path or self.max_bytes is None:
            return

        if not self.log_path.exists():
            return

        current_size = self.log_path.stat().st_size
        if current_size > 0 and (current_size + new_bytes_len) > self.max_bytes:
            timestamp_str = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
            stem = self.log_path.stem
            ext = self.log_path.suffix or ".jsonl"
            rotated_name = f"{stem}-{timestamp_str}{ext}"
            rotated_path = self.log_path.parent / rotated_name

            # Ensure uniqueness if rotated in the same second
            counter = 1
            while rotated_path.exists():
                rotated_name = f"{stem}-{timestamp_str}-{counter}{ext}"
                rotated_path = self.log_path.parent / rotated_name
                counter += 1

            # Atomically rename current log file to rotated name
            os.replace(self.log_path, rotated_path)
            self.rotated_files.append(rotated_path)

            # Seq restarts per file
            self._seq = 0
            # _prev_hash is preserved so the first entry in new file points to last entry of rotated file!

    def _write_event_to_disk(self, event: AuditEvent) -> None:
        """Write serialized event to disk with rotation and optional fsync."""
        with self._lock:
            line_str = event.model_dump_json(exclude_none=False)
            line_bytes = line_str.encode("utf-8")

            if self.log_path:
                self._maybe_rotate_unlocked(len(line_bytes) + 1)
                # Re-assign seq if rotation happened before write
                if self._seq == 0:
                    self._seq = 1
                    event.seq = 1
                    # Recalculate JSON after seq reset
                    line_str = event.model_dump_json(exclude_none=False)
                    line_bytes = line_str.encode("utf-8")
                    if self.tamper_evident:
                        self._prev_hash = hashlib.sha256(line_bytes).hexdigest()

                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line_str + "\n")
                    f.flush()
                    if self.fsync:
                        os.fsync(f.fileno())

    def log_event(self, event: AuditEvent, sync: bool = False) -> AuditEvent:
        """Write or enqueue a typed audit event to the log."""
        with self._lock:
            self._seq += 1
            event.seq = self._seq
            if self.tamper_evident:
                event.prev_hash = self._prev_hash

            line_str = event.model_dump_json(exclude_none=False)
            line_bytes = line_str.encode("utf-8")

            if self.tamper_evident:
                self._prev_hash = hashlib.sha256(line_bytes).hexdigest()

        if self._queue is not None and not sync:
            # Enqueue with backpressure (blocks if queue is full)
            self._queue.put((event, None))
        else:
            self._write_event_to_disk(event)

        return event

    def flush(self) -> None:
        """Wait for any enqueued audit events to be written to disk."""
        if self._queue is not None:
            self._queue.join()

    def close(self) -> None:
        """Flush and shut down background writer thread."""
        if self._queue is not None and self._writer_thread is not None:
            self.flush()
            self._queue.put(None)
            self._writer_thread.join(timeout=5.0)

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
        action: Literal[
            "first_seen", "changed", "approved", "list_changed_received", "server_info_changed"
        ],
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
