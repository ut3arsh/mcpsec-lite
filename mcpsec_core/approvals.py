"""Approval queue and state management for human-in-the-loop elevation.

Implements:
1. Append-only pending_approvals.jsonl with cross-platform file locking.
2. Crash recovery: state derived by replaying the event log.
3. Idempotent CLI and API operations (approve, deny, clear-taint).
4. Strict policy validation for taint clearance (refuses private_data by default).
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

_APPROVAL_PROCESS_LOCK = threading.RLock()

if sys.platform == "win32":
    import msvcrt

    @contextlib.contextmanager
    def file_lock(file_obj: Any) -> Iterator[None]:
        """Lock file on Windows using msvcrt with threading lock and retries."""
        fd = file_obj.fileno()
        with _APPROVAL_PROCESS_LOCK:
            locked = False
            for _ in range(3000):
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError:
                    time.sleep(0.002)
            if not locked:
                raise OSError("Timeout acquiring approvals file lock on Windows")
            try:
                yield
            finally:
                if locked:
                    try:
                        file_obj.flush()
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
else:
    import fcntl

    @contextlib.contextmanager
    def file_lock(file_obj: Any) -> Iterator[None]:
        """Lock file on POSIX using fcntl and threading lock."""
        fd = file_obj.fileno()
        with _APPROVAL_PROCESS_LOCK:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except Exception:
                    pass


@dataclass
class PendingApproval:
    call_id: str
    session_id: str
    agent_id: str
    server: str
    tool: str
    args: dict[str, Any]
    capabilities: list[str]
    taint_state: list[str]
    rule_id: str
    created_at: str
    expires_at: str
    status: Literal["pending", "approved", "denied", "timeout"] = "pending"
    operator: str | None = None
    reason: str | None = None
    decided_at: str | None = None


class ApprovalManager:
    """Manages append-only approval log and derived state."""

    def __init__(self, log_path: Path | str = "pending_approvals.jsonl") -> None:
        self.log_path = Path(log_path)
        self._listeners: dict[str, Any] = {}
        self._approvals: dict[str, PendingApproval] = {}
        self._last_read_offset: int = 0
        self._manager_lock = threading.RLock()

    def _sync_from_disk(self) -> None:
        """Incrementally read new lines from log_path into self._approvals."""
        if not self.log_path.exists():
            return
        with open(self.log_path, encoding="utf-8") as f:
            with file_lock(f):
                f.seek(self._last_read_offset)
                for line_str in f:
                    line = line_str.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._apply_event_to_state(data)
                self._last_read_offset = f.tell()

    def _apply_event_to_state(self, data: dict[str, Any]) -> None:
        ev_type = data.get("event")
        call_id = data.get("call_id")
        if not call_id:
            return

        if ev_type == "requested":
            self._approvals[call_id] = PendingApproval(
                call_id=call_id,
                session_id=data.get("session_id", ""),
                agent_id=data.get("agent_id", "*"),
                server=data.get("server", ""),
                tool=data.get("tool", ""),
                args=data.get("args", {}),
                capabilities=data.get("capabilities", []),
                taint_state=data.get("taint_state", []),
                rule_id=data.get("rule_id", ""),
                created_at=data.get("created_at", ""),
                expires_at=data.get("expires_at", ""),
                status="pending",
            )
        elif ev_type == "approved" and call_id in self._approvals:
            appr = self._approvals[call_id]
            appr.status = "approved"
            appr.operator = data.get("operator")
            appr.reason = data.get("reason")
            appr.decided_at = data.get("timestamp")
        elif ev_type == "denied" and call_id in self._approvals:
            appr = self._approvals[call_id]
            appr.status = "denied"
            appr.operator = data.get("operator")
            appr.reason = data.get("reason")
            appr.decided_at = data.get("timestamp")
        elif ev_type == "timeout" and call_id in self._approvals:
            appr = self._approvals[call_id]
            appr.status = "timeout"
            appr.decided_at = data.get("timestamp")

    def _append_event(self, event_data: dict[str, Any]) -> None:
        """Atomically append a single event line to the JSONL log under file lock."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._manager_lock:
            with open(self.log_path, "a+", encoding="utf-8") as f:
                with file_lock(f):
                    f.seek(0, os.SEEK_END)
                    line = json.dumps(event_data, separators=(",", ":"))
                    f.write(line + "\n")
                    f.flush()
                    self._last_read_offset = f.tell()
                    self._apply_event_to_state(event_data)

    def get_all_approvals(self) -> dict[str, PendingApproval]:
        """Derive current approval states by replaying the entire event log from start."""
        with self._manager_lock:
            self._sync_from_disk()
            return {k: PendingApproval(**vars(v)) for k, v in self._approvals.items()}

    def request_approval(
        self,
        call_id: str,
        session_id: str,
        agent_id: str,
        server: str,
        tool: str,
        args: dict[str, Any],
        capabilities: list[str],
        taint_state: list[str],
        rule_id: str,
        timeout_seconds: float = 120.0,
    ) -> PendingApproval:
        """Create and log a new approval request."""
        now = datetime.now(UTC)
        expires = now.timestamp() + timeout_seconds
        created_at_iso = now.isoformat()
        expires_at_iso = datetime.fromtimestamp(expires, UTC).isoformat()

        event = {
            "event": "requested",
            "call_id": call_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "server": server,
            "tool": tool,
            "args": args,
            "capabilities": capabilities,
            "taint_state": taint_state,
            "rule_id": rule_id,
            "created_at": created_at_iso,
            "expires_at": expires_at_iso,
        }
        self._append_event(event)

        return PendingApproval(
            call_id=call_id,
            session_id=session_id,
            agent_id=agent_id,
            server=server,
            tool=tool,
            args=args,
            capabilities=capabilities,
            taint_state=taint_state,
            rule_id=rule_id,
            created_at=created_at_iso,
            expires_at=expires_at_iso,
            status="pending",
        )

    def approve(
        self,
        call_id: str,
        operator: str = "operator",
        reason: str = "Approved by operator",
    ) -> bool:
        """Approve a pending request (idempotent)."""
        all_apprs = self.get_all_approvals()
        if call_id not in all_apprs:
            return False
        appr = all_apprs[call_id]
        if appr.status == "approved":
            return True  # Already approved, idempotent no-op
        if appr.status in ("denied", "timeout"):
            return False  # Terminal state reached

        event = {
            "event": "approved",
            "call_id": call_id,
            "operator": operator,
            "reason": reason,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self._append_event(event)

        # Notify any active in-process listener
        if call_id in self._listeners:
            self._listeners[call_id].set()

        return True

    def deny(
        self,
        call_id: str,
        operator: str = "operator",
        reason: str = "Denied by operator",
    ) -> bool:
        """Deny a pending request (idempotent)."""
        all_apprs = self.get_all_approvals()
        if call_id not in all_apprs:
            return False
        appr = all_apprs[call_id]
        if appr.status == "denied":
            return True  # Already denied, idempotent no-op
        if appr.status in ("approved", "timeout"):
            return False  # Terminal state reached

        event = {
            "event": "denied",
            "call_id": call_id,
            "operator": operator,
            "reason": reason,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self._append_event(event)

        if call_id in self._listeners:
            self._listeners[call_id].set()

        return True

    def record_timeout(self, call_id: str) -> None:
        """Record timeout expiration for a request."""
        all_apprs = self.get_all_approvals()
        if call_id in all_apprs and all_apprs[call_id].status == "pending":
            event = {
                "event": "timeout",
                "call_id": call_id,
                "timestamp": datetime.now(UTC).isoformat(),
            }
            self._append_event(event)
            if call_id in self._listeners:
                self._listeners[call_id].set()

    def clear_taint(
        self,
        session_id: str,
        label: str,
        policy: Any = None,
        operator: str = "operator",
        force: bool = False,
    ) -> tuple[bool, str]:
        """Clear a taint label for a session with strict policy validation.

        Refuses private_data clearing by default.
        Validates label against policy.approval.allow_clear.
        """
        # 1. Refuse private_data by default
        if label == "private_data" and not force:
            return (
                False,
                "Clearing 'private_data' taint is refused by default (requires operator elevation)",
            )

        # 2. Validate against policy allow_clear if policy is provided
        if policy is not None and hasattr(policy, "approval") and policy.approval is not None:
            allow_clear = getattr(policy.approval, "allow_clear", []) or []
            if label not in allow_clear and not force:
                return (
                    False,
                    f"Label '{label}' is not in policy approval.allow_clear list: {allow_clear}",
                )

        # 3. Log taint_cleared event
        event = {
            "event": "taint_cleared",
            "session_id": session_id,
            "label": label,
            "operator": operator,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self._append_event(event)
        return True, f"Taint label '{label}' cleared for session '{session_id}'"
