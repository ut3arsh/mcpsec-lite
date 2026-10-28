"""Tool-description pinning, cryptographic hashing, and integrity management (ADR-016).

Implements:
1. Canonical JSON tool hashing covering all model-visible fields (name, description,
   inputSchema, outputSchema, title, annotations, nested properties).
2. Pure SHA-256 over raw UTF-8 bytes with NO Unicode normalization prior to hashing.
3. Server-level aggregate hash over sorted tool hashes and serverInfo.
4. Versioned, crash-safe, atomic pin storage (pins.json) with cross-process file locking.
5. Diff inspection flagging zero-width, bidi characters, and description size deltas.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from mcpsec_core.models import Decision

# Regex for model-visible invisible, zero-width, or bidi control characters
BIDI_ZERO_WIDTH_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2066-\u2069]")

# Volatile fields explicitly ignored during tool definition hashing
VOLATILE_TOOL_FIELDS = frozenset({"_meta"})

DEFAULT_PROXY_LOCK_TIMEOUT_SECONDS: float = 0.2
DEFAULT_CLI_LOCK_TIMEOUT_SECONDS: float = 5.0
DEFAULT_LOCK_TIMEOUT_SECONDS: float = DEFAULT_PROXY_LOCK_TIMEOUT_SECONDS


class LockTimeout(TimeoutError):
    """Raised when acquiring a cross-process or in-process lock exceeds the timeout."""

    pass


_PIN_PROCESS_LOCK = threading.RLock()

if sys.platform == "win32":
    import msvcrt

    @contextlib.contextmanager
    def _pin_file_lock(
        file_obj: Any, timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS
    ) -> Iterator[None]:
        """Lock file on Windows using msvcrt with threading lock and retries."""
        fd = file_obj.fileno()
        acquired_thread_lock = _PIN_PROCESS_LOCK.acquire(timeout=timeout)
        if not acquired_thread_lock:
            raise LockTimeout(f"Timeout acquiring in-process PinStore lock after {timeout}s")
        try:
            deadline = time.monotonic() + timeout
            poll_interval = 0.005
            locked = False
            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LockTimeout(
                            f"Timeout acquiring PinStore file lock on Windows after {timeout}s"
                        ) from None
                    time.sleep(poll_interval)
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
        finally:
            _PIN_PROCESS_LOCK.release()
else:
    import fcntl

    @contextlib.contextmanager
    def _pin_file_lock(
        file_obj: Any, timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS
    ) -> Iterator[None]:
        """Lock file on POSIX using fcntl and threading lock."""
        fd = file_obj.fileno()
        acquired_thread_lock = _PIN_PROCESS_LOCK.acquire(timeout=timeout)
        if not acquired_thread_lock:
            raise LockTimeout(f"Timeout acquiring in-process PinStore lock after {timeout}s")
        try:
            deadline = time.monotonic() + timeout
            poll_interval = 0.005
            locked = False
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise LockTimeout(
                            f"Timeout acquiring PinStore file lock on POSIX after {timeout}s"
                        ) from None
                    time.sleep(poll_interval)
            try:
                yield
            finally:
                if locked:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
        finally:
            _PIN_PROCESS_LOCK.release()


def check_pinning(
    server: str,
    tool_name: str,
    tool_def: dict[str, Any],
    pin_store: PinStore | None = None,
    mode: Literal["audit", "strict"] = "audit",
) -> tuple[Decision, Literal["pinned", "unpinned", "changed", "unchecked"], str | None, str]:
    """Pure pinning lifecycle evaluation function.

    Takes server name, tool name, raw/cleaned tool definition, pin store snapshot, and pinning mode.
    Returns: (Decision, pin_status, diff_summary, current_hash).

    Precedence & Rules:
    1. If pin_store is None:
       - strict mode -> Decision(deny, layer="pinning", reason="ERR_UNPINNED_TOOL: No pin store configured under strict pinning")
       - audit mode  -> Decision(allow, layer="pinning", reason="pass-through (no pinning store)")
    2. If pin_store is present:
       Evaluates pin status against store snapshot:
       - 'pinned': Decision(allow, layer="pinning", reason="tool definition matches pin")
       - 'unpinned':
           strict mode -> Decision(deny, layer="pinning", reason="ERR_UNPINNED_TOOL: Tool '<server>.<tool>' is unpinned under strict pinning")
           audit mode  -> Decision(allow, layer="pinning", reason="tool is unpinned (audit mode)")
       - 'changed':
           strict mode -> Decision(deny, layer="pinning", reason="ERR_TOOL_HASH_MISMATCH: Tool '<server>.<tool>' is changed under strict pinning")
           audit mode  -> Decision(allow, layer="pinning", reason="tool definition changed (audit mode)")
    """
    if pin_store is None:
        if mode == "strict":
            return (
                Decision(
                    decision="deny",
                    layer="pinning",
                    reason="ERR_UNPINNED_TOOL: No pin store configured under strict pinning",
                ),
                "unchecked",
                None,
                "",
            )
        return (
            Decision(
                decision="allow",
                layer="pinning",
                reason="pass-through (no pinning store)",
            ),
            "unchecked",
            None,
            "",
        )

    status, diff_summary, current_hash = pin_store.check_tool(server, tool_def, mode=mode)

    if mode == "strict" and status != "pinned":
        err_code = "ERR_UNPINNED_TOOL" if status == "unpinned" else "ERR_TOOL_HASH_MISMATCH"
        reason = f"{err_code}: Tool '{server}.{tool_name}' is {status} under strict pinning"
        return (
            Decision(decision="deny", layer="pinning", reason=reason),
            status,
            diff_summary,
            current_hash,
        )

    reason = (
        "tool definition matches pin" if status == "pinned" else f"tool is {status} (audit mode)"
    )
    return (
        Decision(decision="allow", layer="pinning", reason=reason),
        status,
        diff_summary,
        current_hash,
    )


class PinStoreError(Exception):
    """Raised when pin store is corrupt, invalid, or inaccessible."""


def clean_tool_definition(raw_def: dict[str, Any]) -> dict[str, Any]:
    """Strip volatile fields and return model-visible tool definition dict."""
    return {k: v for k, v in raw_def.items() if k not in VOLATILE_TOOL_FIELDS}


def compute_canonical_json_bytes(obj: Any) -> bytes:
    """Serialize object to canonical JSON (sorted keys, no whitespace, UTF-8 encoded).

    CRITICAL SECURITY REQUIREMENT (ADR-016):
    NO Unicode normalization (NFC/NFD/NFKC/NFKD) is performed before hashing.
    Homoglyphs and zero-width characters must produce distinct hashes.
    """
    json_str = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return json_str.encode("utf-8")


def compute_tool_hash(tool_def: dict[str, Any]) -> str:
    """Compute SHA-256 hash of canonical model-visible tool definition."""
    cleaned = clean_tool_definition(tool_def)
    canonical_bytes = compute_canonical_json_bytes(cleaned)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_server_hash(
    tools: list[dict[str, Any]], server_info: dict[str, Any] | None = None
) -> str:
    """Compute aggregate SHA-256 hash across sorted tool definitions and serverInfo."""
    tool_hashes: dict[str, str] = {}
    for t in tools:
        t_name = str(t.get("name", ""))
        tool_hashes[t_name] = compute_tool_hash(t)

    server_payload = {
        "server_info": server_info or {},
        "tools": {k: tool_hashes[k] for k in sorted(tool_hashes.keys())},
    }
    canonical_bytes = compute_canonical_json_bytes(server_payload)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_diff_summary(
    old_def: dict[str, Any] | None, new_def: dict[str, Any]
) -> tuple[str, bool]:
    """Compute human-readable diff summary and check for hidden/bidi characters.

    Returns (diff_summary_string, has_bidi_or_zero_width_flag).
    """
    new_json = json.dumps(new_def, sort_keys=True, ensure_ascii=False)
    has_invisible = bool(BIDI_ZERO_WIDTH_REGEX.search(new_json))

    flags: list[str] = []
    if has_invisible:
        flags.append("WARNING: contains invisible/zero-width/bidi control characters")

    if old_def is None:
        summary = "new tool first seen"
        if flags:
            summary = f"{summary} ({'; '.join(flags)})"
        return summary, has_invisible

    old_desc = str(old_def.get("description", ""))
    new_desc = str(new_def.get("description", ""))

    delta_chars = len(new_desc) - len(old_desc)
    changes: list[str] = []

    if old_desc != new_desc:
        sign = "+" if delta_chars >= 0 else ""
        changes.append(f"description changed ({sign}{delta_chars} chars)")

    if old_def.get("inputSchema") != new_def.get("inputSchema") or old_def.get(
        "input_schema"
    ) != new_def.get("input_schema"):
        changes.append("inputSchema changed")

    if old_def.get("outputSchema") != new_def.get("outputSchema") or old_def.get(
        "output_schema"
    ) != new_def.get("output_schema"):
        changes.append("outputSchema changed")

    if old_def.get("title") != new_def.get("title"):
        changes.append("title changed")

    if old_def.get("annotations") != new_def.get("annotations"):
        changes.append("annotations changed")

    added_keys = sorted(set(new_def.keys()) - set(old_def.keys()))
    removed_keys = sorted(set(old_def.keys()) - set(new_def.keys()))
    if added_keys:
        changes.append(f"added fields: {', '.join(added_keys)}")
    if removed_keys:
        changes.append(f"removed fields: {', '.join(removed_keys)}")

    if not changes:
        changes.append("definition metadata changed")

    if flags:
        changes.extend(flags)

    return "; ".join(changes), has_invisible


@dataclass
class ToolPin:
    tool_hash: str
    definition: dict[str, Any]
    pinned_at: str
    hashed_fields: list[str] = field(default_factory=list)


@dataclass
class ServerPin:
    server_info: dict[str, Any] = field(default_factory=dict)
    server_hash: str = ""
    tools: dict[str, ToolPin] = field(default_factory=dict)
    pinned_at: str = ""


class PinStore:
    """Thread-safe, process-safe, versioned pin store backed by pins.json."""

    def __init__(
        self,
        store_path: Path | str,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.store_path = Path(store_path)
        self._lock_file_path = self.store_path.with_suffix(".lock")
        self.lock_timeout = lock_timeout
        self.schema_version = 1
        self.servers: dict[str, ServerPin] = {}

    def _load_unlocked(self, fail_closed: bool = True) -> None:
        """Internal load and parse from disk without acquiring lock."""
        if not self.store_path.exists():
            self.servers = {}
            return

        try:
            with open(self.store_path, "rb") as f:
                data = json.loads(f.read().decode("utf-8"))
        except Exception as e:
            if fail_closed:
                raise PinStoreError(
                    f"Pin store file corrupt or unreadable at {self.store_path}: {e}"
                ) from e
            self.servers = {}
            return

        if not isinstance(data, dict):
            if fail_closed:
                raise PinStoreError(
                    f"Invalid pin store root: expected dict, got {type(data).__name__}"
                )
            self.servers = {}
            return

        version = data.get("schema_version")
        if version != self.schema_version:
            if fail_closed:
                raise PinStoreError(
                    f"Unsupported pin store schema_version: {version} (expected {self.schema_version})"
                )
            self.servers = {}
            return

        raw_servers = data.get("servers", {})
        if not isinstance(raw_servers, dict):
            if fail_closed:
                raise PinStoreError("Invalid pin store servers dict")
            self.servers = {}
            return

        parsed_servers: dict[str, ServerPin] = {}
        for srv_name, srv_data in raw_servers.items():
            if not isinstance(srv_data, dict):
                continue
            srv_info = srv_data.get("server_info", {})
            srv_hash = srv_data.get("server_hash", "")
            pinned_at = srv_data.get("pinned_at", "")
            raw_tools = srv_data.get("tools", {})
            parsed_tools: dict[str, ToolPin] = {}
            for t_name, t_data in raw_tools.items():
                if not isinstance(t_data, dict):
                    continue
                t_def = dict(t_data.get("definition", {}))
                raw_fields = t_data.get("hashed_fields")
                if isinstance(raw_fields, list):
                    h_fields = [str(x) for x in raw_fields]
                else:
                    h_fields = sorted(t_def.keys())
                parsed_tools[t_name] = ToolPin(
                    tool_hash=str(t_data.get("tool_hash", "")),
                    definition=t_def,
                    pinned_at=str(t_data.get("pinned_at", "")),
                    hashed_fields=h_fields,
                )
            parsed_servers[srv_name] = ServerPin(
                server_info=srv_info if isinstance(srv_info, dict) else {},
                server_hash=str(srv_hash),
                tools=parsed_tools,
                pinned_at=str(pinned_at),
            )

        self.servers = parsed_servers

    def load(self, fail_closed: bool = True) -> None:
        """Load and validate pins.json.

        If missing, initializes empty.
        If corrupt or invalid schema version, raises PinStoreError (fail closed).
        """
        if not self.store_path.exists():
            self.servers = {}
            return

        self._lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lock_file_path, "a+b") as lock_f:
            with _pin_file_lock(lock_f, timeout=self.lock_timeout):
                self._load_unlocked(fail_closed=fail_closed)

    def _save_unlocked(self) -> None:
        """Internal save assuming caller holds lock."""
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": self.schema_version,
            "servers": {
                srv_name: {
                    "server_info": srv_pin.server_info,
                    "server_hash": srv_pin.server_hash,
                    "pinned_at": srv_pin.pinned_at,
                    "tools": {
                        t_name: {
                            "tool_hash": t_pin.tool_hash,
                            "definition": t_pin.definition,
                            "hashed_fields": t_pin.hashed_fields or sorted(t_pin.definition.keys()),
                            "pinned_at": t_pin.pinned_at,
                        }
                        for t_name, t_pin in sorted(srv_pin.tools.items())
                    },
                }
                for srv_name, srv_pin in sorted(self.servers.items())
            },
        }

        canonical_data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False).encode(
            "utf-8"
        )

        temp_file = self.store_path.with_name(
            f"{self.store_path.name}.tmp.{os.getpid()}.{time.time_ns()}"
        )
        try:
            with open(temp_file, "wb") as f:
                f.write(canonical_data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, self.store_path)
        finally:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

    def save(self) -> None:
        """Atomically save pin store with fsync, cross-platform locking, and replace."""
        self._lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lock_file_path, "a+b") as lock_f:
            with _pin_file_lock(lock_f, timeout=self.lock_timeout):
                self._save_unlocked()

    def get_tool_pin(self, server: str, tool: str) -> ToolPin | None:
        srv = self.servers.get(server)
        if srv is None:
            return None
        return srv.tools.get(tool)

    def get_server_pin(self, server: str) -> ServerPin | None:
        return self.servers.get(server)

    def check_tool(
        self, server: str, tool_def: dict[str, Any], mode: Literal["audit", "strict"]
    ) -> tuple[Literal["pinned", "unpinned", "changed"], str | None, str]:
        """Check pinning status for a tool definition against current store.

        Returns (status, diff_summary, current_hash).
        """
        tool_name = str(tool_def.get("name", ""))
        cleaned = clean_tool_definition(tool_def)
        current_hash = compute_tool_hash(cleaned)
        pinned = self.get_tool_pin(server, tool_name)

        if pinned is None:
            diff, _ = compute_diff_summary(None, cleaned)
            return "unpinned", diff, current_hash

        if pinned.tool_hash != current_hash:
            diff, _ = compute_diff_summary(pinned.definition, cleaned)
            return "changed", diff, current_hash

        return "pinned", None, current_hash

    def check_server(
        self,
        server: str,
        tools: list[dict[str, Any]],
        server_info: dict[str, Any] | None = None,
    ) -> tuple[Literal["pinned", "unpinned", "changed"], str | None, str]:
        """Check server-level pinning status across all tools and serverInfo."""
        cleaned_tools = [clean_tool_definition(t) for t in tools]
        current_srv_hash = compute_server_hash(cleaned_tools, server_info)
        pinned_srv = self.get_server_pin(server)

        if pinned_srv is None:
            return "unpinned", "server first seen", current_srv_hash

        if pinned_srv.server_hash != current_srv_hash:
            diffs: list[str] = []
            if pinned_srv.server_info != (server_info or {}):
                diffs.append("server_info changed")
            # Check individual tool status
            for t in cleaned_tools:
                t_name = str(t.get("name", ""))
                st, t_diff, _ = self.check_tool(server, t, mode="audit")
                if st != "pinned" and t_diff:
                    diffs.append(f"{t_name}: {t_diff}")
            return "changed", "; ".join(diffs) or "server hash changed", current_srv_hash

        return "pinned", None, current_srv_hash

    def approve_tool(
        self,
        server: str,
        tool_def: dict[str, Any],
        server_info: dict[str, Any] | None = None,
    ) -> ToolPin:
        """Approve and pin a specific tool definition."""
        tool_name = str(tool_def.get("name", ""))
        cleaned = clean_tool_definition(tool_def)
        tool_hash = compute_tool_hash(cleaned)
        hashed_fields = sorted(cleaned.keys())
        now_iso = datetime.now(UTC).isoformat()

        pin = ToolPin(
            tool_hash=tool_hash,
            definition=cleaned,
            pinned_at=now_iso,
            hashed_fields=hashed_fields,
        )

        self._lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lock_file_path, "a+b") as lock_f:
            with _pin_file_lock(lock_f, timeout=self.lock_timeout):
                if self.store_path.exists():
                    try:
                        self._load_unlocked(fail_closed=False)
                    except Exception:
                        pass

                if server not in self.servers:
                    self.servers[server] = ServerPin(
                        server_info=server_info or {},
                        pinned_at=now_iso,
                        tools={},
                    )

                srv = self.servers[server]
                if server_info:
                    srv.server_info = server_info
                srv.tools[tool_name] = pin

                # Recompute server hash
                tool_defs = [t.definition for t in srv.tools.values()]
                srv.server_hash = compute_server_hash(tool_defs, srv.server_info)
                srv.pinned_at = now_iso

                self._save_unlocked()

        return pin

    def approve_server(
        self,
        server: str,
        tools: list[dict[str, Any]],
        server_info: dict[str, Any] | None = None,
    ) -> ServerPin:
        """Approve and pin all tools for a given server."""
        now_iso = datetime.now(UTC).isoformat()
        parsed_tools: dict[str, ToolPin] = {}

        for t in tools:
            t_name = str(t.get("name", ""))
            cleaned = clean_tool_definition(t)
            t_hash = compute_tool_hash(cleaned)
            parsed_tools[t_name] = ToolPin(
                tool_hash=t_hash,
                definition=cleaned,
                pinned_at=now_iso,
                hashed_fields=sorted(cleaned.keys()),
            )

        cleaned_tools = [p.definition for p in parsed_tools.values()]
        srv_hash = compute_server_hash(cleaned_tools, server_info)

        srv_pin = ServerPin(
            server_info=server_info or {},
            server_hash=srv_hash,
            tools=parsed_tools,
            pinned_at=now_iso,
        )

        self._lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lock_file_path, "a+b") as lock_f:
            with _pin_file_lock(lock_f, timeout=self.lock_timeout):
                if self.store_path.exists():
                    try:
                        self._load_unlocked(fail_closed=False)
                    except Exception:
                        pass
                self.servers[server] = srv_pin
                self._save_unlocked()

        return srv_pin
