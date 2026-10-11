"""Subprocess supervision and multi-upstream MCP server lifecycle management."""

from __future__ import annotations

import contextvars
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import anyio
import mcp.client.stdio as mcp_stdio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcpsec_core.adapters import SERVER_NAME_REGEX, encode_tool_name

# Global hook to capture subprocess PID spawned by stdio_client
_current_upstream_proc: contextvars.ContextVar[UpstreamProcess | None] = contextvars.ContextVar(
    "_current_upstream_proc", default=None
)

_orig_create_process = mcp_stdio._create_platform_compatible_process


async def _hooked_create_process(*args: Any, **kwargs: Any) -> Any:
    proc = await _orig_create_process(*args, **kwargs)
    upstream = _current_upstream_proc.get()
    if upstream is not None and hasattr(proc, "pid"):
        upstream.pid = proc.pid
    return proc


mcp_stdio._create_platform_compatible_process = _hooked_create_process

# Safe base system environment variable allowlists
SAFE_SYSTEM_ENV_VARS_WIN = frozenset(
    {
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "COMSPEC",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "COMMONPROGRAMFILES",
        "LOCALAPPDATA",
        "APPDATA",
    }
)

SAFE_SYSTEM_ENV_VARS_POSIX = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "SHELL",
        "TERM",
    }
)


def sanitize_upstream_env(user_env: dict[str, str] | None = None) -> dict[str, str]:
    """Construct an isolated environment for upstream server execution.

    Allows safe base system variables plus explicitly declared env variables from config.
    Prevents leaking parent process secrets (e.g. API keys, credentials) to upstream.
    """
    safe_keys = SAFE_SYSTEM_ENV_VARS_WIN if os.name == "nt" else SAFE_SYSTEM_ENV_VARS_POSIX
    clean_env: dict[str, str] = {}

    for k, v in os.environ.items():
        if k.upper() in safe_keys:
            clean_env[k] = v

    if user_env:
        for k, v in user_env.items():
            clean_env[k] = str(v)

    return clean_env


def _get_descendants_posix(root_pid: int) -> list[int]:
    """Find all descendant PIDs of root_pid using psutil or /proc."""
    if root_pid <= 0:
        return []

    # 1. Try psutil if available
    try:
        import psutil  # type: ignore[import-untyped,unused-ignore]

        proc = psutil.Process(root_pid)
        return [c.pid for c in proc.children(recursive=True)]
    except Exception:
        pass

    # 2. Descendant-walk using /proc on Linux
    from collections import defaultdict

    parent_map: dict[int, list[int]] = defaultdict(list)
    try:
        proc_entries = os.listdir("/proc")
    except OSError:
        return []

    for entry in proc_entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf-8", errors="ignore") as f:
                stat_line = f.read()
            rparen = stat_line.rfind(")")
            if rparen == -1:
                continue
            rest = stat_line[rparen + 1 :].strip().split()
            # rest[0] is state, rest[1] is ppid
            if len(rest) >= 2:
                ppid = int(rest[1])
                child_pid = int(entry)
                parent_map[ppid].append(child_pid)
        except (OSError, ValueError):
            continue

    descendants: list[int] = []
    queue = list(parent_map.get(root_pid, []))
    visited = set(queue)
    while queue:
        curr = queue.pop(0)
        descendants.append(curr)
        for child in parent_map.get(curr, []):
            if child not in visited:
                visited.add(child)
                queue.append(child)

    return descendants


def kill_process_tree(pid: int) -> None:
    """Kill entire process tree on Windows and POSIX to avoid orphan children.

    Guarantees:
    - Kills the process and all its descendants.
    - Never kills the caller or the caller's process group.
    - On POSIX, combines process-group signaling with /proc descendant walk.
    """
    if pid <= 0:
        return
    if sys.platform == "win32":
        import subprocess

        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass
    else:
        import signal

        caller_pid = os.getpid()
        caller_pgid = os.getpgid(0)

        # 1. Collect descendants via /proc or psutil before signaling
        descendants = _get_descendants_posix(pid)

        # 2. If pid has its own process group (start_new_session=True), kill the group
        try:
            child_pgid = os.getpgid(pid)
        except OSError:
            child_pgid = pid

        if child_pgid > 0 and child_pgid != caller_pgid:
            try:
                os.killpg(child_pgid, signal.SIGKILL)
            except OSError:
                pass

        # 3. Terminate all discovered descendants individually (deepest first)
        for d_pid in reversed(descendants):
            if d_pid != caller_pid and d_pid != caller_pgid:
                try:
                    os.kill(d_pid, signal.SIGKILL)
                except OSError:
                    pass

        # 4. Terminate the target process itself
        if pid != caller_pid and pid != caller_pgid:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def is_pid_alive(pid: int) -> bool:
    """Check whether a given PID is currently active and running."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        import ctypes.wintypes

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        code = ctypes.wintypes.DWORD()
        res = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return bool(res and code.value == 259)
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


@dataclass
class UpstreamConfig:
    """Configuration for a single upstream MCP server."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    required: bool = False
    start_timeout: float = 15.0
    call_timeout: float = 30.0
    max_restarts: int = 3


class UpstreamProcess:
    """Manages the lifecycle, supervision, and tool calls for a single upstream server."""

    def __init__(
        self,
        config: UpstreamConfig,
        sleep_fn: Callable[[float], Any] = anyio.sleep,
        time_fn: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.config = config
        self.sleep_fn = sleep_fn
        self.time_fn = time_fn
        self.session: ClientSession | None = None
        self.pid: int | None = None
        self.is_healthy = False
        self.restart_count = 0
        self.raw_tools: list[types.Tool] = []
        self.exposed_tools: list[types.Tool] = []
        self.start_error: Exception | None = None

        self._ready_event = anyio.Event()
        self._stop_event = anyio.Event()
        self._lock = anyio.Lock()

    async def run_worker(self) -> None:
        """Dedicated worker task that owns stdio_client and ClientSession lifecycles."""
        if (
            not SERVER_NAME_REGEX.match(self.config.name)
            or "." in self.config.name
            or "__" in self.config.name
        ):
            self.start_error = ValueError(
                f"Invalid server name '{self.config.name}': must match ^[a-z][a-z0-9-]*$ and not contain '.' or '__'"
            )
            self.is_healthy = False
            self._ready_event.set()
            return

        sanitized_env = sanitize_upstream_env(self.config.env)
        params = StdioServerParameters(
            command=self.config.command,
            args=self.config.args,
            env=sanitized_env,
            cwd=self.config.cwd,
        )

        while not self._stop_event.is_set():
            token = _current_upstream_proc.set(self)
            try:
                async with stdio_client(params) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        with anyio.fail_after(self.config.start_timeout):
                            await session.initialize()
                            tools_res = await session.list_tools()

                        # Discover and namespace tools
                        self.raw_tools = list(tools_res.tools)
                        self.exposed_tools = []

                        for t in self.raw_tools:
                            exposed_name = encode_tool_name(self.config.name, t.name)
                            schema = getattr(t, "input_schema", None) or getattr(
                                t, "inputSchema", {}
                            )
                            exposed_tool = types.Tool(
                                name=exposed_name,
                                description=t.description,
                                input_schema=schema,
                            )
                            self.exposed_tools.append(exposed_tool)

                        self.session = session
                        self.is_healthy = True
                        self.start_error = None
                        self._ready_event.set()

                        # Supervise process liveness until stop is signaled
                        while not self._stop_event.is_set():
                            if self.pid is not None and not is_pid_alive(self.pid):
                                raise RuntimeError(
                                    f"Upstream process {self.pid} terminated unexpectedly"
                                )
                            with anyio.move_on_after(0.2):
                                await self._stop_event.wait()
            except Exception as exc:
                self.is_healthy = False
                self.session = None
                self.start_error = exc
                self._ready_event.set()
                if self._stop_event.is_set():
                    break
                if self.restart_count < self.config.max_restarts:
                    self.restart_count += 1
                    # Ensure any orphaned descendants from this crash are cleanly reaped
                    if self.pid is not None:
                        kill_process_tree(self.pid)
                        self.pid = None
                    self._ready_event = anyio.Event()
                    await self.sleep_fn(0.1)
                    continue
                else:
                    break
            finally:
                _current_upstream_proc.reset(token)
                self.is_healthy = False
                self.session = None
                if self.pid is not None:
                    kill_process_tree(self.pid)
                    self.pid = None

    async def wait_ready(self) -> None:
        """Wait for the worker task to complete startup initialization or recovery."""
        while not self.is_healthy and not self._stop_event.is_set():
            if self.restart_count >= self.config.max_restarts and not self.is_healthy:
                break
            await self._ready_event.wait()
            if self.is_healthy or self.restart_count >= self.config.max_restarts:
                break
            await self.sleep_fn(0.05)

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> types.CallToolResult:
        """Execute a tool call with explicit timeout supervision."""
        if not self.is_healthy or self.session is None:
            raise RuntimeError(f"Upstream server '{self.config.name}' is unhealthy or degraded")

        try:
            with anyio.fail_after(self.config.call_timeout):
                return await self.session.call_tool(
                    name=tool_name,
                    arguments=arguments or {},
                )
        except Exception as exc:
            self.is_healthy = False
            self._ready_event = anyio.Event()
            raise RuntimeError(
                f"Error calling tool '{tool_name}' on upstream '{self.config.name}': {exc}"
            ) from exc

    async def stop(self) -> None:
        """Signal worker task to wind down and terminate subprocess."""
        self.is_healthy = False
        self._stop_event.set()


class UpstreamManager:
    """Coordinates multiple upstream MCP server supervisors within a TaskGroup."""

    def __init__(
        self,
        configs: list[UpstreamConfig],
        sleep_fn: Callable[[float], Any] = anyio.sleep,
        time_fn: Callable[[], float] = time.perf_counter,
    ) -> None:
        seen_names: set[str] = set()
        self.servers: dict[str, UpstreamProcess] = {}
        self.sleep_fn = sleep_fn
        self.time_fn = time_fn

        for cfg in configs:
            if cfg.name in seen_names:
                raise ValueError(f"Duplicate upstream server name: '{cfg.name}'")
            if not SERVER_NAME_REGEX.match(cfg.name) or "." in cfg.name or "__" in cfg.name:
                raise ValueError(
                    f"Invalid upstream server name '{cfg.name}': must match ^[a-z][a-z0-9-]*$ and not contain '.' or '__'"
                )
            seen_names.add(cfg.name)
            self.servers[cfg.name] = UpstreamProcess(cfg, sleep_fn=sleep_fn, time_fn=time_fn)

    async def start_all(self, tg: anyio.abc.TaskGroup) -> list[str]:
        """Launch all configured upstream workers in the provided TaskGroup.

        Returns list of warnings for degraded non-required servers.
        Fails closed if any required server fails to start.
        """
        warnings: list[str] = []

        for proc in self.servers.values():
            tg.start_soon(proc.run_worker)

        for name, proc in self.servers.items():
            await proc.wait_ready()
            if not proc.is_healthy:
                if proc.config.required:
                    await self.shutdown_all()
                    raise RuntimeError(
                        f"Required upstream server '{name}' failed to start: {proc.start_error}"
                    )
                else:
                    warnings.append(
                        f"Non-required upstream server '{name}' failed to start and is degraded: {proc.start_error}"
                    )

        return warnings

    def list_all_tools(self) -> list[types.Tool]:
        """Return deterministic, sorted union of all healthy upstreams' tools."""
        all_tools: list[types.Tool] = []
        for name in sorted(self.servers.keys()):
            proc = self.servers[name]
            if proc.is_healthy:
                all_tools.extend(proc.exposed_tools)

        # Sort deterministically by exposed tool name
        all_tools.sort(key=lambda t: t.name)
        return all_tools

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> types.CallToolResult:
        """Route tool call to the designated upstream server."""
        proc = self.servers.get(server_name)
        if not proc or not proc.is_healthy:
            raise KeyError(f"Upstream server '{server_name}' is not found or degraded")
        return await proc.call_tool(tool_name, arguments)

    async def shutdown_all(self) -> None:
        """Clean shutdown of all child server processes."""
        for proc in self.servers.values():
            await proc.stop()
