"""Subprocess supervision and multi-upstream MCP server lifecycle management."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcpsec_core.adapters import SERVER_NAME_REGEX, encode_tool_name

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


def kill_process_tree(pid: int) -> None:
    """Kill entire process tree on Windows and POSIX to avoid orphan children."""
    if pid <= 0:
        return
    if os.name == "nt":
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

        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)  # type: ignore[attr-defined]
        except Exception:
            try:
                os.kill(pid, signal.SIGKILL)  # type: ignore[attr-defined]
            except Exception:
                pass


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
                        schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", {})
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

                    # Wait until stop is signaled
                    await self._stop_event.wait()
        except Exception as exc:
            self.is_healthy = False
            self.session = None
            self.start_error = exc
            self._ready_event.set()
        finally:
            self.is_healthy = False
            self.session = None

    async def wait_ready(self) -> None:
        """Wait for the worker task to complete startup initialization."""
        await self._ready_event.wait()

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
