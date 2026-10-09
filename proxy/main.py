"""Main entrypoint for mcpsec-lite proxy service."""

from __future__ import annotations

import argparse
import hashlib
import sys
import uuid
from pathlib import Path
from typing import Any, Literal

import anyio
import mcp.types as types
import yaml
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcpsec_core.audit import AuditLogger
from proxy.session import ProxySession


def load_config(config_path: Path) -> dict[str, Any]:
    """Load proxy configuration from a YAML file."""
    if not config_path.exists():
        return {
            "server": {
                "name": "filesystem",
                "command": "python",
                "args": ["-m", "tests.test_server"],
            },
            "redaction": {
                "log_args": "redacted",
            },
        }

    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}


def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file's raw contents."""
    if not path.exists():
        return hashlib.sha256(b"").hexdigest()
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


async def run_proxy(
    config_path: Path,
    audit_log_path: Path,
    agent_id: str = "dev-agent",
    mode: Literal["audit", "enforce"] = "enforce",
    tamper_evident: bool = False,
    fsync: bool = False,
) -> None:
    """Run the MCP proxy connecting agent on stdio to upstream server."""
    config = load_config(config_path)
    policy_hash = compute_file_hash(config_path)

    # Configure redaction & audit logger
    redaction_cfg = config.get("redaction", {})
    log_args_mode: Literal["full", "redacted", "hash_only"] = redaction_cfg.get(
        "log_args", "redacted"
    )
    patterns = redaction_cfg.get("patterns")
    never_log_fields = redaction_cfg.get("never_log_fields")

    audit_logger = AuditLogger(
        log_path=audit_log_path,
        log_args=log_args_mode,
        patterns=patterns,
        never_log_fields=never_log_fields,
        tamper_evident=tamper_evident,
        fsync=fsync,
    )

    # 1. Log policy_loaded event
    warnings: list[str] = []
    if not config_path.exists():
        warnings.append(f"Config file {config_path} not found; using defaults")
    audit_logger.log_policy_loaded(
        policy_path=str(config_path),
        policy_hash=policy_hash,
        warnings=warnings,
    )

    # 2. Extract upstream server parameters
    server_cfg = config.get("server", {})
    server_name = server_cfg.get("name", "filesystem")
    command = server_cfg.get("command", "python")
    args = server_cfg.get("args", [])
    env = server_cfg.get("env")
    cwd = server_cfg.get("cwd")

    upstream_params = StdioServerParameters(
        command=command,
        args=args,
        env=env,
        cwd=cwd,
    )

    session_id = str(uuid.uuid4())

    # 3. Connect to upstream and serve agent on stdio
    async with stdio_client(upstream_params) as (upstream_read, upstream_write):
        async with ClientSession(upstream_read, upstream_write) as upstream_session:
            await upstream_session.initialize()

            proxy_session = ProxySession(
                session_id=session_id,
                upstream_session=upstream_session,
                audit_logger=audit_logger,
                server_name=server_name,
                policy_hash=policy_hash,
                agent_id=agent_id,
                mode=mode,
                policy_data=config,
            )

            proxy_session.start()

            # Create agent-facing MCP server
            server = Server("mcpsec-proxy")

            async def handle_list_tools(
                req_ctx: Any,
                params: types.PaginatedRequestParams,
            ) -> types.ListToolsResult:
                return await proxy_session.list_tools()

            async def handle_call_tool(
                req_ctx: Any,
                params: types.CallToolRequestParams,
            ) -> types.CallToolResult:
                return await proxy_session.call_tool(
                    name=params.name,
                    arguments=params.arguments,
                )

            server.add_request_handler(
                "tools/list", types.PaginatedRequestParams, handle_list_tools
            )
            server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)

            close_reason: Literal["disconnect", "shutdown", "error"] = "disconnect"
            try:
                async with stdio_server() as (server_read, server_write):
                    await server.run(
                        server_read,
                        server_write,
                        server.create_initialization_options(),
                    )
            except Exception as exc:
                if isinstance(exc, (KeyboardInterrupt, anyio.get_cancelled_exc_class())):
                    close_reason = "shutdown"
                else:
                    close_reason = "error"
                raise
            finally:
                proxy_session.close(reason=close_reason)


def main() -> None:
    """CLI entrypoint for mcpsec-proxy."""
    parser = argparse.ArgumentParser(
        description="mcpsec-proxy - Deterministic security & audit proxy for MCP tool calls."
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=Path("proxy.yaml"),
        help="Path to proxy configuration or policy file (default: proxy.yaml)",
    )
    parser.add_argument(
        "--audit-log",
        "-a",
        type=Path,
        default=Path("audit.jsonl"),
        help="Path to output JSONL audit log (default: audit.jsonl)",
    )
    parser.add_argument(
        "--agent-id",
        type=str,
        default="dev-agent",
        help="Identifier of the connecting agent (default: dev-agent)",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["audit", "enforce"],
        default="enforce",
        help="Enforcement mode: enforce or audit (default: enforce)",
    )
    parser.add_argument(
        "--tamper-evident",
        action="store_true",
        help="Enable hash chain across log entries",
    )
    parser.add_argument(
        "--fsync",
        action="store_true",
        help="Flush and fsync after each log entry",
    )

    args = parser.parse_args()

    try:
        anyio.run(
            run_proxy,
            args.config,
            args.audit_log,
            args.agent_id,
            args.mode,
            args.tamper_evident,
            args.fsync,
        )
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
