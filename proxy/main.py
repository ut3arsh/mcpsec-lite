"""Main entrypoint for mcpsec-lite multi-upstream proxy service."""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Any, Literal

import anyio
import mcp.types as types
import yaml
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import LatencyMs
from mcpsec_core.policy import Policy, PolicyError, load_policy
from proxy.session import ProxySession
from proxy.supervisor import UpstreamConfig, UpstreamManager


def load_raw_config(config_path: Path) -> dict[str, Any]:
    """Load raw proxy YAML configuration for server parameters."""
    if not config_path.exists():
        return {}
    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}


def parse_upstream_configs(raw_config: dict[str, Any]) -> list[UpstreamConfig]:
    """Parse list of UpstreamConfig objects from raw proxy configuration."""
    configs: list[UpstreamConfig] = []

    # 1. Multi-upstream list under 'servers'
    if "servers" in raw_config and isinstance(raw_config["servers"], list):
        for s in raw_config["servers"]:
            if isinstance(s, dict):
                configs.append(
                    UpstreamConfig(
                        name=s.get("name", "upstream"),
                        command=s.get("command", "python"),
                        args=s.get("args", []),
                        env=s.get("env", {}),
                        cwd=s.get("cwd"),
                        required=s.get("required", False),
                    )
                )

    # 2. Legacy single-upstream format under 'server'
    elif "server" in raw_config and isinstance(raw_config["server"], dict):
        s = raw_config["server"]
        configs.append(
            UpstreamConfig(
                name=s.get("name", "filesystem"),
                command=s.get("command", "python"),
                args=s.get("args", ["-m", "tests.test_server"]),
                env=s.get("env", {}),
                cwd=s.get("cwd"),
                required=s.get("required", True),
            )
        )

    # 3. Default fallback if no servers specified
    if not configs:
        configs.append(
            UpstreamConfig(
                name="filesystem",
                command="python",
                args=["-m", "tests.test_server"],
                required=True,
            )
        )

    return configs


async def run_proxy(
    config_path: Path,
    audit_log_path: Path,
    agent_id: str = "dev-agent",
    mode: Literal["audit", "enforce"] = "enforce",
    tamper_evident: bool = False,
    fsync: bool = False,
) -> None:
    """Run the MCP proxy connecting agent on stdio to multiple upstream servers."""
    policy: Policy | None = None
    policy_hash: str = ""
    warnings: list[str] = []

    if config_path.exists():
        try:
            policy, policy_hash, warnings = load_policy(config_path, check_unenforced_guards=True)
            mode = policy.mode
        except PolicyError as err:
            print(f"Error loading policy from {config_path}: {err}", file=sys.stderr)
            for e in err.errors:
                print(
                    f"  [{e.get('code', 'ERR')}] {e.get('path', '')}: {e.get('message', '')}",
                    file=sys.stderr,
                )
            sys.exit(1)
    else:
        warnings.append(f"Config file {config_path} not found; running with default allow-all")

    raw_config = load_raw_config(config_path)

    # Configure redaction & audit logger
    redaction_cfg = raw_config.get("redaction", {})
    if policy is not None:
        log_args_mode: Literal["full", "redacted", "hash_only"] = policy.redaction.log_args
        patterns = list(policy.redaction.patterns) or None
        never_log_fields = list(policy.redaction.never_log_fields) or None
    else:
        log_args_mode = redaction_cfg.get("log_args", "redacted")
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

    # 1. Parse and initialize UpstreamManager
    upstream_configs = parse_upstream_configs(raw_config)
    upstream_manager = UpstreamManager(upstream_configs)

    async with anyio.create_task_group() as tg:
        # 2. Start upstream servers and capture startup warnings
        try:
            startup_warnings = await upstream_manager.start_all(tg)
            warnings.extend(startup_warnings)
        except Exception as exc:
            print(f"Proxy startup failed: {exc}", file=sys.stderr)
            audit_logger.log_policy_loaded(
                policy_path=str(config_path),
                policy_hash=policy_hash,
                warnings=[f"Proxy failed to start: {exc}"],
            )
            sys.exit(1)

        # 3. Log policy_loaded event
        audit_logger.log_policy_loaded(
            policy_path=str(config_path),
            policy_hash=policy_hash,
            warnings=warnings,
        )

        session_id = str(uuid.uuid4())
        proxy_session = ProxySession(
            session_id=session_id,
            upstream_manager=upstream_manager,
            audit_logger=audit_logger,
            policy_hash=policy_hash,
            agent_id=agent_id,
            mode=mode,
            policy_data=policy,
        )

        proxy_session.start()

        # 4. Create agent-facing MCP server (advertising only tools)
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

        async def handle_unsupported_surface(req_ctx: Any, params: Any) -> Any:
            # Reject unsupported MCP surfaces (sampling, elicitation, roots, prompts, resources)
            call_id = str(uuid.uuid4())
            audit_logger.log_tool_call(
                session_id=session_id,
                call_id=call_id,
                agent_id=agent_id,
                server="proxy",
                tool="unsupported_surface",
                capabilities=[],
                raw_args={},
                decision="deny",
                effective_decision="blocked",
                decision_layer="policy",
                decision_reason="ERR_UNSUPPORTED_SURFACE: MCP surface beyond tools is not supported in v1",
                pin_status="unchecked",
                latency_ms=LatencyMs(proxy=0.1, upstream=None),
                taint_before=sorted(proxy_session.session_state.taint),
                taint_after=sorted(proxy_session.session_state.taint),
                response_summary=None,
                error="ERR_UNSUPPORTED_SURFACE",
            )
            raise ValueError(
                "ERR_UNSUPPORTED_SURFACE: Surface beyond tools is rejected by mcpsec policy"
            )

        server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
        server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)

        for surface_method in [
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "sampling/createMessage",
            "roots/list",
        ]:
            server.add_request_handler(surface_method, types.RequestParams, handle_unsupported_surface)

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
            await upstream_manager.shutdown_all()
            tg.cancel_scope.cancel()


def main() -> None:
    """CLI entrypoint for mcpsec-proxy."""
    parser = argparse.ArgumentParser(
        description="mcpsec-proxy - Deterministic multi-upstream security & audit proxy for MCP."
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
