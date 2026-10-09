"""Integration test verifying proxy against real @modelcontextprotocol/server-filesystem
via stdio.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import parse_audit_event
from proxy.session import ProxySession
from proxy.supervisor import UpstreamConfig, UpstreamManager


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_filesystem_server_proxy(
    tmp_path: Path, local_filesystem_server_info: tuple[str, list[str]]
) -> None:
    cmd, base_args = local_filesystem_server_info
    if not cmd:
        pytest.skip("Local filesystem server not available")

    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    test_file = sandbox_dir / "integration_test.txt"
    test_file.write_text("Hello from real MCP filesystem server!", encoding="utf-8")

    audit_log = tmp_path / "audit.jsonl"
    audit_logger = AuditLogger(log_path=audit_log, log_args="redacted")

    server_params = StdioServerParameters(
        command=cmd,
        args=[*base_args, str(sandbox_dir)],
    )

    # 1. Direct call to real MCP server
    direct_tools_list: types.ListToolsResult
    direct_call_result: types.CallToolResult

    try:
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as direct_session:
                await direct_session.initialize()
                direct_tools_list = await direct_session.list_tools()

                assert len(direct_tools_list.tools) > 0
                tool_names = {t.name for t in direct_tools_list.tools}

                # Find a read tool from the real server's tools/list
                target_tool_name = (
                    "read_file" if "read_file" in tool_names else direct_tools_list.tools[0].name
                )
                target_tool = next(t for t in direct_tools_list.tools if t.name == target_tool_name)

                # Determine argument name from tool's input_schema
                props = (
                    target_tool.input_schema.get("properties", {})
                    if target_tool.input_schema
                    else {}
                )
                path_param = (
                    "path" if "path" in props else list(props.keys())[0] if props else "path"
                )

                direct_call_result = await direct_session.call_tool(
                    target_tool_name,
                    {path_param: str(test_file)},
                )
    except Exception as exc:
        pytest.skip(f"Failed to run real @modelcontextprotocol/server-filesystem: {exc}")

    # 2. Proxied call to real MCP server via UpstreamManager
    upstream_config = UpstreamConfig(
        name="fs",
        command=cmd,
        args=[*base_args, str(sandbox_dir)],
        required=True,
    )
    upstream_manager = UpstreamManager([upstream_config])

    proxy_server = Server("mcpsec-proxy")

    # Connect in-memory client to proxy server
    c2s_w, c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
    s2c_w, s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

    async with anyio.create_task_group() as tg:
        await upstream_manager.start_all(tg)

        proxy_session = ProxySession(
            session_id="real-server-session",
            upstream_manager=upstream_manager,
            audit_logger=audit_logger,
            policy_hash="test-policy-hash",
            agent_id="dev-agent",
            mode="enforce",
        )
        proxy_session.start()

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

        proxy_server.add_request_handler(
            "tools/list", types.PaginatedRequestParams, handle_list_tools
        )
        proxy_server.add_request_handler(
            "tools/call", types.CallToolRequestParams, handle_call_tool
        )

        async def run_server() -> None:
            await proxy_server.run(
                c2s_r,
                s2c_w,
                proxy_server.create_initialization_options(),
                raise_exceptions=True,
            )

        tg.start_soon(run_server)

        async with ClientSession(s2c_r, c2s_w) as client:
            await client.initialize()

            proxied_tools_list = await client.list_tools()
            # Verify tools are prefixed with fs__
            proxied_names = [t.name for t in proxied_tools_list.tools]
            expected_exposed_name = f"fs__{target_tool_name}"
            assert expected_exposed_name in proxied_names

            proxied_call_result = await client.call_tool(
                expected_exposed_name,
                {path_param: str(test_file)},
            )

            # Compare results
            assert proxied_call_result.is_error == direct_call_result.is_error
            assert len(proxied_call_result.content) == len(direct_call_result.content)
            if proxied_call_result.content and isinstance(
                proxied_call_result.content[0], types.TextContent
            ):
                assert isinstance(direct_call_result.content[0], types.TextContent)
                assert proxied_call_result.content[0].text == direct_call_result.content[0].text

            proxy_session.close(reason="disconnect")
            await upstream_manager.shutdown_all()
            tg.cancel_scope.cancel()

    # 3. Verify audit log has unchecked pin_status and valid event structure
    assert audit_log.exists()
    lines = audit_log.read_text(encoding="utf-8").strip().split("\n")
    events = [parse_audit_event(line) for line in lines]
    tool_events = [e for e in events if e.event_type == "tool_call"]
    assert len(tool_events) == 1
    assert tool_events[0].pin_status == "unchecked"
