"""End-to-end integration tests for the MCP proxy against a filesystem MCP server."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import parse_audit_event
from proxy.session import ProxySession
from proxy.supervisor import UpstreamConfig, UpstreamManager


@pytest.mark.integration
@pytest.mark.asyncio
async def test_proxy_filesystem_end_to_end(tmp_path: Path) -> None:
    # Set up sandbox directory for filesystem server
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    audit_log = tmp_path / "audit.jsonl"

    audit_logger = AuditLogger(log_path=audit_log, log_args="redacted")

    audit_logger.log_policy_loaded(
        policy_path="proxy.yaml",
        policy_hash="test-policy-hash",
        warnings=[],
    )

    upstream_config = UpstreamConfig(
        name="fs",
        command=sys.executable,
        args=["-m", "tests.test_server", "--dir", str(sandbox_dir)],
        required=True,
    )
    upstream_manager = UpstreamManager([upstream_config])

    # Connect agent client and proxy server via memory streams
    agent_c2s_writer, agent_c2s_reader = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](10)
    agent_s2c_writer, agent_s2c_reader = anyio.create_memory_object_stream[SessionMessage](10)

    proxy_server = Server("mcpsec-proxy")

    async with anyio.create_task_group() as tg:
        await upstream_manager.start_all(tg)

        proxy_session = ProxySession(
            session_id="test-session-uuid",
            upstream_manager=upstream_manager,
            audit_logger=audit_logger,
            policy_hash="test-policy-hash",
            agent_id="dev-agent",
            mode="enforce",
        )
        proxy_session.start({"name": "pytest-client", "version": "1.0"})

        # Register proxy handlers
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

        # Run proxy server
        async def run_proxy() -> None:
            await proxy_server.run(
                agent_c2s_reader,
                agent_s2c_writer,
                proxy_server.create_initialization_options(),
                raise_exceptions=True,
            )

        tg.start_soon(run_proxy)

        # Connect agent client to proxy
        async with ClientSession(agent_s2c_reader, agent_c2s_writer) as agent_client:
            init_res = await agent_client.initialize()
            assert init_res.server_info.name == "mcpsec-proxy"

            # 1. tools/list through proxy
            tools_res = await agent_client.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            assert "fs__read_file" in tool_names
            assert "fs__write_file" in tool_names
            assert "fs__list_directory" in tool_names

            # 2. tools/call write_file through proxy
            write_res = await agent_client.call_tool(
                "fs__write_file",
                {"path": "greeting.txt", "content": "Hello from MCP proxy test!"},
            )
            assert not write_res.is_error
            assert len(write_res.content) > 0
            assert isinstance(write_res.content[0], types.TextContent)
            assert "Wrote" in write_res.content[0].text

            # Verify file actually created in sandbox dir
            created_file = sandbox_dir / "greeting.txt"
            assert created_file.exists()
            assert created_file.read_text(encoding="utf-8") == "Hello from MCP proxy test!"

            # 3. tools/call read_file through proxy
            read_res = await agent_client.call_tool(
                "fs__read_file",
                {"path": "greeting.txt"},
            )
            assert not read_res.is_error
            assert len(read_res.content) > 0
            assert isinstance(read_res.content[0], types.TextContent)
            assert read_res.content[0].text == "Hello from MCP proxy test!"

            # 4. tools/call read_file on non-existent file (upstream error handling)
            err_res = await agent_client.call_tool(
                "fs__read_file",
                {"path": "non_existent.txt"},
            )
            assert err_res.is_error
            assert len(err_res.content) > 0
            assert isinstance(err_res.content[0], types.TextContent)
            assert "File not found" in err_res.content[0].text

            # Close session
            proxy_session.close(reason="disconnect")
            await upstream_manager.shutdown_all()
            tg.cancel_scope.cancel()

    # Verify Audit Log
    assert audit_log.exists()
    lines = audit_log.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 6  # policy_loaded, session_start, 3 tool_calls, session_end

    events = [parse_audit_event(line) for line in lines]
    assert events[0].event_type == "policy_loaded"
    assert events[1].event_type == "session_start"
    assert events[2].event_type == "tool_call"
    assert events[3].event_type == "tool_call"
    assert events[4].event_type == "tool_call"
    assert events[5].event_type == "session_end"

    # Verify latency breakdown is present on tool calls
    for ev in events[2:5]:
        assert ev.event_type == "tool_call"
        raw_call = json.loads(lines[events.index(ev)])
        assert "proxy" in raw_call["latency_ms"]
        assert raw_call["latency_ms"]["proxy"] >= 0
        assert "upstream" in raw_call["latency_ms"]
        assert raw_call["latency_ms"]["upstream"] is not None
        assert raw_call["latency_ms"]["upstream"] >= 0
