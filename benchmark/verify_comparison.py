"""Direct vs Proxy Call Comparison Script."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.audit import AuditLogger
from proxy.session import ProxySession
from proxy.supervisor import UpstreamManager
from tests.test_server import create_test_fs_server


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        sandbox_dir = Path(tmp_dir_str) / "sandbox"
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        audit_file = Path(tmp_dir_str) / "audit.jsonl"

        test_file = sandbox_dir / "test.txt"
        test_file.write_text("MCP Direct vs Proxy Test Content", encoding="utf-8")

        # 1. DIRECT CALL TO UPSTREAM SERVER
        fs_server = create_test_fs_server(sandbox_dir)
        d_c2s_w, d_c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        d_s2c_w, d_s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

        direct_tools = None
        direct_read_res = None
        direct_write_res = None

        async with anyio.create_task_group() as tg1:

            async def run_fs() -> None:
                await fs_server.run(
                    d_c2s_r,
                    d_s2c_w,
                    fs_server.create_initialization_options(),
                    raise_exceptions=True,
                )

            tg1.start_soon(run_fs)

            async with ClientSession(d_s2c_r, d_c2s_w) as direct_client:
                await direct_client.initialize()
                direct_tools = await direct_client.list_tools()
                direct_read_res = await direct_client.call_tool("read_file", {"path": "test.txt"})
                direct_write_res = await direct_client.call_tool(
                    "write_file", {"path": "direct_out.txt", "content": "Direct Write"}
                )
                tg1.cancel_scope.cancel()

        # 2. CALL THROUGH PROXY
        fs_upstream = create_test_fs_server(sandbox_dir)
        up_c2s_w, up_c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        up_s2c_w, up_s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

        p_c2s_w, p_c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        p_s2c_w, p_s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

        proxy_server = Server("mcpsec-proxy")
        audit_logger = AuditLogger(log_path=audit_file)

        proxy_tools = None
        proxy_read_res = None
        proxy_write_res = None

        async with anyio.create_task_group() as tg2:

            async def run_upstream_fs() -> None:
                await fs_upstream.run(
                    up_c2s_r,
                    up_s2c_w,
                    fs_upstream.create_initialization_options(),
                    raise_exceptions=True,
                )

            tg2.start_soon(run_upstream_fs)

            async with ClientSession(up_s2c_r, up_c2s_w) as upstream_client:
                await upstream_client.initialize()
                from unittest.mock import AsyncMock

                tools_res = await upstream_client.list_tools()
                fs_proc = AsyncMock()
                fs_proc.is_healthy = True
                fs_proc.raw_tools = list(tools_res.tools)
                fs_proc.exposed_tools = list(tools_res.tools)

                upstream_mgr = AsyncMock(spec=UpstreamManager)
                upstream_mgr.servers = {"filesystem": fs_proc}
                upstream_mgr.call_tool = lambda srv, tool, args: upstream_client.call_tool(
                    tool, args or {}
                )

                proxy_session = ProxySession(
                    session_id="test-session",
                    upstream_manager=upstream_mgr,
                    audit_logger=audit_logger,
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
                    return await proxy_session.call_tool(params.name, params.arguments)

                proxy_server.add_request_handler(
                    "tools/list", types.PaginatedRequestParams, handle_list_tools
                )
                proxy_server.add_request_handler(
                    "tools/call", types.CallToolRequestParams, handle_call_tool
                )

                async def run_proxy_srv() -> None:
                    await proxy_server.run(
                        p_c2s_r,
                        p_s2c_w,
                        proxy_server.create_initialization_options(),
                        raise_exceptions=True,
                    )

                tg2.start_soon(run_proxy_srv)

                async with ClientSession(p_s2c_r, p_c2s_w) as proxy_client:
                    await proxy_client.initialize()
                    proxy_tools = await proxy_client.list_tools()
                    proxy_read_res = await proxy_client.call_tool("read_file", {"path": "test.txt"})
                    proxy_write_res = await proxy_client.call_tool(
                        "write_file", {"path": "proxy_out.txt", "content": "Proxy Write"}
                    )
                    proxy_session.close()
                    tg2.cancel_scope.cancel()

        print("=== COMPARISON RESULTS ===")
        assert direct_tools is not None and proxy_tools is not None
        assert direct_read_res is not None and proxy_read_res is not None
        assert direct_write_res is not None and proxy_write_res is not None

        print("1. tools/list comparison:")
        direct_tool_names = [t.name for t in direct_tools.tools]
        proxy_tool_names = [t.name for t in proxy_tools.tools]
        print(f"   Direct tools: {direct_tool_names}")
        print(f"   Proxy tools:  {proxy_tool_names}")
        assert direct_tool_names == proxy_tool_names
        print("   -> tools/list matches 100%")

        print("\n2. tools/call read_file comparison:")
        d_c0 = direct_read_res.content[0]
        p_c0 = proxy_read_res.content[0]
        assert isinstance(d_c0, types.TextContent) and isinstance(p_c0, types.TextContent)
        print(f'   Direct result text: "{d_c0.text}", is_error={direct_read_res.is_error}')
        print(f'   Proxy result text:  "{p_c0.text}", is_error={proxy_read_res.is_error}')
        assert d_c0.text == p_c0.text
        assert direct_read_res.is_error == proxy_read_res.is_error
        print("   -> read_file matches 100%")

        print("\n3. tools/call write_file comparison:")
        d_w0 = direct_write_res.content[0]
        p_w0 = proxy_write_res.content[0]
        assert isinstance(d_w0, types.TextContent) and isinstance(p_w0, types.TextContent)
        print(f'   Direct result text: "{d_w0.text}", is_error={direct_write_res.is_error}')
        print(f'   Proxy result text:  "{p_w0.text}", is_error={proxy_write_res.is_error}')
        assert direct_write_res.is_error == proxy_write_res.is_error
        assert (sandbox_dir / "proxy_out.txt").read_text(encoding="utf-8") == "Proxy Write"
        print("   -> write_file executed and matches 100%")


if __name__ == "__main__":
    anyio.run(main)
