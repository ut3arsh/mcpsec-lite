"""Fake upstream MCP server that spawns a long-sleeping grandchild process for process hygiene tests."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Any

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


def create_fake_server() -> Server:
    server = Server("fake-upstream-grandchild")

    tools = [
        types.Tool(
            name="ping",
            description="Ping tool",
            input_schema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="crash",
            description="Simulates immediate crash by exiting process",
            input_schema={"type": "object", "properties": {}},
        ),
    ]

    async def handle_list_tools(
        req_ctx: Any, params: types.PaginatedRequestParams
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tools)

    async def handle_call_tool(
        req_ctx: Any, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        if params.name == "crash":
            os._exit(42)
        return types.CallToolResult(content=[types.TextContent(type="text", text="pong")])

    server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)

    return server


async def run_stdio(upstream_pid_file: str, grandchild_pid_file: str) -> None:
    # 1. Record own PID
    with open(upstream_pid_file, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    # 2. Spawn a long-sleeping grandchild process
    grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

    # 3. Record grandchild PID
    with open(grandchild_pid_file, "w", encoding="utf-8") as f:
        f.write(str(grandchild.pid))

    server = create_fake_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(description="Fake Upstream MCP Server with Grandchild")
    parser.add_argument("--upstream-pid-file", required=True, help="File to record upstream PID")
    parser.add_argument(
        "--grandchild-pid-file", required=True, help="File to record grandchild PID"
    )
    args = parser.parse_args()

    try:
        anyio.run(run_stdio, args.upstream_pid_file, args.grandchild_pid_file)
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)


if __name__ == "__main__":
    main()
