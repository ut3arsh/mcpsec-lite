"""In-process Fake HTTP Fetch MCP server for deterministic testing without external network."""

from __future__ import annotations

import argparse
import sys
from typing import Any
from urllib.parse import urlsplit

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

# Canned web content for local testing
CANNED_RESPONSES: dict[str, str] = {
    "https://api.github.com/repos/acme/repo": '{"id": 12345, "name": "acme/repo", "private": false}',
    "https://raw.githubusercontent.com/acme/repo/main/README.md": "# Acme Public Documentation\nClean text.",
    "https://httpbin.org/get": '{"url": "https://httpbin.org/get", "status": "ok"}',
    "https://attacker-observable.com/sink": '{"received": true}',
}


def create_fake_fetch_server() -> Server:
    """Create an MCP server with the fetch tool."""
    server = Server("fake-fetch-server")

    tools = [
        types.Tool(
            name="fetch",
            description="Fetches a URL from the internet and extracts its contents as markdown.",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "max_length": {"type": "integer", "default": 5000},
                    "start_index": {"type": "integer", "default": 0},
                    "raw": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )
    ]

    async def handle_list_tools(
        req_ctx: Any, params: types.PaginatedRequestParams
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tools)

    async def handle_call_tool(
        req_ctx: Any, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        name = params.name
        args = params.arguments or {}

        if name != "fetch":
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool: {name}")],
                is_error=True,
            )

        url = args.get("url", "")
        max_len = int(args.get("max_length", 5000))
        start_idx = int(args.get("start_index", 0))

        # Check canned responses
        if url in CANNED_RESPONSES:
            content = CANNED_RESPONSES[url]
        else:
            parsed = urlsplit(url)
            content = f"# Mock Content for {parsed.netloc}\nPath: {parsed.path}"

        sliced = content[start_idx : start_idx + max_len]
        return types.CallToolResult(content=[types.TextContent(type="text", text=sliced)])

    server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)

    return server


async def run_stdio() -> None:
    server = create_fake_fetch_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(description="Fake Fetch MCP Server")
    parser.parse_args()
    try:
        anyio.run(run_stdio)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
