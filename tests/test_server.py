"""A standalone stdio MCP filesystem server for testing and local proxying."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


def create_test_fs_server(allowed_dir: Path) -> Server:
    """Create a test MCP filesystem server instance."""
    server = Server("test-filesystem")

    tools = [
        types.Tool(
            name="read_file",
            description="Read the contents of a file.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
        types.Tool(
            name="write_file",
            description="Write content to a file.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        ),
        types.Tool(
            name="list_directory",
            description="List the contents of a directory.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
    ]

    async def handle_list_tools(
        req_ctx: Any,
        params: types.PaginatedRequestParams,
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tools)

    async def handle_call_tool(
        req_ctx: Any,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        name = params.name
        args = params.arguments or {}

        try:
            if name == "read_file":
                rel_path = args.get("path", "")
                target_path = Path(rel_path)
                if not target_path.is_absolute():
                    target_path = (allowed_dir / target_path).resolve()
                else:
                    target_path = target_path.resolve()

                # Native upstream confinement check (TOCTOU defense-in-depth)
                try:
                    target_path.relative_to(allowed_dir.resolve())
                except ValueError:
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=f"Access denied: path outside allowed root {allowed_dir}",
                            )
                        ],
                        is_error=True,
                    )

                if not target_path.exists() or not target_path.is_file():
                    err_msg = f"File not found: {rel_path}"
                    return types.CallToolResult(
                        content=[types.TextContent(type="text", text=err_msg)],
                        is_error=True,
                    )
                content = target_path.read_text(encoding="utf-8")
                return types.CallToolResult(content=[types.TextContent(type="text", text=content)])

            elif name == "write_file":
                rel_path = args.get("path", "")
                content_str = args.get("content", "")
                target_path = Path(rel_path)
                if not target_path.is_absolute():
                    target_path = (allowed_dir / target_path).resolve()
                else:
                    target_path = target_path.resolve()

                try:
                    target_path.relative_to(allowed_dir.resolve())
                except ValueError:
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=f"Access denied: path outside allowed root {allowed_dir}",
                            )
                        ],
                        is_error=True,
                    )

                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_text(content_str, encoding="utf-8")
                msg = f"Wrote {len(content_str)} bytes to {rel_path}"
                return types.CallToolResult(content=[types.TextContent(type="text", text=msg)])

            elif name == "list_directory":
                rel_path = args.get("path", ".")
                target_path = Path(rel_path)
                if not target_path.is_absolute():
                    target_path = (allowed_dir / target_path).resolve()
                else:
                    target_path = target_path.resolve()

                try:
                    target_path.relative_to(allowed_dir.resolve())
                except ValueError:
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=f"Access denied: path outside allowed root {allowed_dir}",
                            )
                        ],
                        is_error=True,
                    )

                if not target_path.exists() or not target_path.is_dir():
                    err_msg = f"Directory not found: {rel_path}"
                    return types.CallToolResult(
                        content=[types.TextContent(type="text", text=err_msg)],
                        is_error=True,
                    )
                entries = [p.name for p in target_path.iterdir()]
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text="\n".join(entries))]
                )

            else:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=f"Unknown tool: {name}")],
                    is_error=True,
                )

        except Exception as exc:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(exc))],
                is_error=True,
            )

    server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)

    return server


async def run_server(allowed_dir: Path) -> None:
    """Run server on stdio."""
    server = create_test_fs_server(allowed_dir)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    """CLI entrypoint for standalone test server."""
    parser = argparse.ArgumentParser(description="Test MCP Filesystem Server")
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path("."),
        help="Root directory for filesystem access",
    )
    args = parser.parse_args()
    try:
        anyio.run(run_server, args.dir.resolve())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
