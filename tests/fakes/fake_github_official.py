"""Fake-official GitHub MCP server replaying schemas from github.tools.official.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from tests.fakes.fake_github import MOCK_FILES, MOCK_ISSUES, MOCK_PULL_REQUESTS

OFFICIAL_SNAPSHOT_PATH = (
    Path(__file__).resolve().parent.parent / "fixtures" / "github.tools.official.json"
)


def load_official_snapshot_raw(
    snapshot_path: Path = OFFICIAL_SNAPSHOT_PATH,
) -> dict[str, Any]:
    """Load the captured official github-mcp-server v2.3.0 snapshot."""
    data: Any = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        raise ValueError(f"Invalid official GitHub snapshot: {snapshot_path}")
    return data


def load_official_snapshot_tools(
    read_only: bool = False,
    snapshot_path: Path = OFFICIAL_SNAPSHOT_PATH,
) -> tuple[list[types.Tool], dict[str, dict[str, Any]]]:
    """Build mcp.types.Tool list and raw definition index directly from official snapshot."""
    data = load_official_snapshot_raw(snapshot_path=snapshot_path)
    meta = data.get("_metadata", {})
    ro_names = set(meta.get("read_only_tool_names", []))

    tools: list[types.Tool] = []
    by_name: dict[str, dict[str, Any]] = {}
    for raw_tool in data["tools"]:
        name = raw_tool["name"]
        if read_only and name not in ro_names:
            continue
        tools.append(types.Tool.model_validate(raw_tool))
        by_name[name] = raw_tool
    return tools, by_name


def _validate_call_against_schema(
    name: str,
    args: dict[str, Any],
    raw_by_name: dict[str, dict[str, Any]],
) -> str | None:
    """Validate tool existence, required fields, and property keys against snapshot inputSchema."""
    tool_def = raw_by_name.get(name)
    if tool_def is None:
        return f"Unknown or disabled official tool: {name}"

    schema = tool_def.get("inputSchema") or {}
    allowed_props = set(schema.get("properties", {}).keys())
    unknown_keys = sorted(set(args.keys()) - allowed_props)
    if unknown_keys:
        return f"Unexpected argument(s) for '{name}': {', '.join(unknown_keys)}"

    required_keys = schema.get("required", [])
    missing_keys = [req for req in required_keys if req not in args or args[req] is None]
    if missing_keys:
        return f"Missing required argument(s) for '{name}': {', '.join(missing_keys)}"

    return None


def execute_official_github_call(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    read_only: bool = False,
    raw_by_name: dict[str, dict[str, Any]] | None = None,
) -> types.CallToolResult:
    """Evaluate a tool call against official snapshot schemas and return deterministic canned data."""
    if raw_by_name is None:
        _, raw_by_name = load_official_snapshot_tools(read_only=read_only)

    args = dict(arguments or {})
    err = _validate_call_against_schema(name, args, raw_by_name)
    if err is not None:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=err)],
            is_error=True,
        )

    if name == "issue_read":
        owner = str(args["owner"])
        repo = str(args["repo"])
        num = int(args["issue_number"])
        method = str(args["method"])
        if method == "get":
            issue = MOCK_ISSUES.get((owner, repo, num))
            if issue is not None:
                text = json.dumps(
                    {
                        "number": issue["number"],
                        "title": issue["title"],
                        "body": issue["body"],
                        "state": issue["state"],
                        "labels": issue["labels"],
                    }
                )
            else:
                text = json.dumps(
                    {
                        "number": num,
                        "title": f"Issue #{num} in {owner}/{repo}",
                        "body": f"Canned official issue_read body for {owner}/{repo}#{num}.",
                        "state": "open",
                        "labels": [],
                    }
                )
        else:
            text = json.dumps({"issue_number": num, "method": method, "items": []})
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    if name == "pull_request_read":
        owner = str(args["owner"])
        repo = str(args["repo"])
        num = int(args["pullNumber"])
        method = str(args["method"])
        if method == "get":
            pr = MOCK_PULL_REQUESTS.get((owner, repo, num))
            if pr is not None:
                text = json.dumps(pr)
            else:
                text = json.dumps(
                    {
                        "number": num,
                        "title": f"PR #{num} in {owner}/{repo}",
                        "body": f"Canned official pull_request_read body for {owner}/{repo}#{num}.",
                        "state": "open",
                    }
                )
        else:
            text = json.dumps({"pullNumber": num, "method": method, "items": []})
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    if name == "get_file_contents":
        owner = str(args["owner"])
        repo = str(args["repo"])
        path = str(args.get("path", "/"))
        if path in ("/", ""):
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(
                            [{"name": "README.md", "path": "README.md", "type": "file"}]
                        ),
                    )
                ]
            )
        file_text = MOCK_FILES.get(
            (owner, repo, path),
            f"# Canned file content for {owner}/{repo}:{path}",
        )
        return types.CallToolResult(content=[types.TextContent(type="text", text=file_text)])

    if name == "list_issues":
        owner = str(args["owner"])
        repo = str(args["repo"])
        items = [
            {"number": i["number"], "title": i["title"], "body": i["body"], "state": i["state"]}
            for (o, r, _), i in MOCK_ISSUES.items()
            if o == owner and r == repo
        ]
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(items))]
        )

    if name == "list_pull_requests":
        owner = str(args["owner"])
        repo = str(args["repo"])
        items = [p for (o, r, _), p in MOCK_PULL_REQUESTS.items() if o == owner and r == repo]
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(items))]
        )

    if name == "search_repositories":
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "total_count": 1,
                            "items": [{"full_name": "acme/repo", "query": args["query"]}],
                        }
                    ),
                )
            ]
        )

    if name == "add_issue_comment":
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "status": "ok",
                            "owner": args["owner"],
                            "repo": args["repo"],
                            "issue_number": args["issue_number"],
                        }
                    ),
                )
            ]
        )

    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps({"status": "ok", "tool": name}))]
    )


def create_fake_github_official_server(*, read_only: bool = False) -> Server:
    """Create a lowlevel MCP server replaying official github-mcp-server v2.3.0 schemas."""
    server = Server("fake-github-official-server")
    tools, raw_by_name = load_official_snapshot_tools(read_only=read_only)

    async def handle_list_tools(
        req_ctx: Any, params: types.PaginatedRequestParams
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tools)

    async def handle_call_tool(
        req_ctx: Any, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return execute_official_github_call(
            params.name,
            params.arguments,
            read_only=read_only,
            raw_by_name=raw_by_name,
        )

    server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)
    return server


async def run_stdio(*, read_only: bool = False) -> None:
    server = create_fake_github_official_server(read_only=read_only)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(description="Fake Official GitHub MCP Server (v2.3.0 schema)")
    parser.add_argument("--read-only", action="store_true", default=False)
    args = parser.parse_args()
    try:
        anyio.run(lambda: run_stdio(read_only=args.read_only))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
