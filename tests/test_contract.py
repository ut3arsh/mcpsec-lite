"""Contract tests validating adapter schemas against committed snapshot fixtures and live servers."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcpsec_core.adapters import get_adapter

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_tool_fixture(server_name: str) -> list[dict[str, Any]]:
    """Load committed tool snapshot fixture for a server."""
    fixture_path = FIXTURES_DIR / f"{server_name}.tools.json"
    assert fixture_path.exists(), f"Missing fixture file: {fixture_path}"
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list)
    return data


def test_filesystem_adapter_conformance_with_snapshot() -> None:
    """Validate that filesystem adapters match the snapshot schema."""
    tools = load_tool_fixture("filesystem")
    assert len(tools) > 0

    for tool in tools:
        tool_name = tool["name"]
        adapter_fs = get_adapter(f"fs.{tool_name}")
        adapter_filesystem = get_adapter(f"filesystem.{tool_name}")

        assert adapter_fs is not None, f"Missing adapter for fs.{tool_name}"
        assert adapter_filesystem is not None, f"Missing adapter for filesystem.{tool_name}"

        # Verify all properties in inputSchema are declared in adapter.all_args
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        props = set(schema.get("properties", {}).keys())
        assert props.issubset(adapter_fs.all_args), (
            f"Adapter fs.{tool_name} all_args ({adapter_fs.all_args}) missing props ({props})"
        )


def test_fetch_adapter_conformance_with_snapshot() -> None:
    """Validate that fetch adapter matches the snapshot schema."""
    tools = load_tool_fixture("fetch")
    assert len(tools) == 1
    tool = tools[0]
    assert tool["name"] == "fetch"

    adapter = get_adapter("fetch.fetch")
    assert adapter is not None
    assert adapter.domain_args == ("url",)

    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    props = set(schema.get("properties", {}).keys())
    assert props.issubset(adapter.all_args)


def test_github_adapter_conformance_with_snapshot() -> None:
    """Validate that github adapters match the snapshot schema."""
    tools = load_tool_fixture("github")
    assert len(tools) > 0

    for tool in tools:
        tool_name = tool["name"]
        adapter = get_adapter(f"github.{tool_name}")
        assert adapter is not None, f"Missing adapter for github.{tool_name}"

        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        props = set(schema.get("properties", {}).keys())
        assert props.issubset(adapter.all_args), (
            f"Adapter github.{tool_name} all_args missing schema props ({props})"
        )


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_filesystem_contract_vs_snapshot(tmp_path: Path) -> None:
    """Live contract test comparing live filesystem server to snapshot fixture."""
    if not os.environ.get("RUN_LIVE_CONTRACT_TESTS"):
        pytest.skip("Opt-in live contract test (set RUN_LIVE_CONTRACT_TESTS=1)")

    npx_bin = shutil.which("npx.cmd") if os.name == "nt" else shutil.which("npx")
    if not npx_bin:
        pytest.skip("npx not available for live contract test")

    params = StdioServerParameters(
        command=npx_bin,
        args=["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)],
    )

    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            live_tools = await session.list_tools()
            live_names = {t.name for t in live_tools.tools}

            snapshot_tools = load_tool_fixture("filesystem")
            snapshot_names = {t["name"] for t in snapshot_tools}

            assert live_names == snapshot_names
