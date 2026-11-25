"""Contract tests validating adapter schemas against committed snapshot fixtures and live servers."""

from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcpsec_core.adapters import (
    _BUILTIN_ADAPTERS,
    OFFICIAL_GITHUB_TOOL_TABLE,
    OfficialGitHubToolSpec,
    get_adapter,
    get_official_github_tool_spec,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_tool_fixture(server_name: str) -> list[dict[str, Any]]:
    """Load committed tool snapshot fixture for a server."""
    fixture_path = FIXTURES_DIR / f"{server_name}.tools.json"
    assert fixture_path.exists(), f"Missing fixture file: {fixture_path}"
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list)
    return data


def load_fixture_meta(server_name: str) -> dict[str, Any]:
    """Load metadata sidecar fixture for a server."""
    meta_path = FIXTURES_DIR / f"{server_name}.tools.meta.json"
    if not meta_path.exists():
        return {"verified": False, "status": "UNKNOWN"}
    with open(meta_path, encoding="utf-8") as f:
        data: Any = json.load(f)
        if isinstance(data, dict):
            return dict(data)
        return {"verified": False, "status": "UNKNOWN"}


def test_filesystem_adapter_conformance_with_snapshot() -> None:
    """Validate that filesystem adapters match the snapshot schema."""
    meta = load_fixture_meta("filesystem")
    assert meta.get("verified") is True, f"Filesystem fixture must be verified: {meta}"

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
    meta = load_fixture_meta("fetch")
    assert meta.get("verified") is True, f"Fetch fixture must be verified: {meta}"

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


def _assert_official_table_matches_snapshot(
    table: dict[str, OfficialGitHubToolSpec],
    snapshot_data: dict[str, Any],
    check_builtin_adapters: bool = False,
) -> None:
    """Assert bidirectional exact equality between reviewed static table and official snapshot."""
    snap_tools_list = snapshot_data.get("tools", [])
    assert isinstance(snap_tools_list, list) and len(snap_tools_list) > 0
    snap_by_name = {t["name"]: t for t in snap_tools_list}
    meta = snapshot_data.get("_metadata", {})
    ro_names = set(meta.get("read_only_tool_names", []))

    table_names = set(table.keys())
    snap_names = set(snap_by_name.keys())
    assert table_names == snap_names, (
        f"Official GitHub table vs snapshot tool set mismatch: "
        f"missing_in_table={sorted(snap_names - table_names)}, "
        f"extra_in_table={sorted(table_names - snap_names)}"
    )

    if check_builtin_adapters:
        builtin_gh_ids = {tid for tid in _BUILTIN_ADAPTERS if tid.startswith("github.")}
        expected_gh_ids = {f"github.{n}" for n in snap_names}
        assert builtin_gh_ids == expected_gh_ids, (
            f"_BUILTIN_ADAPTERS github.* mismatch: "
            f"missing={sorted(expected_gh_ids - builtin_gh_ids)}, "
            f"extra={sorted(builtin_gh_ids - expected_gh_ids)}"
        )

    for tool_name, tool_def in snap_by_name.items():
        spec = table[tool_name]
        assert spec.tool_id == f"github.{tool_name}"
        assert spec.adapter.tool_id == spec.tool_id

        schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
        snap_props = set(schema.get("properties", {}).keys())
        assert set(spec.adapter.all_args) == snap_props, (
            f"Official GitHub tool '{tool_name}' arg mismatch: "
            f"missing_in_table={sorted(snap_props - spec.adapter.all_args)}, "
            f"extra_in_table={sorted(spec.adapter.all_args - snap_props)}"
        )
        assert spec.read_only == (tool_name in ro_names), (
            f"read_only flag mismatch for '{tool_name}'"
        )
        assert set(spec.capabilities).issubset({"read", "write", "network_read", "egress", "exec"})
        assert spec.taint_class in {"U", "P", "T"}

        if check_builtin_adapters:
            reg_adapter = get_adapter(spec.tool_id)
            assert reg_adapter == spec.adapter


def test_github_handwritten_fixture_labeled_benchmark_mock() -> None:
    """Handwritten 8-tool GitHub fixture must remain clearly labeled as an unverified benchmark mock."""
    meta = load_fixture_meta("github")
    assert meta.get("verified") is False
    assert meta.get("status") == "UNVERIFIED-handwritten"
    assert "benchmark mock" in str(meta.get("role", "")).lower()

    mock_tools = load_tool_fixture("github")
    assert len(mock_tools) == 8


def test_github_official_adapter_and_table_conformance_with_snapshot() -> None:
    """Offline CI contract test: reviewed static table == official v2.3.0 snapshot in both directions."""
    official_path = FIXTURES_DIR / "github.tools.official.json"
    assert official_path.exists(), f"Missing official GitHub snapshot: {official_path}"
    snapshot_data: dict[str, Any] = json.loads(official_path.read_text(encoding="utf-8"))

    meta = snapshot_data.get("_metadata", {})
    assert meta.get("verification_status") == "VERIFIED-official-github-mcp-server"
    assert meta.get("version") == "2.3.0"
    assert len(snapshot_data.get("tools", [])) == 46

    # 1. Bidirectional equality between OFFICIAL_GITHUB_TOOL_TABLE / _BUILTIN_ADAPTERS and snapshot
    _assert_official_table_matches_snapshot(
        OFFICIAL_GITHUB_TOOL_TABLE,
        snapshot_data,
        check_builtin_adapters=True,
    )

    # 2. Capabilities and U/P/T taint class match docs/github_tool_mapping.md verbatim
    mapping_doc = Path(__file__).parent.parent / "docs" / "github_tool_mapping.md"
    doc_text = mapping_doc.read_text(encoding="utf-8")
    parsed_doc_rows: dict[str, tuple[tuple[str, ...], str]] = {}
    for line in doc_text.splitlines():
        if line.startswith("| `") and "--read-only" not in line:
            parts = [p.strip() for p in line.strip("|").split("|")]
            if len(parts) >= 5:
                t_name = parts[0].strip("`")
                caps = tuple(c.strip() for c in parts[3].strip("`[] ").split(",") if c.strip())
                taint = parts[4].strip("*` ")
                parsed_doc_rows[t_name] = (caps, taint)

    assert set(parsed_doc_rows.keys()) == set(OFFICIAL_GITHUB_TOOL_TABLE.keys())
    for t_name, (doc_caps, doc_taint) in parsed_doc_rows.items():
        spec = get_official_github_tool_spec(t_name)
        assert spec is not None
        assert spec.capabilities == doc_caps, f"Capabilities drift vs mapping doc for {t_name}"
        assert spec.taint_class == doc_taint, f"Taint class drift vs mapping doc for {t_name}"

    # 3. Unknown / non-official tools stay unknown (None -> fail-closed default deny)
    assert get_official_github_tool_spec("get_issue") is None
    assert get_adapter("github.get_issue") is None
    assert get_adapter("github.create_issue_comment") is None
    assert get_adapter("github.unlisted_workflow_tool") is None

    # 4. Contract test must fail if the snapshot changes (tool or arg added/removed)
    added_tool_snap = copy.deepcopy(snapshot_data)
    added_tool_snap["tools"].append(
        {"name": "new_snapshot_tool", "inputSchema": {"type": "object", "properties": {"x": {}}}}
    )
    with pytest.raises(AssertionError, match="missing_in_table"):
        _assert_official_table_matches_snapshot(OFFICIAL_GITHUB_TOOL_TABLE, added_tool_snap)

    removed_tool_snap = copy.deepcopy(snapshot_data)
    removed_tool_snap["tools"] = [
        t for t in removed_tool_snap["tools"] if t["name"] != "issue_read"
    ]
    with pytest.raises(AssertionError, match="extra_in_table"):
        _assert_official_table_matches_snapshot(OFFICIAL_GITHUB_TOOL_TABLE, removed_tool_snap)

    added_arg_snap = copy.deepcopy(snapshot_data)
    for t in added_arg_snap["tools"]:
        if t["name"] == "issue_read":
            t["inputSchema"]["properties"]["unexpected_new_param"] = {"type": "string"}
    with pytest.raises(AssertionError, match="missing_in_table"):
        _assert_official_table_matches_snapshot(OFFICIAL_GITHUB_TOOL_TABLE, added_arg_snap)

    removed_arg_snap = copy.deepcopy(snapshot_data)
    for t in removed_arg_snap["tools"]:
        if t["name"] == "issue_read":
            del t["inputSchema"]["properties"]["perPage"]
    with pytest.raises(AssertionError, match="extra_in_table"):
        _assert_official_table_matches_snapshot(OFFICIAL_GITHUB_TOOL_TABLE, removed_arg_snap)


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


@pytest.mark.live
@pytest.mark.asyncio
async def test_live_fetch_contract_vs_snapshot() -> None:
    """Live contract test comparing live fetch server to snapshot fixture."""
    if not os.environ.get("RUN_LIVE_CONTRACT_TESTS"):
        pytest.skip("Opt-in live contract test (set RUN_LIVE_CONTRACT_TESTS=1)")

    uvx_bin = shutil.which("uvx.cmd") if os.name == "nt" else shutil.which("uvx")
    if not uvx_bin:
        pytest.skip("uvx not available for live fetch contract test")

    params = StdioServerParameters(
        command=uvx_bin,
        args=["mcp-server-fetch"],
    )

    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            live_tools = await session.list_tools()
            live_names = {t.name for t in live_tools.tools}

            snapshot_tools = load_tool_fixture("fetch")
            snapshot_names = {t["name"] for t in snapshot_tools}

            assert live_names == snapshot_names
