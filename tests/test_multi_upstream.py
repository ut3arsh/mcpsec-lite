"""Tests for multi-upstream MCP proxy aggregation, namespacing, and graceful degradation."""

from __future__ import annotations

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
from mcpsec_core.policy import PolicyError, load_policy
from proxy.session import ProxySession
from proxy.supervisor import UpstreamConfig, UpstreamManager


@pytest.mark.asyncio
async def test_multi_upstream_aggregation_and_routing(tmp_path: Path) -> None:
    """Test proxy with 3 upstreams: filesystem, fake fetch, and fake github."""
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    test_file = sandbox_dir / "test_data.txt"
    test_file.write_text("Confidential project data", encoding="utf-8")

    audit_log = tmp_path / "audit.jsonl"
    audit_logger = AuditLogger(log_path=audit_log, log_args="redacted")

    configs = [
        UpstreamConfig(
            name="fs",
            command="python",
            args=["-m", "tests.test_server", "--dir", str(sandbox_dir)],
            required=True,
        ),
        UpstreamConfig(
            name="fetch",
            command="python",
            args=["-m", "tests.fakes.fake_fetch"],
            required=False,
        ),
        UpstreamConfig(
            name="github",
            command="python",
            args=["-m", "tests.fakes.fake_github"],
            env={"GITHUB_READ_ONLY": "true"},
            required=False,
        ),
    ]

    manager = UpstreamManager(configs)

    proxy_session = ProxySession(
        session_id="multi-upstream-session-1",
        upstream_manager=manager,
        audit_logger=audit_logger,
        policy_hash="policy-hash-1",
        agent_id="dev-agent",
        mode="enforce",
    )
    proxy_session.start()

    proxy_server = Server("mcpsec-proxy")

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

    proxy_server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list_tools)
    proxy_server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call_tool)

    c2s_w, c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
    s2c_w, s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

    async with anyio.create_task_group() as tg:
        # Start all upstreams in task group
        startup_warnings = await manager.start_all(tg)
        assert len(startup_warnings) == 0

        async def run_proxy() -> None:
            await proxy_server.run(
                c2s_r,
                s2c_w,
                proxy_server.create_initialization_options(),
                raise_exceptions=True,
            )

        tg.start_soon(run_proxy)

        async with ClientSession(s2c_r, c2s_w) as client:
            await client.initialize()

            # 1. tools/list returns deterministic union of all 3 upstreams
            tools_res = await client.list_tools()
            tool_names = [t.name for t in tools_res.tools]

            # Assert deterministic alphabetical sorting
            assert tool_names == sorted(tool_names)

            # Check namespaced tools exist
            assert "fs__read_file" in tool_names
            assert "fs__write_file" in tool_names
            assert "fetch__fetch" in tool_names
            assert "github__get_issue" in tool_names
            assert "github__get_pull_request" in tool_names

            # 2. Call tool on GitHub upstream
            gh_res = await client.call_tool(
                "github__get_issue",
                {"owner": "acme", "repo": "repo", "issue_number": 1},
            )
            assert not gh_res.is_error
            assert isinstance(gh_res.content[0], types.TextContent)
            assert "Bug in login flow" in gh_res.content[0].text

            # 3. Call tool on Filesystem upstream
            fs_res = await client.call_tool(
                "fs__read_file",
                {"path": "test_data.txt"},
            )
            assert not fs_res.is_error
            assert isinstance(fs_res.content[0], types.TextContent)
            assert "Confidential project data" in fs_res.content[0].text

            # 4. Call tool on Fetch upstream
            fetch_res = await client.call_tool(
                "fetch__fetch",
                {"url": "https://api.github.com/repos/acme/repo"},
            )
            assert not fetch_res.is_error
            assert isinstance(fetch_res.content[0], types.TextContent)
            assert "acme" in fetch_res.content[0].text

            # 5. Call unknown tool prefix -> Denied with ERR_UNKNOWN_TOOL
            unknown_res = await client.call_tool(
                "unknownserver__some_tool",
                {"arg": "val"},
            )
            assert unknown_res.is_error
            assert isinstance(unknown_res.content[0], types.TextContent)
            assert "Denied by mcpsec policy" in unknown_res.content[0].text

            # Verify single SessionState tracked across all calls
            assert proxy_session.session_state.call_count == 4
            assert proxy_session.session_state.deny_count == 1

            proxy_session.close(reason="disconnect")
            await manager.shutdown_all()
            tg.cancel_scope.cancel()

    # Verify audit log records distinct servers and tools
    assert audit_log.exists()
    lines = audit_log.read_text(encoding="utf-8").strip().split("\n")
    events = [parse_audit_event(line) for line in lines]
    tool_events = [e for e in events if e.event_type == "tool_call"]
    assert len(tool_events) == 4

    servers_recorded = [e.server for e in tool_events]
    assert servers_recorded == ["github", "fs", "fetch", "unknownserver"]


@pytest.mark.asyncio
async def test_non_required_upstream_degradation(tmp_path: Path) -> None:
    """Test that a failing non-required upstream degrades gracefully without crashing proxy."""
    configs = [
        UpstreamConfig(
            name="fs",
            command="python",
            args=["-m", "tests.test_server", "--dir", str(tmp_path)],
            required=True,
        ),
        UpstreamConfig(
            name="nonexistent",
            command="python",
            args=["-m", "nonexistent_module_that_fails_immediately"],
            required=False,
        ),
    ]

    manager = UpstreamManager(configs)
    async with anyio.create_task_group() as tg:
        startup_warnings = await manager.start_all(tg)

        # Non-required server failed to start, warning captured
        assert len(startup_warnings) == 1
        assert "nonexistent" in startup_warnings[0]

        # Healthy server's tools are still exposed
        tools = manager.list_all_tools()
        tool_names = [t.name for t in tools]
        assert "fs__read_file" in tool_names
        assert not any(n.startswith("nonexistent__") for n in tool_names)

        await manager.shutdown_all()
        tg.cancel_scope.cancel()


def test_unenforced_policy_guard_fails_closed_in_enforce_mode() -> None:
    """Test that policy with flow_rules/taint_sources/strict pinning refuses to start in enforce mode."""
    yaml_enforce = """
version: 1
mode: enforce
capabilities:
  fs.read_file: [read]
policies:
  - agent: "*"
    tools:
      fs.read_file: {}
taint_sources:
  untrusted_content:
    - tool: fs.read_file
flow_rules:
  - id: rule-1
    if_session_has: [untrusted_content]
    deny_capabilities: [read]
"""
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml_enforce, check_unenforced_guards=True)
    assert any(e["code"] == "ERR_NOT_YET_ENFORCED" for e in exc_info.value.errors)


def test_unenforced_policy_allowed_with_warning_in_audit_mode() -> None:
    """Test that policy with flow_rules/taint_sources starts with warning in audit mode."""
    yaml_audit = """
version: 1
mode: audit
capabilities:
  fs.read_file: [read]
policies:
  - agent: "*"
    tools:
      fs.read_file: {}
taint_sources:
  untrusted_content:
    - tool: fs.read_file
flow_rules:
  - id: rule-1
    if_session_has: [untrusted_content]
    deny_capabilities: [read]
"""
    policy, p_hash, warnings = load_policy(yaml_audit, check_unenforced_guards=True)
    assert policy.mode == "audit"
    assert any("not yet enforced in Week 3" in w for w in warnings)
