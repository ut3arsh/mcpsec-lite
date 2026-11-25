"""Tests for fake_github_official, C7.yaml pre-registration, and github_official_map.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import anyio
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.adapters import OFFICIAL_GITHUB_TOOL_TABLE
from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import ToolCall
from mcpsec_core.policy import check_policy, load_policy_file
from proxy.session import ProxySession
from proxy.supervisor import UpstreamConfig, UpstreamManager
from tests.fakes.fake_github_official import (
    OFFICIAL_SNAPSHOT_PATH,
    execute_official_github_call,
    load_official_snapshot_raw,
    load_official_snapshot_tools,
)


def test_c7_policy_and_official_map_pre_registration() -> None:
    """Validate C7.yaml allowlist minimal posture, all 19 U taint_sources, and map validity."""
    pol, _, _ = load_policy_file(Path("benchmark/configs/C7.yaml"))
    c6, _, _ = load_policy_file(Path("benchmark/configs/C6.yaml"))

    assert pol.mode == c6.mode
    assert pol.serialize_calls == c6.serialize_calls
    assert pol.pinning == c6.pinning
    assert pol.flow_rules == c6.flow_rules
    assert pol.approval == c6.approval

    # C7 allowlist allows only the 4 official GitHub tools needed by dev scenarios
    c7_gh_tools = {t for t in pol.agent_rules["*"] if t.startswith("github.")}
    assert c7_gh_tools == {
        "github.issue_read",
        "github.list_issues",
        "github.search_repositories",
        "github.add_issue_comment",
    }

    # Unknown / extra official / handwritten GitHub tools are default-denied
    for denied_tool in (
        "get_issue",
        "get_pull_request",
        "create_issue_comment",
        "pull_request_read",
        "get_file_contents",
        "delete_file",
        "merge_pull_request",
        "actions_list",
    ):
        call = ToolCall(
            call_id="c-1",
            session_id="s-1",
            agent_id="dev-agent",
            server="github",
            tool=denied_tool,
            args={},
        )
        decision = check_policy(call, pol)
        assert decision.decision == "deny", f"Expected default-deny for github.{denied_tool}"

    # C7 taint_sources.untrusted_content includes all 19 U tools in OFFICIAL_GITHUB_TOOL_TABLE
    expected_u_tools = {
        spec.tool_id for spec in OFFICIAL_GITHUB_TOOL_TABLE.values() if spec.taint_class == "U"
    }
    assert len(expected_u_tools) == 19
    assert "github.issue_read" in expected_u_tools
    assert "github.pull_request_read" in expected_u_tools

    c7_untrusted_tools = {e.tool for e in pol.taint_sources["untrusted_content"]}
    assert expected_u_tools.issubset(c7_untrusted_tools)

    # Map file validates strictly against official snapshot tool names and inputSchema properties
    snap = load_official_snapshot_raw()
    snap_by_name = {t["name"]: t for t in snap["tools"]}
    map_data = json.loads(Path("benchmark/github_official_map.json").read_text(encoding="utf-8"))
    for hw_tool, entry in map_data["tools"].items():
        off_tool = entry["official_tool"]
        assert off_tool in snap_by_name, f"{hw_tool} maps to unknown official tool {off_tool}"
        off_props = set(snap_by_name[off_tool]["inputSchema"]["properties"].keys())
        off_req = set(snap_by_name[off_tool]["inputSchema"].get("required", []))

        arg_map = entry["arg_map"]
        fixed_args = entry.get("fixed_args", {})
        mapped_targets = set(arg_map.values()) | set(fixed_args.keys())
        assert mapped_targets.issubset(off_props), (
            f"Map for {hw_tool} -> {off_tool} emits non-snapshot args {mapped_targets - off_props}"
        )
        # Ensure required fixed params (e.g. method="get") or mapped inputs cover required schema
        assert off_req.issubset(mapped_targets), (
            f"Map for {hw_tool} -> {off_tool} leaves required args uncovered: {off_req - mapped_targets}"
        )


def test_fake_github_official_schema_replay_and_validation() -> None:
    """Fake official server replays exact snapshot schemas, read-only filter, and arg validation."""
    raw = load_official_snapshot_raw(OFFICIAL_SNAPSHOT_PATH)
    tools_full, _ = load_official_snapshot_tools(read_only=False)
    tools_ro, _ = load_official_snapshot_tools(read_only=True)

    assert len(tools_full) == 46
    assert len(tools_ro) == 27
    assert [t.name for t in tools_full] == [t["name"] for t in raw["tools"]]
    for t_obj, t_raw in zip(tools_full, raw["tools"], strict=True):
        assert t_obj.description == t_raw["description"]
        assert t_obj.input_schema == t_raw["inputSchema"]

    res_ok = execute_official_github_call(
        "issue_read", {"owner": "acme", "repo": "repo", "issue_number": 1, "method": "get"}
    )
    assert not res_ok.is_error
    assert isinstance(res_ok.content[0], types.TextContent)
    assert "Bug in login flow" in res_ok.content[0].text

    res_missing_req = execute_official_github_call(
        "issue_read", {"owner": "acme", "repo": "repo", "issue_number": 1}
    )
    assert res_missing_req.is_error

    res_ro_write = execute_official_github_call(
        "add_issue_comment",
        {"owner": "acme", "repo": "repo", "issue_number": 1, "body": "hi"},
        read_only=True,
    )
    assert res_ro_write.is_error


@pytest.mark.asyncio
async def test_fake_github_official_stdio_end_to_end(tmp_path: Path) -> None:
    """Exercise fake_github_official over real stdio transport through ProxySession."""
    audit_log = tmp_path / "audit.jsonl"
    audit_logger = AuditLogger(log_path=audit_log)
    configs = [
        UpstreamConfig(
            name="github",
            command=sys.executable,
            args=["-m", "tests.fakes.fake_github_official"],
            required=True,
        )
    ]
    manager = UpstreamManager(configs)
    proxy_session = ProxySession(
        session_id="official-stdio-test",
        upstream_manager=manager,
        audit_logger=audit_logger,
        agent_id="dev-agent",
        mode="audit",
    )
    proxy_session.start()

    proxy_server = Server("mcpsec-proxy-test")
    proxy_server.add_request_handler(
        "tools/list",
        types.PaginatedRequestParams,
        lambda _ctx, _p: proxy_session.list_tools(),
    )
    proxy_server.add_request_handler(
        "tools/call",
        types.CallToolRequestParams,
        lambda _ctx, p: proxy_session.call_tool(name=p.name, arguments=p.arguments),
    )

    c2s_w, c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
    s2c_w, s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

    async with anyio.create_task_group() as tg:
        warnings = await manager.start_all(tg)
        assert len(warnings) == 0

        async def _serve() -> None:
            await proxy_server.run(
                c2s_r,
                s2c_w,
                proxy_server.create_initialization_options(),
                raise_exceptions=True,
            )

        tg.start_soon(_serve)
        async with ClientSession(s2c_r, c2s_w) as client:
            await client.initialize()
            listed = await client.list_tools()
            names = {t.name for t in listed.tools}
            assert len(names) == 46
            assert "github__issue_read" in names
            assert "github__add_issue_comment" in names
            assert "github__get_issue" not in names

            res = await client.call_tool(
                "github__issue_read",
                {"owner": "org", "repo": "app", "issue_number": 99, "method": "get"},
            )
            assert not res.is_error
            assert isinstance(res.content[0], types.TextContent)
            assert "CTX_SUMMARY_MARKER" in res.content[0].text

            proxy_session.close(reason="disconnect")
            await manager.shutdown_all()
            tg.cancel_scope.cancel()
