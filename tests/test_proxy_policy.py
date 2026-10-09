"""Tests for proxy policy enforcement, audit mode, generic client responses,
and fault injection.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import anyio
import mcp.types as types
import pytest
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import parse_audit_event
from mcpsec_core.policy import load_policy
from proxy.session import ProxySession
from proxy.supervisor import UpstreamConfig, UpstreamManager, sanitize_upstream_env


@pytest.mark.integration
@pytest.mark.asyncio
async def test_proxy_policy_enforce_mode_blocks_and_returns_generic_message(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    allowed_file = sandbox / "allowed.txt"
    allowed_file.write_text("allowed content", encoding="utf-8")

    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("secret content", encoding="utf-8")

    policy_yaml = f"""
version: 1
mode: enforce
capabilities:
  fs.read_file: [read]
policies:
  - agent: dev-agent
    tools:
      fs.read_file:
        path_allowlist: ["{sandbox.as_posix()}/**"]
"""
    policy, p_hash, _ = load_policy(policy_yaml)

    audit_log = tmp_path / "audit.jsonl"
    audit_logger = AuditLogger(log_path=audit_log, log_args="redacted")

    upstream_config = UpstreamConfig(
        name="fs",
        command=sys.executable,
        args=["-m", "tests.test_server", "--dir", str(sandbox)],
        required=True,
    )
    upstream_manager = UpstreamManager([upstream_config])

    agent_c2s_w, agent_c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
    agent_s2c_w, agent_s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

    proxy_server = Server("mcpsec-proxy")

    async with anyio.create_task_group() as tg:
        await upstream_manager.start_all(tg)

        proxy_session = ProxySession(
            session_id="test-enforce-session",
            upstream_manager=upstream_manager,
            audit_logger=audit_logger,
            policy_hash=p_hash,
            agent_id="dev-agent",
            mode="enforce",
            policy_data=policy,
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

        async def run_proxy_srv() -> None:
            await proxy_server.run(
                agent_c2s_r,
                agent_s2c_w,
                proxy_server.create_initialization_options(),
                raise_exceptions=True,
            )

        tg.start_soon(run_proxy_srv)

        async with ClientSession(agent_s2c_r, agent_c2s_w) as client:
            await client.initialize()

            # 1. Allowed call: reading file in sandbox
            res_allowed = await client.call_tool("fs__read_file", {"path": str(allowed_file)})
            assert not res_allowed.is_error
            assert isinstance(res_allowed.content[0], types.TextContent)
            assert res_allowed.content[0].text == "allowed content"

            # 2. Denied call: traversal attempt
            res_denied = await client.call_tool("fs__read_file", {"path": str(secret_file)})
            assert res_denied.is_error
            # Generic message verification - no internal leak
            assert isinstance(res_denied.content[0], types.TextContent)
            assert res_denied.content[0].text == "Denied by mcpsec policy"

            proxy_session.close(reason="disconnect")
            await upstream_manager.shutdown_all()
            tg.cancel_scope.cancel()

    # Verify audit log details
    lines = audit_log.read_text(encoding="utf-8").strip().split("\n")
    events = [parse_audit_event(line) for line in lines]
    tool_events = [e for e in events if e.event_type == "tool_call"]
    assert len(tool_events) == 2

    allowed_ev = tool_events[0]
    assert allowed_ev.decision == "allow"
    assert allowed_ev.effective_decision == "forwarded"
    assert allowed_ev.decision_layer == "policy"
    assert allowed_ev.capabilities == ["read"]

    denied_ev = tool_events[1]
    assert denied_ev.decision == "deny"
    assert denied_ev.effective_decision == "blocked"
    assert denied_ev.decision_layer == "policy"
    assert "path not in allowlist" in denied_ev.decision_reason


@pytest.mark.asyncio
async def test_proxy_policy_audit_mode_logs_and_forwards(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    secret_file = sandbox / "outside.txt"
    secret_file.write_text("accessible in audit mode", encoding="utf-8")

    # Policy denies everything (empty allowlist)
    policy_yaml = """
version: 1
mode: audit
capabilities:
  fs.read_file: [read]
policies:
  - agent: dev-agent
    tools:
      fs.read_file:
        path_allowlist: ["/nonexistent/**"]
"""
    policy, p_hash, _ = load_policy(policy_yaml)
    audit_log = tmp_path / "audit_auditmode.jsonl"
    audit_logger = AuditLogger(log_path=audit_log)

    upstream_mock = AsyncMock(spec=UpstreamManager)
    upstream_mock.servers = {"fs": AsyncMock(is_healthy=True)}
    upstream_mock.call_tool.return_value = types.CallToolResult(
        content=[types.TextContent(type="text", text="forwarded despite deny")],
        is_error=False,
    )

    proxy_session = ProxySession(
        session_id="test-audit-mode",
        upstream_manager=upstream_mock,
        audit_logger=audit_logger,
        policy_hash=p_hash,
        agent_id="dev-agent",
        mode="audit",
        policy_data=policy,
    )

    res = await proxy_session.call_tool("fs__read_file", {"path": str(secret_file)})
    assert not res.is_error
    assert isinstance(res.content[0], types.TextContent)
    assert res.content[0].text == "forwarded despite deny"

    # Verify audit log recorded decision: deny, effective_decision: forwarded
    lines = audit_log.read_text(encoding="utf-8").strip().split("\n")
    events = [parse_audit_event(line) for line in lines]
    tool_events = [e for e in events if e.event_type == "tool_call"]
    assert len(tool_events) == 1
    assert tool_events[0].decision == "deny"
    assert tool_events[0].effective_decision == "forwarded"
    assert tool_events[0].decision_layer == "policy"


@pytest.mark.asyncio
async def test_fault_injection_fails_closed(tmp_path: Path) -> None:
    audit_log = tmp_path / "fault_audit.jsonl"
    audit_logger = AuditLogger(log_path=audit_log)

    upstream_mock = AsyncMock(spec=UpstreamManager)
    upstream_mock.servers = {"fs": AsyncMock(is_healthy=True)}

    proxy_session = ProxySession(
        session_id="fault-sess",
        upstream_manager=upstream_mock,
        audit_logger=audit_logger,
        agent_id="dev-agent",
        mode="enforce",
        policy_data="not-a-valid-policy-object",  # Will cause exception in check_policy
    )

    with patch("proxy.session.check_policy", side_effect=RuntimeError("Injected failure")):
        res = await proxy_session.call_tool("fs__read_file", {"path": "dummy.txt"})
        assert res.is_error
        assert isinstance(res.content[0], types.TextContent)
        assert res.content[0].text == "Denied by mcpsec policy"
        # Upstream must never have been called
        upstream_mock.call_tool.assert_not_called()

    lines = audit_log.read_text(encoding="utf-8").strip().split("\n")
    events = [parse_audit_event(line) for line in lines]
    tool_events = [e for e in events if e.event_type == "tool_call"]
    assert len(tool_events) == 1
    assert tool_events[0].decision == "deny"
    assert tool_events[0].effective_decision == "blocked"
    assert "internal error: RuntimeError" in tool_events[0].decision_reason


def test_sanitize_upstream_env() -> None:
    with patch.dict(
        "os.environ", {"SECRET_TOKEN": "super_secret_123", "PATH": "/usr/bin"}, clear=True
    ):
        clean_env = sanitize_upstream_env({"CUSTOM_VAR": "custom_val"})
        assert "SECRET_TOKEN" not in clean_env
        assert clean_env.get("CUSTOM_VAR") == "custom_val"
        assert "PATH" in clean_env
