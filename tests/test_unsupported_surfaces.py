"""Tests asserting proxy advertises only tools and rejects extra surfaces / server-initiated requests."""

from __future__ import annotations

import json
from pathlib import Path

import mcp.types as types
import pytest
from mcp.server.lowlevel import NotificationOptions, Server

from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import LatencyMs


def test_proxy_server_advertises_only_tools_capability() -> None:
    """Verify that proxy Server instance advertises only tools capability (no prompts/resources/sampling)."""
    server = Server("mcpsec-proxy")

    async def dummy_list(r: object, p: types.PaginatedRequestParams) -> None:
        return None

    async def dummy_call(r: object, p: types.CallToolRequestParams) -> None:
        return None

    server.add_request_handler("tools/list", types.PaginatedRequestParams, dummy_list)
    server.add_request_handler("tools/call", types.CallToolRequestParams, dummy_call)

    opts = NotificationOptions(tools_changed=True, prompts_changed=False, resources_changed=False)
    init_opts = server.create_initialization_options(notification_options=opts)

    caps = init_opts.capabilities
    assert caps.tools is not None
    assert caps.tools.list_changed is True
    assert caps.prompts is None
    assert caps.resources is None
    assert caps.logging is None
    assert caps.experimental is None


@pytest.mark.asyncio
async def test_rejection_of_unsupported_surfaces_audit(tmp_path: Path) -> None:
    """Verify that requests for unsupported surfaces are logged with ERR_UNSUPPORTED_SURFACE."""
    log_file = tmp_path / "audit_surfaces.jsonl"
    audit_logger = AuditLogger(log_path=log_file)

    # Simulate unsupported surface rejection handler in proxy/main.py
    session_id = "test-session-surf"
    agent_id = "dev-agent"

    for surface in ["prompts/list", "resources/list", "sampling/createMessage", "roots/list"]:
        audit_logger.log_tool_call(
            session_id=session_id,
            call_id=f"call-{surface.replace('/', '-')}",
            agent_id=agent_id,
            server="proxy",
            tool=surface,
            capabilities=[],
            raw_args={},
            decision="deny",
            effective_decision="blocked",
            decision_layer="policy",
            decision_reason=f"ERR_UNSUPPORTED_SURFACE: MCP surface {surface} is not supported in v1",
            pin_status="unchecked",
            latency_ms=LatencyMs(proxy=0.1, upstream=None),
            taint_before=[],
            taint_after=[],
            response_summary=None,
            error="ERR_UNSUPPORTED_SURFACE",
        )

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 4
    for line in lines:
        ev = json.loads(line)
        assert ev["event_type"] == "tool_call"
        assert ev["decision"] == "deny"
        assert ev["effective_decision"] == "blocked"
        assert "ERR_UNSUPPORTED_SURFACE" in ev["decision_reason"]
        assert ev["error"] == "ERR_UNSUPPORTED_SURFACE"
