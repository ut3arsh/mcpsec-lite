"""Behavior-driven tests for edge and boundary branches in mcpsec_core modules."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from mcpsec_core.approvals import ApprovalManager
from mcpsec_core.detectors import _extract_text_from_mcp_content
from mcpsec_core.flow import check_flow
from mcpsec_core.matching import (
    DomainSecurityError,
    compile_domain_pattern,
    normalize_domain_or_url,
)
from mcpsec_core.models import (
    parse_audit_event,
)
from mcpsec_core.pinning import PinStore
from mcpsec_core.policy import (
    CompiledFlowRule,
)


def test_domain_matching_edge_cases() -> None:
    """Validate domain normalization and compilation error branches."""
    # 1. Empty host after stripping trailing dot
    with pytest.raises(DomainSecurityError, match="empty after stripping"):
        normalize_domain_or_url(".")

    # 2. Pattern is not string
    with pytest.raises(DomainSecurityError, match="must be a string"):
        compile_domain_pattern(12345)  # type: ignore[arg-type]

    # 3. Trailing dot in domain pattern stripped
    raw, is_wild, regex = compile_domain_pattern("api.github.com.")
    assert raw == "api.github.com"
    assert not is_wild
    assert regex is None

    # 4. Wildcard pattern with empty suffix (e.g. '*..' -> '*.' with empty suffix)
    with pytest.raises(DomainSecurityError, match="empty suffix"):
        compile_domain_pattern("*..")

    # 5. Wildcard pattern targeting IP literal
    with pytest.raises(DomainSecurityError, match="cannot target an IP literal"):
        compile_domain_pattern("*.192.168.1.1")


def test_audit_event_schema_validation_errors() -> None:
    """Validate parse_audit_event error branches."""
    # Unsupported schema version
    with pytest.raises(ValueError, match="Unsupported schema_version: 99"):
        parse_audit_event(json.dumps({"schema_version": 99, "event_type": "tool_call"}))

    # Unknown event type
    with pytest.raises(ValueError, match="Unknown event_type: imaginary_event"):
        parse_audit_event(json.dumps({"schema_version": 1, "event_type": "imaginary_event"}))


def test_detector_extraction_resource_shapes() -> None:
    """Validate _extract_text_from_mcp_content over embedded and dict resource shapes."""
    # 1. Mock item with .resource as a dict containing 'blob'
    mock_obj = Mock(spec=["resource"])
    mock_obj.resource = {"blob": "VGhpcyBpcyBhIHRlc3Q="}
    assert _extract_text_from_mcp_content(mock_obj) == "VGhpcyBpcyBhIHRlc3Q="

    # 2. Dict item with 'resource' containing 'blob'
    dict_blob = {"resource": {"blob": "U2VjcmV0VG9rZW4="}}
    assert _extract_text_from_mcp_content(dict_blob) == "U2VjcmV0VG9rZW4="

    # 3. Dict item with 'resource' containing 'text'
    dict_text = {"resource": {"text": "plain resource text"}}
    assert _extract_text_from_mcp_content(dict_text) == "plain resource text"


def test_approval_manager_edge_branches(tmp_path: Path) -> None:
    """Validate ApprovalManager get_approval None, callable listener, and timeout transition."""
    mgr = ApprovalManager(log_path=tmp_path / "approvals.jsonl")

    # 1. get_approval on nonexistent call_id returns None
    assert mgr.get_approval("nonexistent-call") is None

    # 2. _notify_listener with callable callback without .set attribute
    called = False

    def plain_callable() -> None:
        nonlocal called
        called = True

    mgr.register_listener("call-callable", plain_callable)
    mgr._notify_listener("call-callable")
    assert called
    mgr.unregister_listener("call-callable")

    # 3. _apply_event_to_state with timeout
    mgr.request_approval(
        call_id="call-timeout",
        session_id="sess-1",
        agent_id="agent-1",
        server="srv",
        tool="tool1",
        args={},
        capabilities=["read"],
        taint_state=[],
        rule_id="r1",
        timeout_seconds=5.0,
    )
    mgr._apply_event_to_state(
        {"event": "timeout", "call_id": "call-timeout", "timestamp": "2026-10-28T00:00:00Z"}
    )
    appr = mgr.get_approval("call-timeout")
    assert appr is not None
    assert appr.status == "timeout"


def test_pinstore_edge_branches(tmp_path: Path) -> None:
    """Validate PinStore load on missing path and record_server_pin on existing store."""
    store_file = tmp_path / "nonexistent_pins.json"
    store = PinStore(store_file)

    # 1. load on missing file initializes empty dict without error
    store.load()
    assert store.servers == {}

    # 2. save an initial pin
    store.approve_tool("server1", {"name": "toolA", "description": "descA", "inputSchema": {}})
    assert store_file.exists()

    # 3. approve_server when store file already exists
    srv_pin = store.approve_server(
        server="server2",
        tools=[{"name": "toolB", "description": "descB", "inputSchema": {}}],
        server_info={},
    )
    assert srv_pin is not None
    assert "server2" in store.servers

    # Reload from disk to verify persistence
    reloaded = PinStore(store_file)
    reloaded.load()
    assert "server1" in reloaded.servers
    assert "server2" in reloaded.servers


def test_flow_rule_empty_tuple_fallback() -> None:
    """Validate check_flow evaluating rule with empty if_session_has_tuple fallback."""
    from mcpsec_core.models import SessionState, ToolCall

    rule = CompiledFlowRule(
        id="custom-rule",
        if_session_has=frozenset({"untrusted"}),
        deny_capabilities=frozenset({"network"}),
        require_approval_capabilities=frozenset(),
        if_session_has_tuple=(),
        deny_caps_tuple=("network",),
        appr_caps_tuple=(),
        has_unless=False,
    )
    mock_policy = Mock()
    mock_policy.compiled_flow_rules = [rule]
    mock_policy.capabilities = {"fetch": ["network"]}

    call = ToolCall(
        call_id="c1",
        session_id="s1",
        agent_id="a1",
        server="fetch",
        tool="get",
        args={},
        capabilities=["network"],
    )

    # When session does NOT have taint: should pass
    state_clean = SessionState(session_id="s1", taint=set())
    dec_clean = check_flow(session_state=state_clean, call=call, policy=mock_policy)
    assert dec_clean.is_allowed

    # When session DOES have taint: should deny
    state_tainted = SessionState(session_id="s2", taint={"untrusted"})
    dec_tainted = check_flow(session_state=state_tainted, call=call, policy=mock_policy)
    assert not dec_tainted.is_allowed
    assert dec_tainted.rule_id == "custom-rule"
