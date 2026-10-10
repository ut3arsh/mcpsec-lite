"""Unit tests for stubbed lifecycle functions."""

from __future__ import annotations

from pathlib import Path

from mcpsec_core.flow import check_flow
from mcpsec_core.models import SessionState, ToolCall
from mcpsec_core.pinning import check_pinning
from mcpsec_core.policy import check_policy
from mcpsec_core.taint import update_taint


def test_pinning_pure_function(tmp_path: Path) -> None:
    from mcpsec_core.pinning import PinStore

    # 1. No store in audit mode -> pass-through allow
    d1, st1, _, _ = check_pinning("server-1", "tool_a", {"name": "tool_a"}, None, mode="audit")
    assert d1.is_allowed
    assert d1.layer == "pinning"
    assert st1 == "unchecked"

    # 2. No store in strict mode -> fail-closed deny
    d2, st2, _, _ = check_pinning("server-1", "tool_a", {"name": "tool_a"}, None, mode="strict")
    assert not d2.is_allowed
    assert d2.layer == "pinning"
    assert "ERR_UNPINNED_TOOL" in d2.reason

    # 3. With store and approved tool -> allow
    store = PinStore(tmp_path / "pins.json")
    store.approve_tool("srv", {"name": "read_file", "description": "reads"})
    d3, st3, _, _ = check_pinning(
        "srv", "read_file", {"name": "read_file", "description": "reads"}, store, mode="strict"
    )
    assert d3.is_allowed
    assert st3 == "pinned"

    # 4. With store and changed tool -> deny in strict, allow in audit
    d4_strict, st4_strict, _, _ = check_pinning(
        "srv", "read_file", {"name": "read_file", "description": "mutated"}, store, mode="strict"
    )
    assert not d4_strict.is_allowed
    assert st4_strict == "changed"
    assert "ERR_TOOL_HASH_MISMATCH" in d4_strict.reason

    d4_audit, st4_audit, _, _ = check_pinning(
        "srv", "read_file", {"name": "read_file", "description": "mutated"}, store, mode="audit"
    )
    assert d4_audit.is_allowed
    assert st4_audit == "changed"


def test_policy_stub() -> None:
    call = ToolCall(
        call_id="c1",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="read_file",
        args={"path": "foo.txt"},
    )
    decision = check_policy(call, None)
    assert decision.is_allowed
    assert decision.layer == "none"
    assert decision.reason == "pass-through (no policy)"


def test_flow_stub() -> None:
    state = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c1",
        session_id="s1",
        agent_id="a1",
        server="http",
        tool="post",
        capabilities=["egress"],
    )
    decision = check_flow(state, call, None)
    assert decision.is_allowed
    assert decision.layer == "flow"


def test_taint_stub() -> None:
    state = SessionState(session_id="s1", taint=set())
    call = ToolCall(
        call_id="c1",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="read_file",
    )
    new_state = update_taint(call, None, state, None)
    assert new_state == state
