"""Unit tests for stubbed lifecycle functions."""

from __future__ import annotations

from mcpsec_core.flow import check_flow
from mcpsec_core.models import SessionState, ToolCall
from mcpsec_core.pinning import check_pinning
from mcpsec_core.policy import check_policy
from mcpsec_core.taint import update_taint


def test_pinning_stub() -> None:
    decision = check_pinning("server-1", None)
    assert decision.is_allowed
    assert decision.layer == "pinning"


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
