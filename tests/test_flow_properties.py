"""Hypothesis property-based tests for taint tracking and flow engine.

Proves:
1. Flow is monotone: adding labels never turns a denial/approval into an allow.
2. Taint is monotone (absent approvals): update_taint never loses existing taint labels.
3. update_taint is pure: never mutates input SessionState or arguments.
4. Flow decisions and taint updates are strictly deterministic.
"""

from __future__ import annotations

import copy
from typing import Literal

from hypothesis import given, settings
from hypothesis import strategies as st

from mcpsec_core.flow import check_flow
from mcpsec_core.models import ResponseSummary, SessionState, ToolCall
from mcpsec_core.policy import Policy, load_policy
from mcpsec_core.taint import update_taint

PROPERTY_POLICY_YAML = """
version: 1
mode: enforce
capabilities:
  fs.read_file:       [read]
  fs.write_file:      [write]
  http.fetch:         [network_read, egress]
  http.post:          [egress]
  shell.exec:         [exec]

policies:
  - agent: "*"
    tools:
      fs.read_file:   {}
      fs.write_file:  {}
      http.fetch:     {}
      http.post:      {}
      shell.exec:     {}

taint_sources:
  untrusted_content:
    - { tool: http.fetch }
  private_data:
    - { tool: fs.read_file, args: { path: ["**/.env*", "**/secrets/**"] } }

flow_rules:
  - id: no-egress-untrusted
    if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
    unless:
      domain_allowlist: ["api.github.com", "*.internal.net"]
  - id: no-egress-private
    if_session_has: [private_data]
    deny_capabilities: [egress]
  - id: appr-exec-private
    if_session_has: [private_data]
    require_approval_capabilities: [exec]
"""

PROPERTY_POLICY: Policy
PROPERTY_POLICY, _prop_policy_hash, _prop_policy_warns = load_policy(PROPERTY_POLICY_YAML)

ALL_LABELS = ["untrusted_content", "private_data", "extra_label_1", "extra_label_2"]
ALL_TOOLS = ["fs.read_file", "fs.write_file", "http.fetch", "http.post", "shell.exec"]
ALL_URLS = [
    "https://api.github.com/repos",
    "https://service.internal.net/data",
    "https://evil.attacker.com/steal",
    "http://192.168.1.1/test",
    "invalid-url-scheme://bad",
]
ALL_PATHS = [
    "/app/.env",
    "/home/user/secrets/key.pem",
    "/public/readme.md",
    "relative/path.txt",
]

# Strategies
st_labels = st.sets(st.sampled_from(ALL_LABELS))
st_tool = st.sampled_from(ALL_TOOLS)
st_url = st.sampled_from(ALL_URLS)
st_path = st.sampled_from(ALL_PATHS)


@st.composite
def st_tool_call(draw: st.DrawFn) -> ToolCall:
    tool = draw(st_tool)
    args: dict[str, str] = {}
    if "http" in tool:
        args["url"] = draw(st_url)
    elif "fs" in tool:
        args["path"] = draw(st_path)
    elif "shell" in tool:
        args["cmd"] = "echo test"

    return ToolCall(
        call_id=draw(st.text(min_size=1, max_size=10, alphabet="abcdef0123456789")),
        session_id="prop-session",
        agent_id="agent-1",
        server=tool.split(".")[0],
        tool=tool.split(".")[1],
        args=args,
    )


@given(
    base_labels=st_labels,
    extra_labels=st_labels,
    call=st_tool_call(),
)
def test_flow_monotonicity_property(
    base_labels: set[str],
    extra_labels: set[str],
    call: ToolCall,
) -> None:
    """Monotonicity: S1 subset S2 => Decision(S2) is at least as restrictive as Decision(S1).

    Precedence restriction order: allow < require_approval < deny.
    Adding taint labels can never turn a deny into an allow/require_approval,
    nor turn a require_approval into an allow.
    """
    s1_taint = set(base_labels)
    s2_taint = set(base_labels | extra_labels)

    state1 = SessionState(session_id="prop-sess-1", taint=s1_taint)
    state2 = SessionState(session_id="prop-sess-2", taint=s2_taint)

    d1 = check_flow(state1, call, PROPERTY_POLICY)
    d2 = check_flow(state2, call, PROPERTY_POLICY)

    # Restriction rank: allow = 0, require_approval = 1, deny = 2
    rank = {"allow": 0, "require_approval": 1, "deny": 2}

    assert rank[d2.decision] >= rank[d1.decision], (
        f"Flow monotonicity violated! With labels {s1_taint} got {d1.decision}, "
        f"with superset {s2_taint} got less restrictive {d2.decision} for tool {call.tool}"
    )


@given(
    initial_labels=st_labels,
    call=st_tool_call(),
    status=st.sampled_from(["ok", "error"]),
)
def test_taint_monotonicity_absent_approvals(
    initial_labels: set[str],
    call: ToolCall,
    status: Literal["ok", "error"],
) -> None:
    """Taint monotonicity: absent approvals, state.taint subset update_taint(state).taint."""
    state = SessionState(session_id="prop-sess", taint=set(initial_labels))
    outcome = ResponseSummary(status=status, bytes=100)

    new_state = update_taint(call, outcome, state, PROPERTY_POLICY)

    assert state.taint.issubset(new_state.taint), (
        f"Taint monotonicity violated: initial {state.taint} not subset of {new_state.taint}"
    )


@given(
    initial_labels=st_labels,
    call=st_tool_call(),
    status=st.sampled_from(["ok", "error"]),
)
def test_update_taint_purity(
    initial_labels: set[str],
    call: ToolCall,
    status: Literal["ok", "error"],
) -> None:
    """Purity: update_taint must never mutate input SessionState, call, or args."""
    state = SessionState(session_id="prop-sess", taint=set(initial_labels))
    state_copy = copy.deepcopy(state)
    call_copy = copy.deepcopy(call)
    outcome = ResponseSummary(status=status, bytes=100)

    new_state = update_taint(call, outcome, state, PROPERTY_POLICY)

    # Inputs must be unchanged
    assert state.taint == state_copy.taint
    assert state.session_id == state_copy.session_id
    assert call.args == call_copy.args
    assert call.tool == call_copy.tool
    # Output must be a new object
    assert new_state is not state


@given(
    labels=st_labels,
    call=st_tool_call(),
)
def test_flow_decision_determinism(
    labels: set[str],
    call: ToolCall,
) -> None:
    """Determinism: identical state and call produces identical Decision."""
    state1 = SessionState(session_id="prop-sess", taint=set(labels))
    state2 = SessionState(session_id="prop-sess", taint=set(labels))

    d1 = check_flow(state1, call, PROPERTY_POLICY)
    d2 = check_flow(state2, call, PROPERTY_POLICY)

    assert d1.decision == d2.decision
    assert d1.layer == d2.layer
    assert d1.rule_id == d2.rule_id
