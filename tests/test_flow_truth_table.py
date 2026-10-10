"""Comprehensive truth table tests for flow engine and unless exemptions.

Evaluates every combination:
(labels in {None, U, P, U+P}) x (capabilities in {read, write, network_read, egress, exec})
x (unless match / no-match / parse-failure)
against example policy flow rules.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcpsec_core.flow import check_flow
from mcpsec_core.models import SessionState, ToolCall
from mcpsec_core.policy import Policy, load_policy

TRUTH_TABLE_POLICY_YAML = """
version: 1
mode: enforce
capabilities:
  fs.read_file:       [read]
  fs.write_file:      [write]
  http.get_docs:      [network_read]
  http.fetch:         [network_read, egress]
  shell.exec:         [exec]
  custom.egress:      [egress]

policies:
  - agent: "*"
    tools:
      fs.read_file:   {}
      fs.write_file:  {}
      http.get_docs:  {}
      http.fetch:     {}
      shell.exec:     {}
      custom.egress:  {}

taint_sources:
  untrusted_content:
    - { tool: http.get_docs }
  private_data:
    - { tool: fs.read_file }

flow_rules:
  - id: no-egress-untrusted
    if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
    unless:
      domain_allowlist: ["safe.internal.example.com", "*.trusted.org"]
  - id: no-egress-private
    if_session_has: [private_data]
    deny_capabilities: [egress]
"""


@pytest.fixture(scope="module")
def truth_policy() -> Policy:
    policy, _, _ = load_policy(TRUTH_TABLE_POLICY_YAML)
    return policy


# Label sets: empty, U, P, U+P
LABEL_SETS = [
    frozenset(),
    frozenset(["untrusted_content"]),
    frozenset(["private_data"]),
    frozenset(["untrusted_content", "private_data"]),
]

# Tools representing capabilities
CAPABILITY_TOOLS = [
    ("fs.read_file", "read", {"path": "file.txt"}),
    ("fs.write_file", "write", {"path": "file.txt"}),
    ("http.get_docs", "network_read", {"url": "https://docs.org"}),
    ("shell.exec", "exec", {"cmd": "ls"}),
    ("custom.egress", "egress", {"endpoint": "https://sink.net"}),
]

# URL argument variations for http.fetch ([network_read, egress])
URL_VARIATIONS = [
    ("match_exact", {"url": "https://safe.internal.example.com/api"}),
    ("match_wildcard", {"url": "https://sub.trusted.org/resource"}),
    ("no_match", {"url": "https://attacker.evil.com/leak"}),
    ("parse_failure_userinfo", {"url": "https://user:pass@safe.internal.example.com/"}),
    ("parse_failure_bad_scheme", {"url": "gopher://safe.internal.example.com/"}),
    ("missing_arg", {}),
]


@pytest.mark.parametrize(
    "labels", LABEL_SETS, ids=["none", "untrusted", "private", "untrusted+private"]
)
@pytest.mark.parametrize("tool_id,cap,args", CAPABILITY_TOOLS)
def test_truth_table_non_network_tools(
    truth_policy: Policy, labels: frozenset[str], tool_id: str, cap: str, args: dict[str, Any]
) -> None:
    state = SessionState(session_id="test-session", taint=set(labels))
    call = ToolCall(
        call_id="call-1",
        session_id="test-session",
        agent_id="dev-agent",
        server="srv",
        tool=tool_id,
        args=args,
    )
    decision = check_flow(state, call, truth_policy)

    has_u = "untrusted_content" in labels
    has_p = "private_data" in labels

    if cap == "read" or cap == "write" or cap == "network_read":
        # None of the flow rules deny read, write, or network_read
        assert decision.is_allowed, f"Expected allow for {cap} with labels {labels}, got {decision}"
    elif cap == "exec":
        # Denied if session has untrusted_content
        if has_u:
            assert not decision.is_allowed
            assert decision.decision == "deny"
            assert decision.rule_id == "no-egress-untrusted"
        else:
            assert decision.is_allowed
    elif cap == "egress":
        # Denied if session has untrusted_content OR private_data
        if has_u or has_p:
            assert not decision.is_allowed
            assert decision.decision == "deny"
            if has_u:
                assert decision.rule_id == "no-egress-untrusted"
            else:
                assert decision.rule_id == "no-egress-private"
        else:
            assert decision.is_allowed


@pytest.mark.parametrize(
    "labels", LABEL_SETS, ids=["none", "untrusted", "private", "untrusted+private"]
)
@pytest.mark.parametrize("var_name,args", URL_VARIATIONS)
def test_truth_table_egress_with_unless_exemption(
    truth_policy: Policy, labels: frozenset[str], var_name: str, args: dict[str, Any]
) -> None:
    state = SessionState(session_id="test-session", taint=set(labels))
    call = ToolCall(
        call_id="call-1",
        session_id="test-session",
        agent_id="dev-agent",
        server="srv",
        tool="http.fetch",
        args=args,
    )
    decision = check_flow(state, call, truth_policy)

    has_u = "untrusted_content" in labels
    has_p = "private_data" in labels
    is_match = var_name in ("match_exact", "match_wildcard")

    if not has_u and not has_p:
        # Clean session: always allowed
        assert decision.is_allowed, f"Expected clean session to allow http.fetch with {var_name}"
    elif has_u and not has_p:
        # Untrusted content only: rule 'no-egress-untrusted' applies unless exempt
        if is_match:
            # Exemption applies -> rule skipped -> allowed
            assert decision.is_allowed, f"Expected unless exemption to allow {var_name}"
        else:
            # Non-match or parse failure or missing arg -> fail closed -> denied
            assert not decision.is_allowed
            assert decision.decision == "deny"
            assert decision.rule_id == "no-egress-untrusted"
    elif has_p and not has_u:
        # Private data only: rule 'no-egress-private' has NO unless exemption -> denied
        assert not decision.is_allowed
        assert decision.decision == "deny"
        assert decision.rule_id == "no-egress-private"
    else:
        # Both untrusted_content AND private_data:
        # Even if 'no-egress-untrusted' matches unless exemption, 'no-egress-private' has NO unless clause
        # and therefore blocks egress.
        assert not decision.is_allowed
        assert decision.decision == "deny"
        if is_match:
            # The untrusted rule was exempted, so private_data rule fires
            assert decision.rule_id == "no-egress-private"
        else:
            # Both fire; first rule in policy order is no-egress-untrusted
            assert decision.rule_id in ("no-egress-untrusted", "no-egress-private")


def test_is_response_successful_variants() -> None:
    from mcpsec_core.models import ResponseSummary
    from mcpsec_core.taint import is_response_successful

    assert not is_response_successful(None)
    assert not is_response_successful(ResponseSummary(status="error", bytes=0))
    assert is_response_successful(ResponseSummary(status="ok", bytes=10))
    assert not is_response_successful({"is_error": True})
    assert not is_response_successful({"isError": True})
    assert not is_response_successful({"status": "error"})
    assert is_response_successful({"status": "success"})
    assert not is_response_successful(False)
    assert is_response_successful(True)
    assert is_response_successful("plain text")


def test_update_taint_argument_matching_and_fail_closed_branches() -> None:
    from mcpsec_core.policy import load_policy
    from mcpsec_core.taint import update_taint

    policy_yaml = """
version: 1
mode: enforce
capabilities:
  fs.read: [read]
  net.fetch: [network_read]
policies:
  - agent: "*"
    tools:
      fs.read: {}
      net.fetch: {}
taint_sources:
  private_data:
    - { tool: fs.read, args: { path: ["/secret/**"] } }
  untrusted_content:
    - { tool: net.fetch, args: { url: ["*.untrusted.com"] } }
flow_rules: []
"""
    pol, _, _ = load_policy(policy_yaml)
    init_state = SessionState(session_id="s1")

    # 1. Unsuccessful response -> state unchanged
    s_err = update_taint(
        ToolCall(
            call_id="c1",
            session_id="s1",
            agent_id="a",
            server="fs",
            tool="read",
            args={"path": "/secret/a"},
        ),
        {"is_error": True},
        init_state,
        pol,
    )
    assert len(s_err.taint) == 0

    # 2. None policy -> state unchanged
    s_no_pol = update_taint(
        ToolCall(
            call_id="c1",
            session_id="s1",
            agent_id="a",
            server="fs",
            tool="read",
            args={"path": "/secret/a"},
        ),
        {"is_error": False},
        init_state,
        None,
    )
    assert len(s_no_pol.taint) == 0

    # 3. Missing arg for private_data -> fail closed toward tainting
    s_priv_missing = update_taint(
        ToolCall(call_id="c1", session_id="s1", agent_id="a", server="fs", tool="read", args={}),
        {"is_error": False},
        init_state,
        pol,
    )
    assert "private_data" in s_priv_missing.taint

    # 4. Non-string arg for private_data -> fail closed toward tainting
    s_priv_non_str = update_taint(
        ToolCall(
            call_id="c1",
            session_id="s1",
            agent_id="a",
            server="fs",
            tool="read",
            args={"path": 12345},
        ),
        {"is_error": False},
        init_state,
        pol,
    )
    assert "private_data" in s_priv_non_str.taint

    # 5. Missing arg for untrusted_content -> non-private label does not match -> not tainted
    s_untr_missing = update_taint(
        ToolCall(call_id="c2", session_id="s1", agent_id="a", server="net", tool="fetch", args={}),
        {"is_error": False},
        init_state,
        pol,
    )
    assert "untrusted_content" not in s_untr_missing.taint

    # 6. Non-string arg for untrusted_content -> not tainted
    s_untr_non_str = update_taint(
        ToolCall(
            call_id="c2",
            session_id="s1",
            agent_id="a",
            server="net",
            tool="fetch",
            args={"url": 999},
        ),
        {"is_error": False},
        init_state,
        pol,
    )
    assert "untrusted_content" not in s_untr_non_str.taint

    # 7. Path normalization exception for private_data -> fail closed toward tainting
    s_priv_exc = update_taint(
        ToolCall(
            call_id="c1",
            session_id="s1",
            agent_id="a",
            server="fs",
            tool="read",
            args={"path": "\x00invalid_null_path"},
        ),
        {"is_error": False},
        init_state,
        pol,
    )
    assert "private_data" in s_priv_exc.taint

    # 8. Path normalization exception for untrusted_content -> not tainted
    s_untr_exc = update_taint(
        ToolCall(
            call_id="c2",
            session_id="s1",
            agent_id="a",
            server="net",
            tool="fetch",
            args={"url": "\x00invalid_null_url"},
        ),
        {"is_error": False},
        init_state,
        pol,
    )
    assert "untrusted_content" not in s_untr_exc.taint
