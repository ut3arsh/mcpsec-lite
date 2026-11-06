"""Tests for flow-rule path allowlist exemptions (`unless: { path_allowlist: [...] }`).

Strictly adheres to ADR-018, docs/policy_schema.md §5.1, and AGENTS.md.
Validates:
1. Truth table (match / no match / parse failure / traversal / symlinks /
   tool without path adapter / missing path arg / case-insensitivity on Windows / UNC & device paths).
2. Multi-path arguments (both match vs one outside).
3. Policy validation error codes (ERR_UNLESS_PATH_NON_WRITE, ERR_INVALID_UNLESS_PATH,
   ERR_INVALID_PATH_PATTERN, ERR_INVALID_UNLESS).
4. Hypothesis property tests (monotonicity: adding exemption never denies more;
   normalization idempotency).
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mcpsec_core.flow import check_flow
from mcpsec_core.matching import normalize_path
from mcpsec_core.models import SessionState, ToolCall
from mcpsec_core.policy import Policy, PolicyError, load_policy

BASE_POLICY_YAML = """
version: 1
mode: enforce
capabilities:
  fs.read_file:       [read]
  fs.write_file:      [write]
  fs.move_file:       [write]
  http.fetch:         [network_read, egress]
  custom.raw_write:   [write]

policies:
  - agent: "*"
    tools:
      fs.read_file:   {}
      fs.write_file:  {}
      fs.move_file:   {}
      http.fetch:     {}
      custom.raw_write: {}

taint_sources:
  untrusted_content:
    - { tool: http.fetch }

flow_rules:
  - id: appr-untrusted-write
    if_session_has: [untrusted_content]
    require_approval_capabilities: [write]
    unless:
      path_allowlist: ["sandbox/notes/**"]
"""

NO_UNLESS_POLICY_YAML = """
version: 1
mode: enforce
capabilities:
  fs.read_file:       [read]
  fs.write_file:      [write]
  http.fetch:         [network_read, egress]

policies:
  - agent: "*"
    tools:
      fs.read_file:   {}
      fs.write_file:  {}
      http.fetch:     {}

taint_sources:
  untrusted_content:
    - { tool: http.fetch }

flow_rules:
  - id: appr-untrusted-write
    if_session_has: [untrusted_content]
    require_approval_capabilities: [write]
"""


@pytest.fixture(scope="module")
def flow_path_policy() -> Policy:
    policy, _, _ = load_policy(BASE_POLICY_YAML)
    return policy


@pytest.fixture(scope="module")
def no_unless_policy() -> Policy:
    policy, _, _ = load_policy(NO_UNLESS_POLICY_YAML)
    return policy


# ---------------------------------------------------------------------------
# 1. Truth Table Tests
# ---------------------------------------------------------------------------


def test_flow_path_unless_match_exempts_rule(flow_path_policy: Policy) -> None:
    """A write inside sandbox/notes/** is exempted from approval under untrusted taint."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c1",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": "sandbox/notes/report.md", "content": "clean notes"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "allow"
    assert "passed" in decision.reason


def test_flow_path_unless_no_match_requires_approval(flow_path_policy: Policy) -> None:
    """A write outside sandbox/notes/** requires approval under untrusted taint."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c2",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": "sandbox/src/main.go", "content": "package main"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_parse_failure_fails_closed(flow_path_policy: Policy) -> None:
    """A path containing a NUL byte fails closed and is held for approval."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c3",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": "sandbox/notes/\x00evil.md", "content": "payload"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_traversal_fails_closed(flow_path_policy: Policy) -> None:
    """Directory traversal escaping sandbox/notes/** fails closed and is held for approval."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c4",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": "sandbox/notes/../../sandbox/src/main.go", "content": "payload"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_unc_network_share_fails_closed(flow_path_policy: Policy) -> None:
    """UNC network paths fail normalization, failing closed to hold for approval."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c5",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": "\\\\attacker-host\\share\\notes\\report.md", "content": "payload"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_device_namespace_fails_closed(flow_path_policy: Policy) -> None:
    """Windows device namespace paths fail normalization, failing closed to hold for approval."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c6",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": "\\\\?\\C:\\notes\\report.md", "content": "payload"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_tool_without_path_adapter_fails_closed(
    flow_path_policy: Policy,
) -> None:
    """A tool with write capability but no path adapter cannot be exempted and fails closed."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c7",
        session_id="s1",
        agent_id="a1",
        server="custom",
        tool="raw_write",
        args={"data": "raw data"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_missing_path_arg_fails_closed(flow_path_policy: Policy) -> None:
    """A write call with missing 'path' argument fails closed and requires approval."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c8",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"content": "missing path"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_non_string_path_arg_fails_closed(
    flow_path_policy: Policy,
) -> None:
    """A write call with non-string 'path' fails closed and requires approval."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c9",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": 12345, "content": "invalid type"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_windows_case_insensitive(flow_path_policy: Policy) -> None:
    """On Windows, case-insensitive match exempts UPPERCASE paths."""
    if os.name != "nt":
        pytest.skip("Windows case-insensitivity test applies to Windows only")
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c10",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": "SANDBOX/NOTES/REPORT.MD", "content": "uppercase notes"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "allow"


def test_flow_path_unless_multi_path_both_match(flow_path_policy: Policy) -> None:
    """fs.move_file where both source and destination are in allowlist is exempt."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c11",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="move_file",
        args={
            "source": "sandbox/notes/old_report.md",
            "destination": "sandbox/notes/new_report.md",
        },
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "allow"


def test_flow_path_unless_multi_path_one_outside_fails_closed(
    flow_path_policy: Policy,
) -> None:
    """fs.move_file where destination is outside allowlist fails closed and requires approval."""
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c12",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="move_file",
        args={
            "source": "sandbox/notes/report.md",
            "destination": "sandbox/src/report.md",
        },
        capabilities=["write"],
    )
    decision = check_flow(session, call, flow_path_policy)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-untrusted-write"


def test_flow_path_unless_symlink_escape_fails_closed(tmp_path: Any) -> None:
    """Symlinks resolving outside allowlist fail exemption and trigger the rule."""
    notes_dir = tmp_path / "sandbox" / "notes"
    src_dir = tmp_path / "sandbox" / "src"
    notes_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)
    target_outside = src_dir / "target.txt"
    target_outside.write_text("outside", encoding="utf-8")

    link_path = notes_dir / "link_to_src"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(src_dir), str(link_path))
    else:
        os.symlink(str(src_dir), str(link_path), target_is_directory=True)

    notes_glob = f"{notes_dir.as_posix()}/**"
    policy_yaml = f"""
version: 1
mode: enforce
capabilities:
  fs.write_file: [write]
policies:
  - agent: "*"
    tools:
      fs.write_file: {{}}
flow_rules:
  - id: appr-write
    if_session_has: [untrusted_content]
    require_approval_capabilities: [write]
    unless:
      path_allowlist: ["{notes_glob}"]
"""
    pol, _, _ = load_policy(policy_yaml)
    session = SessionState(session_id="s1", taint={"untrusted_content"})
    call = ToolCall(
        call_id="c13",
        session_id="s1",
        agent_id="a1",
        server="fs",
        tool="write_file",
        args={"path": str(link_path / "target.txt"), "content": "escape"},
        capabilities=["write"],
    )
    decision = check_flow(session, call, pol)
    assert decision.decision == "require_approval"
    assert decision.rule_id == "appr-write"


# ---------------------------------------------------------------------------
# 2. Policy Validation Error Code Tests
# ---------------------------------------------------------------------------


def test_policy_validation_unless_path_non_write() -> None:
    """path_allowlist on a non-write flow rule is rejected with ERR_UNLESS_PATH_NON_WRITE."""
    yaml_src = """
version: 1
mode: enforce
capabilities:
  http.fetch: [egress]
policies:
  - agent: "*"
    tools:
      http.fetch: {}
flow_rules:
  - id: deny-egress
    if_session_has: [untrusted_content]
    deny_capabilities: [egress]
    unless:
      path_allowlist: ["sandbox/notes/**"]
"""
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml_src)
    errors = exc_info.value.errors
    assert any(e["code"] == "ERR_UNLESS_PATH_NON_WRITE" for e in errors)


def test_policy_validation_invalid_unless_path_empty() -> None:
    """Empty path_allowlist list is rejected with ERR_INVALID_UNLESS_PATH."""
    yaml_src = """
version: 1
mode: enforce
capabilities:
  fs.write_file: [write]
policies:
  - agent: "*"
    tools:
      fs.write_file: {}
flow_rules:
  - id: appr-write
    if_session_has: [untrusted_content]
    require_approval_capabilities: [write]
    unless:
      path_allowlist: []
"""
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml_src)
    errors = exc_info.value.errors
    assert any(e["code"] == "ERR_INVALID_UNLESS_PATH" for e in errors)


def test_policy_validation_invalid_unless_path_non_string() -> None:
    """Non-string elements in path_allowlist are rejected with ERR_INVALID_UNLESS_PATH."""
    yaml_src = """
version: 1
mode: enforce
capabilities:
  fs.write_file: [write]
policies:
  - agent: "*"
    tools:
      fs.write_file: {}
flow_rules:
  - id: appr-write
    if_session_has: [untrusted_content]
    require_approval_capabilities: [write]
    unless:
      path_allowlist: [12345]
"""
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml_src)
    errors = exc_info.value.errors
    assert any(e["code"] == "ERR_INVALID_UNLESS_PATH" for e in errors)


def test_policy_validation_invalid_path_pattern() -> None:
    """Uncompilable glob patterns in path_allowlist are rejected with ERR_INVALID_PATH_PATTERN."""
    from unittest.mock import patch

    yaml_src = """
version: 1
mode: enforce
capabilities:
  fs.write_file: [write]
policies:
  - agent: "*"
    tools:
      fs.write_file: {}
flow_rules:
  - id: appr-write
    if_session_has: [untrusted_content]
    require_approval_capabilities: [write]
    unless:
      path_allowlist: ["bad/pattern/**"]
"""
    with patch(
        "mcpsec_core.policy.compile_path_glob", side_effect=ValueError("bad pattern syntax")
    ):
        with pytest.raises(PolicyError) as exc_info:
            load_policy(yaml_src)
    errors = exc_info.value.errors
    assert any(e["code"] == "ERR_INVALID_PATH_PATTERN" for e in errors)


def test_policy_validation_empty_unless_clause() -> None:
    """An unless clause with neither domain_allowlist nor path_allowlist is rejected."""
    yaml_src = """
version: 1
mode: enforce
capabilities:
  fs.write_file: [write]
policies:
  - agent: "*"
    tools:
      fs.write_file: {}
flow_rules:
  - id: appr-write
    if_session_has: [untrusted_content]
    require_approval_capabilities: [write]
    unless: {}
"""
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml_src)
    errors = exc_info.value.errors
    assert any(e["code"] == "ERR_INVALID_UNLESS" for e in errors)


# ---------------------------------------------------------------------------
# 3. Hypothesis Property Tests
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(
    has_taint=st.booleans(),
    subpath=st.sampled_from(["report.md", "notes/doc.txt", "../src/main.go", "other/file.py"]),
)
def test_property_path_unless_monotonicity(
    has_taint: bool,
    subpath: str,
    flow_path_policy: Policy,
    no_unless_policy: Policy,
) -> None:
    """Monotonicity: Adding an 'unless' exemption NEVER denies more.

    If policy without exemption allows, policy with exemption MUST allow.
    If policy with exemption denies/approves, policy without exemption could not have allowed.
    """
    taint = {"untrusted_content"} if has_taint else set()
    session = SessionState(session_id="s_prop", taint=taint)
    call = ToolCall(
        call_id="c_prop",
        session_id="s_prop",
        agent_id="a_prop",
        server="fs",
        tool="write_file",
        args={"path": f"sandbox/notes/{subpath}", "content": "data"},
        capabilities=["write"],
    )

    dec_no_exempt = check_flow(session, call, no_unless_policy)
    dec_with_exempt = check_flow(session, call, flow_path_policy)

    # 1. If base allowed, exempt policy must allow
    if dec_no_exempt.decision == "allow":
        assert dec_with_exempt.decision == "allow"

    # 2. If exempt policy required approval, base policy must have required approval
    if dec_with_exempt.decision == "require_approval":
        assert dec_no_exempt.decision == "require_approval"


@settings(max_examples=50)
@given(
    path=st.sampled_from(
        [
            "sandbox/notes/report.md",
            "sandbox/notes/sub/doc.txt",
            "sandbox/src/main.go",
            "./sandbox/notes/../notes/report.md",
            "foo/bar/baz.txt",
        ]
    )
)
def test_property_path_normalization_idempotent(path: str) -> None:
    """normalize_path is strictly idempotent: f(f(p)) == f(p)."""
    norm1 = normalize_path(path)
    norm2 = normalize_path(norm1)
    assert norm1 == norm2
