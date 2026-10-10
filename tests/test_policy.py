"""Tests for policy loader, 9 validation rules, warnings, and check_policy evaluation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from mcpsec_core.models import ToolCall
from mcpsec_core.policy import (
    PolicyError,
    check_policy,
    get_tool_capabilities,
    load_policy,
)

# Minimal valid policy from policy_schema.md §11
VALID_POLICY_YAML = """
version: 1
mode: enforce
serialize_calls: true

capabilities:
  fs.read_file:        [read]
  fs.write_file:       [write]
  http.fetch:          [network_read]
  http.post:           [egress]
  github.get_issue:    [network_read]

policies:
  - agent: "*"
    tools:
      fs.read_file:     { path_allowlist: ["/home/user/project/**"] }
      http.fetch:       { domain_allowlist: ["api.github.com"] }
      github.get_issue: {}

taint_sources:
  untrusted_content:
    - { tool: github.get_issue }
    - { tool: http.fetch }
  private_data:
    - { tool: fs.read_file, args: { path: ["**/.env"] } }

flow_rules:
  - id: no-egress-untrusted
    if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
  - id: no-egress-private
    if_session_has: [private_data]
    deny_capabilities: [egress]

approval: { channel: cli, allow_clear: [untrusted_content] }
pinning:  { mode: strict, store: ./pins.json }
detectors: { secrets: true, injection_heuristics: true }
redaction: { log_args: redacted }
"""


def test_valid_minimal_policy_loads_cleanly(tmp_path: Path) -> None:
    pol_file = tmp_path / "policy.yaml"
    pol_file.write_text(VALID_POLICY_YAML, encoding="utf-8", newline="\n")

    # Test loading from Path, str, and bytes
    p1, h1, w1 = load_policy(pol_file)
    assert p1.version == 1
    assert p1.mode == "enforce"
    assert p1.serialize_calls is True
    assert len(h1) == 64

    p2, h2, w2 = load_policy(VALID_POLICY_YAML.encode("utf-8"))
    assert h1 == h2

    with pytest.raises(PolicyError):
        load_policy(12345)  # type: ignore[arg-type]


def test_policy_load_idempotent() -> None:
    policy1, hash1, w1 = load_policy(VALID_POLICY_YAML)
    policy2, hash2, w2 = load_policy(VALID_POLICY_YAML)
    assert hash1 == hash2
    assert policy1.version == policy2.version
    assert policy1.capabilities == policy2.capabilities
    assert w1 == w2


def test_get_tool_capabilities() -> None:
    policy, _, _ = load_policy(VALID_POLICY_YAML)
    assert get_tool_capabilities("fs.read_file", policy) == ["read"]
    assert get_tool_capabilities("unknown.tool", policy) == []
    assert get_tool_capabilities("fs.read_file", None) == []


def test_non_dict_yaml_rejected() -> None:
    with pytest.raises(PolicyError, match="must be a YAML mapping"):
        load_policy("- item1\n- item2")

    with pytest.raises(PolicyError, match="YAML syntax error"):
        load_policy("version: [unclosed")


# ---------------------------------------------------------------------------
# The 9 Validation Rules (§10)
# ---------------------------------------------------------------------------


def test_rule1_invalid_or_missing_version() -> None:
    # Missing version
    data = yaml.safe_load(VALID_POLICY_YAML)
    del data["version"]
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_VERSION" in err_codes or "ERR_SCHEMA" in err_codes

    # Unsupported version
    data["version"] = 2
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_VERSION" in err_codes


def test_rule2_unknown_key_rejected() -> None:
    data = yaml.safe_load(VALID_POLICY_YAML)
    data["unknown_top_level_key"] = "forbidden"
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_UNKNOWN_KEY" in err_codes


def test_rule3_capabilities_tag_outside_closed_set() -> None:
    data = yaml.safe_load(VALID_POLICY_YAML)
    data["capabilities"]["fs.read_file"] = ["super_admin_read"]
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_INVALID_CAPABILITY" in err_codes


def test_rule4_unknown_taint_label_or_tag() -> None:
    data = yaml.safe_load(VALID_POLICY_YAML)
    data["taint_sources"]["unknown_label_xyz"] = [{"tool": "fs.read_file"}]
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_UNKNOWN_LABEL_OR_TAG" in err_codes

    # Unknown flow rule label
    data2 = yaml.safe_load(VALID_POLICY_YAML)
    data2["flow_rules"][0]["if_session_has"] = ["unknown_label_abc"]
    with pytest.raises(PolicyError) as exc_info2:
        load_policy(yaml.dump(data2))
    assert "ERR_UNKNOWN_LABEL_OR_TAG" in [e["code"] for e in exc_info2.value.errors]

    # Unknown deny capability
    data3 = yaml.safe_load(VALID_POLICY_YAML)
    data3["flow_rules"][0]["deny_capabilities"] = ["invalid_cap"]
    with pytest.raises(PolicyError) as exc_info3:
        load_policy(yaml.dump(data3))
    assert "ERR_UNKNOWN_LABEL_OR_TAG" in [e["code"] for e in exc_info3.value.errors]


def test_rule5_duplicate_flow_rule_id() -> None:
    data = yaml.safe_load(VALID_POLICY_YAML)
    data["flow_rules"].append(
        {
            "id": "no-egress-untrusted",  # duplicate ID
            "if_session_has": ["private_data"],
            "deny_capabilities": ["egress"],
        }
    )
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_DUPLICATE_RULE_ID" in err_codes


def test_rule6_flow_rule_invalid_capabilities() -> None:
    # Rule with neither deny nor require_approval
    data = yaml.safe_load(VALID_POLICY_YAML)
    data["flow_rules"] = [
        {
            "id": "invalid-rule",
            "if_session_has": ["untrusted_content"],
        }
    ]
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_INVALID_RULE_CAPABILITIES" in err_codes

    # Rule with both deny and require_approval
    data["flow_rules"] = [
        {
            "id": "both-rule",
            "if_session_has": ["untrusted_content"],
            "deny_capabilities": ["egress"],
            "require_approval_capabilities": ["write"],
        }
    ]
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_INVALID_RULE_CAPABILITIES" in err_codes


def test_rule7_tool_in_policies_has_no_capabilities() -> None:
    data = yaml.safe_load(VALID_POLICY_YAML)
    # Add tool to policies that has no entry in capabilities
    data["policies"][0]["tools"]["unlisted.tool"] = {}
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_TOOL_NO_CAPABILITIES" in err_codes


def test_rule8_constraint_on_tool_with_no_adapter() -> None:
    data = yaml.safe_load(VALID_POLICY_YAML)
    # github.get_issue has no path adapter, so setting path_allowlist must fail rule 8
    data["policies"][0]["tools"]["github.get_issue"] = {"path_allowlist": ["/home/user/**"]}
    with pytest.raises(PolicyError) as exc_info:
        load_policy(yaml.dump(data))
    err_codes = [e["code"] for e in exc_info.value.errors]
    assert "ERR_NO_ARGUMENT_ADAPTER" in err_codes


def test_rule9_invalid_glob_syntax() -> None:
    data = yaml.safe_load(VALID_POLICY_YAML)
    with patch("mcpsec_core.policy.compile_path_glob", side_effect=ValueError("bad glob")):
        with pytest.raises(PolicyError) as exc_info:
            load_policy(yaml.dump(data))
        assert "ERR_INVALID_GLOB" in [e["code"] for e in exc_info.value.errors]


def test_unless_exemption_validation_rules() -> None:
    """Test ADR-012 validation rules for flow rule 'unless' exemptions."""
    # 1. 'unless' on rule without egress capability -> ERR_INVALID_UNLESS
    bad_yaml_no_egress = """
version: 1
mode: enforce
capabilities:
  fs.write_file: [write]
policies:
  - agent: "*"
    tools: { fs.write_file: {} }
taint_sources:
  untrusted_content: [{ tool: fs.write_file }]
flow_rules:
  - id: write-rule
    if_session_has: [untrusted_content]
    deny_capabilities: [write]
    unless:
      domain_allowlist: ["safe.com"]
"""
    with pytest.raises(PolicyError) as exc:
        load_policy(bad_yaml_no_egress)
    assert any(e["code"] == "ERR_INVALID_UNLESS" for e in exc.value.errors)

    # 2. 'unless' with empty domain_allowlist -> ERR_INVALID_UNLESS or ERR_SCHEMA
    bad_yaml_empty_domains = """
version: 1
mode: enforce
capabilities:
  http.fetch: [egress]
policies:
  - agent: "*"
    tools: { http.fetch: {} }
taint_sources:
  untrusted_content: [{ tool: http.fetch }]
flow_rules:
  - id: fetch-rule
    if_session_has: [untrusted_content]
    deny_capabilities: [egress]
    unless:
      domain_allowlist: []
"""
    with pytest.raises(PolicyError) as exc:
        load_policy(bad_yaml_empty_domains)
    assert any(e["code"] in ("ERR_INVALID_UNLESS", "ERR_SCHEMA") for e in exc.value.errors)

    # 3. 'unless' with invalid domain pattern -> ERR_INVALID_DOMAIN_PATTERN
    bad_yaml_invalid_domain = """
version: 1
mode: enforce
capabilities:
  http.fetch: [egress]
policies:
  - agent: "*"
    tools: { http.fetch: {} }
taint_sources:
  untrusted_content: [{ tool: http.fetch }]
flow_rules:
  - id: fetch-rule
    if_session_has: [untrusted_content]
    deny_capabilities: [egress]
    unless:
      domain_allowlist: ["http://user:pass@evil.com/"]
"""
    with pytest.raises(PolicyError) as exc:
        load_policy(bad_yaml_invalid_domain)
    assert any(
        e["code"] in ("ERR_INVALID_DOMAIN_PATTERN", "ERR_INVALID_GLOB") for e in exc.value.errors
    )

    # 4. Valid 'unless' compiles cleanly
    good_yaml = """
version: 1
mode: enforce
capabilities:
  http.fetch: [network_read, egress]
policies:
  - agent: "*"
    tools: { http.fetch: {} }
taint_sources:
  untrusted_content: [{ tool: http.fetch }]
flow_rules:
  - id: fetch-rule
    if_session_has: [untrusted_content]
    deny_capabilities: [egress]
    unless:
      domain_allowlist: ["docs.internal", "*.safe.org"]
"""
    policy, p_hash, warnings = load_policy(good_yaml)
    assert len(policy.compiled_flow_rules) == 1
    assert policy.compiled_flow_rules[0].has_unless is True
    assert len(policy.compiled_flow_rules[0].unless_domain_rules) == 2


def test_warnings_generated(tmp_path: Path) -> None:
    # Policy with unreferenced taint source, unreferenced cap, and serialize_calls: false
    custom_yaml = """
version: 1
mode: enforce
serialize_calls: false

capabilities:
  fs.read_file: [read]

policies:
  - agent: "*"
    tools:
      fs.read_file: {}

taint_sources:
  untrusted_content:
    - { tool: fs.read_file }

flow_rules: []
"""
    policy, p_hash, warnings = load_policy(custom_yaml)
    warning_texts = " ".join(warnings)
    assert "serialize_calls is false" in warning_texts
    assert "untrusted_content" in warning_texts
    assert "Capability tag 'read'" in warning_texts


# ---------------------------------------------------------------------------
# check_policy Evaluation Tests
# ---------------------------------------------------------------------------


def test_check_policy_default_deny(tmp_path: Path) -> None:
    policy, _, _ = load_policy(VALID_POLICY_YAML)

    # Tool not in allowlist
    call = ToolCall(
        call_id="call-1",
        session_id="sess-1",
        agent_id="dev-agent",
        server="shell",
        tool="exec",
        args={"command": "ls"},
    )
    dec = check_policy(call, policy)
    assert dec.decision == "deny"
    assert "not in allowlist" in dec.reason

    # Agent not allowed
    policy_specific = """
version: 1
capabilities:
  fs.read_file: [read]
policies:
  - agent: explicit-agent-only
    tools:
      fs.read_file: {}
"""
    pol_spec, _, _ = load_policy(policy_specific)
    unauthorized_agent_call = ToolCall(
        call_id="call-2",
        session_id="sess-2",
        agent_id="other-agent",
        server="fs",
        tool="read_file",
        args={"path": "test.txt"},
    )
    dec_agent = check_policy(unauthorized_agent_call, pol_spec)
    assert dec_agent.decision == "deny"
    assert "not permitted by policy" in dec_agent.reason


def test_check_policy_path_and_domain_allowlists(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    allowed_file = sandbox / "allowed.txt"
    allowed_file.write_text("ok", encoding="utf-8")

    forbidden_file = tmp_path / "forbidden.txt"
    forbidden_file.write_text("no", encoding="utf-8")

    custom_yaml = f"""
version: 1
capabilities:
  fs.read_file: [read]
  http.fetch: [network_read]
policies:
  - agent: dev-agent
    tools:
      fs.read_file:
        path_allowlist: ["{sandbox.as_posix()}/**"]
      http.fetch:
        domain_allowlist: ["api.github.com", "*.trusted.org"]
"""
    policy, _, _ = load_policy(custom_yaml)

    # 1. Allowed path
    allowed_call = ToolCall(
        call_id="c1",
        session_id="s1",
        agent_id="dev-agent",
        server="fs",
        tool="read_file",
        args={"path": str(allowed_file)},
    )
    dec1 = check_policy(allowed_call, policy)
    assert dec1.decision == "allow"

    # 2. Forbidden path
    forbidden_call = ToolCall(
        call_id="c2",
        session_id="s1",
        agent_id="dev-agent",
        server="fs",
        tool="read_file",
        args={"path": str(forbidden_file)},
    )
    dec2 = check_policy(forbidden_call, policy)
    assert dec2.decision == "deny"
    assert "path not in allowlist" in dec2.reason

    # 3. Path security error (NUL byte)
    nul_call = ToolCall(
        call_id="c3",
        session_id="s1",
        agent_id="dev-agent",
        server="fs",
        tool="read_file",
        args={"path": f"{sandbox}/file.txt\x00.evil"},
    )
    dec3 = check_policy(nul_call, policy)
    assert dec3.decision == "deny"
    assert "security violation" in dec3.reason

    # 4. Domain allowlist check
    dom_allow_call = ToolCall(
        call_id="c4",
        session_id="s1",
        agent_id="dev-agent",
        server="http",
        tool="fetch",
        args={"url": "https://api.github.com/v1/repos"},
    )
    assert check_policy(dom_allow_call, policy).decision == "allow"

    dom_sub_call = ToolCall(
        call_id="c5",
        session_id="s1",
        agent_id="dev-agent",
        server="http",
        tool="fetch",
        args={"url": "https://sub.trusted.org/data"},
    )
    assert check_policy(dom_sub_call, policy).decision == "allow"

    dom_deny_call = ToolCall(
        call_id="c6",
        session_id="s1",
        agent_id="dev-agent",
        server="http",
        tool="fetch",
        args={"url": "https://evil-github.com/data"},
    )
    dec_dom = check_policy(dom_deny_call, policy)
    assert dec_dom.decision == "deny"
    assert "domain not in allowlist" in dec_dom.reason

    # 5. Domain security violation (userinfo in URL)
    userinfo_call = ToolCall(
        call_id="c7",
        session_id="s1",
        agent_id="dev-agent",
        server="http",
        tool="fetch",
        args={"url": "https://api.github.com@evil.com/"},
    )
    dec_userinfo = check_policy(userinfo_call, policy)
    assert dec_userinfo.decision == "deny"
    assert "security violation" in dec_userinfo.reason
