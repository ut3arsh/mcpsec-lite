"""Tests for ADR-021 (Rule 11): Fail-closed policy check for built-in U tool taint completeness."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from mcpsec_core.adapters import (
    BUILTIN_TOOL_TAINT_CLASSES,
    OFFICIAL_GITHUB_TOOL_TABLE,
    UNTRUSTED_CONTENT_BUILTIN_TOOLS,
    get_builtin_taint_class,
)
from mcpsec_core.audit import AuditLogger
from mcpsec_core.policy import PolicyError, load_policy_file, load_policy_text

REPO_ROOT = Path(__file__).resolve().parent.parent

OFFICIAL_GITHUB_U_TOOLS = sorted(
    spec.tool_id for spec in OFFICIAL_GITHUB_TOOL_TABLE.values() if spec.taint_class == "U"
)
OFFICIAL_GITHUB_T_TOOLS = sorted(
    spec.tool_id for spec in OFFICIAL_GITHUB_TOOL_TABLE.values() if spec.taint_class == "T"
)
ALL_BUILTIN_U_TOOLS = sorted(UNTRUSTED_CONTENT_BUILTIN_TOOLS)


def test_builtin_u_classification_data_matches_adr021() -> None:
    """Built-in taint data includes the 19 official GitHub U tools + fetch.fetch + http.fetch."""
    assert len(OFFICIAL_GITHUB_U_TOOLS) == 19
    assert len(OFFICIAL_GITHUB_T_TOOLS) == 27
    assert UNTRUSTED_CONTENT_BUILTIN_TOOLS == frozenset(
        OFFICIAL_GITHUB_U_TOOLS + ["fetch.fetch", "http.fetch"]
    )
    assert len(UNTRUSTED_CONTENT_BUILTIN_TOOLS) == 21
    assert BUILTIN_TOOL_TAINT_CLASSES["fetch.fetch"] == "U"
    assert BUILTIN_TOOL_TAINT_CLASSES["http.fetch"] == "U"
    assert get_builtin_taint_class("fetch.fetch") == "U"
    assert get_builtin_taint_class("http.fetch") == "U"
    assert get_builtin_taint_class("github.add_issue_comment") == "T"
    assert get_builtin_taint_class("github.get_issue") is None
    assert get_builtin_taint_class("custom.tool") is None


def _build_policy_dict(
    *,
    allowed_by_agent: dict[str, list[str]],
    declared_untrusted: list[str] | None = None,
    taint_exempt: list[dict[str, str]] | None = None,
    has_untrusted_flow_rule: bool = True,
    mode: Literal["audit", "enforce"] = "enforce",
) -> dict[str, object]:
    all_tools = sorted({t for tools in allowed_by_agent.values() for t in tools} | {"fs.read_file"})
    caps = {
        t: (["write", "egress"] if t == "github.add_issue_comment" else ["network_read"])
        for t in all_tools
    }
    caps["fs.read_file"] = ["read"]
    caps["fs.write_file"] = ["write"]

    policies_list = [
        {"agent": agent, "tools": {t: {} for t in tools}}
        for agent, tools in allowed_by_agent.items()
    ]
    taint_sources: dict[str, list[dict[str, str]]] = {}
    if declared_untrusted:
        taint_sources["untrusted_content"] = [{"tool": t} for t in declared_untrusted]

    flow_rules: list[dict[str, object]] = []
    if has_untrusted_flow_rule:
        flow_rules.append(
            {
                "id": "no-write-after-untrusted",
                "if_session_has": ["untrusted_content"],
                "deny_capabilities": ["write"],
            }
        )

    doc: dict[str, object] = {
        "version": 1,
        "mode": mode,
        "capabilities": caps,
        "policies": policies_list,
        "taint_sources": taint_sources,
        "flow_rules": flow_rules,
    }
    if taint_exempt is not None:
        doc["taint_exempt"] = taint_exempt
    return doc


@pytest.mark.parametrize("tool_id", ALL_BUILTIN_U_TOOLS)
@pytest.mark.parametrize("mode", ["enforce", "audit"])
def test_adr021_truth_table_missing_declared_exempt(
    tool_id: str, mode: Literal["audit", "enforce"]
) -> None:
    """Every built-in U tool must pass if declared/exempt and fail with ERR_TAINT_SOURCE_MISSING otherwise."""
    # 1. Missing -> PolicyError naming the tool
    doc_missing = _build_policy_dict(
        allowed_by_agent={"*": [tool_id]},
        declared_untrusted=[],
        has_untrusted_flow_rule=True,
        mode=mode,
    )
    with pytest.raises(PolicyError) as exc_info:
        load_policy_text(yaml.safe_dump(doc_missing, sort_keys=False))
    missing_errs = [e for e in exc_info.value.errors if e["code"] == "ERR_TAINT_SOURCE_MISSING"]
    assert missing_errs, f"Expected ERR_TAINT_SOURCE_MISSING for {tool_id}"
    assert tool_id in missing_errs[0]["message"]

    # 2. Declared -> loads cleanly with no Rule 11 warning
    doc_declared = _build_policy_dict(
        allowed_by_agent={"*": [tool_id]},
        declared_untrusted=[tool_id],
        has_untrusted_flow_rule=True,
        mode=mode,
    )
    pol_ok, _, warns_ok = load_policy_text(yaml.safe_dump(doc_declared, sort_keys=False))
    assert pol_ok.mode == mode
    assert not any("taint_exempt" in w or "without appearing" in w for w in warns_ok)

    # 3. Exempt with non-empty reason -> loads cleanly and records tool + reason in warnings
    reason_text = f"Approved read-only fixed mirror for {tool_id}"
    doc_exempt = _build_policy_dict(
        allowed_by_agent={"*": [tool_id]},
        declared_untrusted=[],
        taint_exempt=[{"tool": tool_id, "reason": reason_text}],
        has_untrusted_flow_rule=True,
        mode=mode,
    )
    pol_ex, _, warns_ex = load_policy_text(yaml.safe_dump(doc_exempt, sort_keys=False))
    assert len(pol_ex.taint_exempt) == 1
    assert any(tool_id in w and reason_text in w for w in warns_ex)


def test_adr021_taint_exempt_validation_and_audit_logging(tmp_path: Path) -> None:
    """Empty/invalid taint_exempt fails closed; valid exemption records reason in policy_loaded."""
    for bad_exempt in (
        [{"tool": "http.fetch", "reason": ""}],
        [{"tool": "http.fetch", "reason": "   \t\n"}],
        [{"tool": "  ", "reason": "valid reason"}],
    ):
        doc_bad = _build_policy_dict(
            allowed_by_agent={"*": ["http.fetch"]},
            taint_exempt=bad_exempt,
            has_untrusted_flow_rule=True,
        )
        with pytest.raises(PolicyError) as exc_info:
            load_policy_text(yaml.safe_dump(doc_bad, sort_keys=False))
        assert any(e["code"] == "ERR_INVALID_TAINT_EXEMPT" for e in exc_info.value.errors)

    # Empty reason must also be rejected even without flow_rules
    doc_no_flow_bad_reason = _build_policy_dict(
        allowed_by_agent={"*": ["http.fetch"]},
        taint_exempt=[{"tool": "http.fetch", "reason": ""}],
        has_untrusted_flow_rule=False,
    )
    with pytest.raises(PolicyError) as exc_no_flow:
        load_policy_text(yaml.safe_dump(doc_no_flow_bad_reason, sort_keys=False))
    assert any(e["code"] == "ERR_INVALID_TAINT_EXEMPT" for e in exc_no_flow.value.errors)

    # Missing reason key or unknown extra key must fail closed
    yaml_missing_key = """
version: 1
mode: enforce
capabilities:
  http.fetch: [network_read]
policies:
  - agent: "*"
    tools: { http.fetch: {} }
taint_exempt:
  - tool: http.fetch
"""
    with pytest.raises(PolicyError) as exc_schema:
        load_policy_text(yaml_missing_key)
    assert any(e["code"] == "ERR_SCHEMA" for e in exc_schema.value.errors)

    yaml_extra_key = """
version: 1
mode: enforce
capabilities:
  http.fetch: [network_read]
policies:
  - agent: "*"
    tools: { http.fetch: {} }
taint_exempt:
  - tool: http.fetch
    reason: "Fixed internal mirror"
    extra_field: true
"""
    with pytest.raises(PolicyError) as exc_extra:
        load_policy_text(yaml_extra_key)
    assert any(e["code"] == "ERR_UNKNOWN_KEY" for e in exc_extra.value.errors)

    # Valid exemption logged into policy_loaded audit event
    reason = "Dedicated localhost metrics endpoint only"
    policy_path = tmp_path / "exempt_policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            _build_policy_dict(
                allowed_by_agent={"*": ["http.fetch"]},
                taint_exempt=[{"tool": "http.fetch", "reason": reason}],
                has_untrusted_flow_rule=True,
            ),
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _, p_hash, warnings = load_policy_file(policy_path)
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=audit_path)
    logger.log_policy_loaded(policy_path=str(policy_path), policy_hash=p_hash, warnings=warnings)
    logger.close()

    loaded_event = json.loads(audit_path.read_text(encoding="utf-8").strip().splitlines()[0])
    assert loaded_event["event_type"] == "policy_loaded"
    assert any("http.fetch" in w and reason in w for w in loaded_event["warnings"])


def test_adr021_agent_specific_allowlist_checked() -> None:
    """Missing U taint source under a named non-wildcard agent must still fail closed."""
    doc = _build_policy_dict(
        allowed_by_agent={
            "*": ["fs.read_file"],
            "research-bot": ["github.issue_read", "fetch.fetch"],
        },
        declared_untrusted=[],
        has_untrusted_flow_rule=True,
    )
    with pytest.raises(PolicyError) as exc_info:
        load_policy_text(yaml.safe_dump(doc, sort_keys=False))
    missing_errs = [e for e in exc_info.value.errors if e["code"] == "ERR_TAINT_SOURCE_MISSING"]
    missing_msgs = " ".join(e["message"] for e in missing_errs)
    assert len(missing_errs) == 2
    assert "github.issue_read" in missing_msgs
    assert "fetch.fetch" in missing_msgs
    assert any(e["path"].startswith("policies[1].tools.") for e in missing_errs)


def test_adr021_no_untrusted_flow_rule_emits_loud_warning() -> None:
    """Without an untrusted_content flow rule, omitted U tools load with loud warnings."""
    yaml_private_only = """
version: 1
mode: enforce
capabilities:
  fs.read_file: [read]
  fs.write_file: [write]
  github.issue_read: [network_read]
  http.fetch: [network_read, egress]
policies:
  - agent: "*"
    tools:
      fs.read_file: {}
      github.issue_read: {}
      http.fetch: {}
taint_sources:
  private_data:
    - { tool: fs.read_file }
flow_rules:
  - id: no-egress-private
    if_session_has: [private_data]
    deny_capabilities: [egress]
"""
    pol, _, warnings = load_policy_text(yaml_private_only)
    assert pol.mode == "enforce"
    loud_warns = [
        w for w in warnings if "without appearing in taint_sources.untrusted_content" in w
    ]
    assert len(loud_warns) == 2
    assert any("github.issue_read" in w and w.startswith("WARNING:") for w in loud_warns)
    assert any("http.fetch" in w and w.startswith("WARNING:") for w in loud_warns)


def test_adr021_ignores_unmapped_and_t_classified_tools() -> None:
    """Unmapped tools and T-classified official tools do not trigger ADR-021."""
    doc = _build_policy_dict(
        allowed_by_agent={
            "*": [
                "github.get_issue",
                "custom.reader",
                "github.add_issue_comment",
                "github.list_branches",
            ]
        },
        declared_untrusted=["fs.read_file"],
        has_untrusted_flow_rule=True,
    )
    pol, _, warnings = load_policy_text(yaml.safe_dump(doc, sort_keys=False))
    assert pol.mode == "enforce"
    assert not any("ERR_TAINT_SOURCE_MISSING" in w or "WARNING:" in w for w in warnings)


@given(
    agent_u_assignments=st.dictionaries(
        keys=st.sampled_from(["*", "agent-alpha", "agent-beta"]),
        values=st.lists(
            st.sampled_from(ALL_BUILTIN_U_TOOLS),
            max_size=6,
            unique=True,
        ),
        min_size=1,
        max_size=3,
    ),
    agent_non_u=st.lists(
        st.sampled_from(["github.add_issue_comment", "github.list_branches", "custom.helper"]),
        max_size=3,
        unique=True,
    ),
    declared_u=st.sets(st.sampled_from(ALL_BUILTIN_U_TOOLS), max_size=12),
    exempt_u=st.sets(st.sampled_from(ALL_BUILTIN_U_TOOLS), max_size=6),
    has_untrusted_flow=st.booleans(),
)
def test_adr021_property_random_allowlists_and_exemptions(
    agent_u_assignments: dict[str, list[str]],
    agent_non_u: list[str],
    declared_u: set[str],
    exempt_u: set[str],
    has_untrusted_flow: bool,
) -> None:
    """Property check over random per-agent allowlists, taint_sources, exemptions, and flow rules."""
    allowed_by_agent: dict[str, list[str]] = {}
    all_allowed_u: set[str] = set()
    for idx, (agent, u_tools) in enumerate(agent_u_assignments.items()):
        tools = list(u_tools)
        if idx == 0:
            tools.extend(t for t in agent_non_u if t not in tools)
            if not tools:
                tools.append("fs.read_file")
        allowed_by_agent[agent] = tools
        all_allowed_u.update(u_tools)

    exempt_list = [
        {"tool": t, "reason": f"Property test exemption for {t}"} for t in sorted(exempt_u)
    ]
    doc = _build_policy_dict(
        allowed_by_agent=allowed_by_agent,
        declared_untrusted=sorted(declared_u),
        taint_exempt=exempt_list if exempt_list else None,
        has_untrusted_flow_rule=has_untrusted_flow,
    )
    yaml_text = yaml.safe_dump(doc, sort_keys=False)
    missing_u = all_allowed_u - declared_u - exempt_u

    if has_untrusted_flow and missing_u:
        with pytest.raises(PolicyError) as exc_info:
            load_policy_text(yaml_text)
        err_msgs = [
            e["message"] for e in exc_info.value.errors if e["code"] == "ERR_TAINT_SOURCE_MISSING"
        ]
        assert len(err_msgs) == len(missing_u)
        combined = "\n".join(err_msgs)
        for tool_id in missing_u:
            assert tool_id in combined
    else:
        _, _, warnings = load_policy_text(yaml_text)
        for ex_tool in exempt_u:
            assert any(
                ex_tool in w and f"Property test exemption for {ex_tool}" in w for w in warnings
            )
        if not has_untrusted_flow:
            for tool_id in missing_u:
                assert any(tool_id in w and w.startswith("WARNING:") for w in warnings)


def test_adr021_committed_configs_and_examples_audit() -> None:
    """Audit all C0-C7 configs and examples/policies/ under ADR-021 without mutating them."""
    for clean_cfg in ("C5.yaml", "C6.yaml", "C7.yaml", "E4b.yaml", "E5.yaml"):
        _, _, warns = load_policy_file(REPO_ROOT / "benchmark" / "configs" / clean_cfg)
        assert not any("without appearing in taint_sources.untrusted_content" in w for w in warns)

    for warn_cfg in ("C0.yaml", "C1.yaml"):
        _, _, warns = load_policy_file(REPO_ROOT / "benchmark" / "configs" / warn_cfg)
        u_warns = [w for w in warns if "without appearing in taint_sources.untrusted_content" in w]
        assert (
            len(u_warns) == 4
        )  # fetch.fetch, http.fetch, github.list_issues, github.search_repositories

    for legacy_fail_cfg in ("C2.yaml", "C2s.yaml", "C3.yaml", "C4.yaml"):
        with pytest.raises(PolicyError) as exc_info:
            load_policy_file(REPO_ROOT / "benchmark" / "configs" / legacy_fail_cfg)
        errs = [e for e in exc_info.value.errors if e["code"] == "ERR_TAINT_SOURCE_MISSING"]
        assert errs and "github.list_issues" in errs[0]["message"]

    with pytest.raises(PolicyError) as exc_ex:
        load_policy_file(REPO_ROOT / "examples" / "policies" / "dev-agent.yaml")
    ex_missing = {
        e["path"].split(".")[-2] + "." + e["path"].split(".")[-1]
        for e in exc_ex.value.errors
        if e["code"] == "ERR_TAINT_SOURCE_MISSING"
    }
    assert ex_missing == {
        "github.get_file_contents",
        "github.list_issues",
        "github.list_pull_requests",
        "github.search_repositories",
    }
