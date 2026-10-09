"""Tests for CLI replay log filtering and timeline formatting."""

from __future__ import annotations

from pathlib import Path

from cli.replay import filter_events, format_timeline, load_audit_events
from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import LatencyMs, ResponseSummary, ToolCallEvent


def test_replay_filtering_and_timeline(tmp_path: Path) -> None:
    log_file = tmp_path / "replay_test.jsonl"
    logger = AuditLogger(log_path=log_file, log_args="redacted")

    logger.log_policy_loaded(policy_path="policy.yaml", policy_hash="hash1")

    # Session 1
    logger.log_session_start(
        session_id="sess-alpha",
        agent_id="agent-1",
        policy_hash="hash1",
        mode="enforce",
    )
    logger.log_tool_call(
        session_id="sess-alpha",
        call_id="call-1",
        agent_id="agent-1",
        server="fs",
        tool="read_file",
        capabilities=["read"],
        raw_args={"path": "doc.txt"},
        decision="allow",
        effective_decision="forwarded",
        decision_layer="policy",
        decision_reason="allowed",
        latency_ms=LatencyMs(proxy=1.5, upstream=10.0),
        response_summary=ResponseSummary(status="ok", bytes=100),
    )
    logger.log_tool_call(
        session_id="sess-alpha",
        call_id="call-2",
        agent_id="agent-1",
        server="http",
        tool="post",
        capabilities=["egress"],
        raw_args={"url": "https://example.com"},
        decision="deny",
        effective_decision="blocked",
        decision_layer="flow",
        decision_reason="egress denied",
        latency_ms=LatencyMs(proxy=0.8, upstream=None),
        response_summary=None,
    )
    logger.log_session_end(
        session_id="sess-alpha",
        reason="disconnect",
        final_taint=["untrusted_content"],
        call_count=2,
        deny_count=1,
    )

    # Session 2
    logger.log_session_start(
        session_id="sess-beta",
        agent_id="agent-2",
        policy_hash="hash1",
        mode="audit",
    )
    logger.log_tool_call(
        session_id="sess-beta",
        call_id="call-3",
        agent_id="agent-2",
        server="fs",
        tool="write_file",
        capabilities=["write"],
        raw_args={"path": "out.txt"},
        decision="allow",
        effective_decision="forwarded",
        decision_layer="policy",
        decision_reason="allowed",
        latency_ms=LatencyMs(proxy=2.0, upstream=12.0),
        response_summary=ResponseSummary(status="ok", bytes=50),
    )
    logger.log_session_end(
        session_id="sess-beta",
        reason="shutdown",
        final_taint=[],
        call_count=1,
        deny_count=0,
    )

    # Load events
    events = load_audit_events(log_file)
    assert len(events) == 8

    # Filter by session
    s_alpha = filter_events(events, session_id="sess-alpha")
    assert len(s_alpha) == 4  # session_start, 2 tool_calls, session_end

    # Filter by tool
    fs_calls = filter_events(events, tool="read_file")
    assert len(fs_calls) == 1
    assert isinstance(fs_calls[0], ToolCallEvent)
    assert fs_calls[0].tool == "read_file"

    # Filter by decision
    denied_calls = filter_events(events, decision="deny")
    assert len(denied_calls) == 1
    assert isinstance(denied_calls[0], ToolCallEvent)
    assert denied_calls[0].tool == "post"

    # Filter by agent
    agent2_events = filter_events(events, agent_id="agent-2")
    assert len(agent2_events) == 2

    # Filter by layer
    flow_events = filter_events(events, decision_layer="flow")
    assert len(flow_events) == 1

    # Format timeline output
    timeline = format_timeline(s_alpha)
    assert "SESSION: sess-alpha" in timeline
    assert "fs.read_file" in timeline
    assert "http.post" in timeline
    assert "allow/forwarded" in timeline
    assert "deny/blocked" in timeline
