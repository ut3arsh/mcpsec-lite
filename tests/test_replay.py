"""Tests for streaming replay, index generation, and filtering."""

from __future__ import annotations

from pathlib import Path

from cli.replay import (
    build_sidecar_index,
    get_or_create_index,
    matches_filter,
    stream_audit_events,
)
from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import LatencyMs, ResponseSummary, ToolCallEvent


def test_streaming_replay_and_sidecar_index(tmp_path: Path) -> None:
    log_file = tmp_path / "stream_replay_test.jsonl"
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

    # Append a malformed line to test graceful skipping
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("this is not valid json\n")

    # Build sidecar index
    idx = build_sidecar_index(log_file)
    assert idx["file_size"] == log_file.stat().st_size
    assert "sess-alpha" in idx["sessions"]
    assert len(idx["sessions"]["sess-alpha"]) == 4

    # Re-fetch index should be valid and cached
    idx2 = get_or_create_index(log_file)
    assert idx2["file_size"] == idx["file_size"]

    # Stream all events
    events = []
    stream = stream_audit_events(log_file)
    for ev, _line_num in stream:
        events.append(ev)

    assert len(events) == 5  # policy_loaded, session_start, 2 tool_calls, session_end

    # Filter with matches_filter
    fs_calls = [e for e in events if matches_filter(e, tool="read_file")]
    assert len(fs_calls) == 1
    assert isinstance(fs_calls[0], ToolCallEvent)
    assert fs_calls[0].tool == "read_file"

    denied = [e for e in events if matches_filter(e, decision="deny")]
    assert len(denied) == 1
    assert isinstance(denied[0], ToolCallEvent)
    assert denied[0].tool == "post"

    # Stream by exact session_id using index
    sess_stream = stream_audit_events(log_file, session_id="sess-alpha")
    sess_events = [ev for ev, _ in sess_stream]
    assert len(sess_events) == 4
