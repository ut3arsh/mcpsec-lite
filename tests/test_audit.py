"""Tests for audit log schema compliance, event serialization, and seq monotonicity."""

from __future__ import annotations

import json
from pathlib import Path

from mcpsec_core.audit import AuditLogger, canonical_json_hash, format_rfc3339_utc
from mcpsec_core.models import (
    ApprovalEvent,
    LatencyMs,
    PinEvent,
    PolicyLoadedEvent,
    ResponseSummary,
    SessionEndEvent,
    SessionStartEvent,
    ToolCallEvent,
    parse_audit_event,
)


def test_format_rfc3339_utc() -> None:
    ts = format_rfc3339_utc()
    assert ts.endswith("Z")
    assert "T" in ts
    # e.g. 2026-10-10T01:23:45.678Z
    parts = ts[:-1].split(".")
    assert len(parts) == 2
    assert len(parts[1]) == 3


def test_canonical_json_hash() -> None:
    obj1 = {"b": 2, "a": 1}
    obj2 = {"a": 1, "b": 2}
    assert canonical_json_hash(obj1) == canonical_json_hash(obj2)


def test_all_audit_event_types_schema_conformance(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=log_file, log_args="redacted", tamper_evident=True)

    # 1. Policy Loaded
    ev1 = logger.log_policy_loaded(
        policy_path="proxy.yaml",
        policy_hash="abcdef1234567890",
        warnings=["test warning"],
    )
    assert isinstance(ev1, PolicyLoadedEvent)
    assert ev1.seq == 1
    assert ev1.session_id is None

    # 2. Session Start
    ev2 = logger.log_session_start(
        session_id="session-1234",
        agent_id="test-agent",
        policy_hash="abcdef1234567890",
        client_info={"name": "test-client", "version": "1.0"},
        mode="enforce",
    )
    assert isinstance(ev2, SessionStartEvent)
    assert ev2.seq == 2
    assert ev2.session_id == "session-1234"
    assert ev2.prev_hash is not None

    # 3. Tool Call
    ev3 = logger.log_tool_call(
        session_id="session-1234",
        call_id="call-5678",
        agent_id="test-agent",
        server="filesystem",
        tool="read_file",
        capabilities=["read"],
        raw_args={"path": "test.txt"},
        decision="allow",
        effective_decision="forwarded",
        decision_layer="policy",
        decision_reason="allowed by policy",
        latency_ms=LatencyMs(proxy=1.2, upstream=15.4),
        taint_before=[],
        taint_after=[],
        response_summary=ResponseSummary(status="ok", bytes=42),
    )
    assert isinstance(ev3, ToolCallEvent)
    assert ev3.seq == 3
    assert ev3.latency_ms.proxy == 1.2
    assert ev3.latency_ms.upstream == 15.4

    # 4. Approval
    ev4 = logger.log_approval(
        session_id="session-1234",
        action="clear_taint",
        cleared_labels=["untrusted_content"],
        approver="cli",
        taint_before=["untrusted_content"],
        taint_after=[],
        note="Approved by admin",
    )
    assert isinstance(ev4, ApprovalEvent)
    assert ev4.seq == 4

    # 5. Pin Event
    ev5 = logger.log_pin_event(
        server="filesystem",
        tool="read_file",
        action="first_seen",
        mode="strict",
        effective_decision="accepted",
        session_id="session-1234",
        new_hash="hash123",
    )
    assert isinstance(ev5, PinEvent)
    assert ev5.seq == 5

    # 6. Session End
    ev6 = logger.log_session_end(
        session_id="session-1234",
        reason="disconnect",
        final_taint=[],
        call_count=1,
        deny_count=0,
    )
    assert isinstance(ev6, SessionEndEvent)
    assert ev6.seq == 6

    # Verify every line in the file parses and validates against schema v1
    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 6

    for line in lines:
        raw_dict = json.loads(line)
        assert raw_dict["schema_version"] == 1
        parsed = parse_audit_event(line)
        assert parsed.schema_version == 1


def test_seq_monotonicity_and_recovery(tmp_path: Path) -> None:
    log_file = tmp_path / "seq_test.jsonl"
    logger1 = AuditLogger(log_path=log_file)

    for i in range(1, 6):
        ev = logger1.log_session_start(
            session_id=f"session-{i}",
            agent_id="test-agent",
            policy_hash="dummy",
        )
        assert ev.seq == i

    # Create new logger instance on same file; verify it resumes monotonic seq
    logger2 = AuditLogger(log_path=log_file)
    ev6 = logger2.log_session_start(
        session_id="session-6",
        agent_id="test-agent",
        policy_hash="dummy",
    )
    assert ev6.seq == 6


def test_pin_status_enum_matches_schema_doc() -> None:
    from mcpsec_core.models import PinStatus

    expected_statuses = {"pinned", "unpinned", "changed", "unchecked"}
    actual_statuses = {s.value for s in PinStatus}
    assert actual_statuses == expected_statuses

    schema_doc = Path("docs/audit_log_schema.md").read_text(encoding="utf-8")
    for status in expected_statuses:
        assert f"`{status}`" in schema_doc or f'"{status}"' in schema_doc or status in schema_doc
