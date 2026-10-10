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
    """Strictly assert {pinned, unpinned, changed, unchecked} equals the list parsed from docs/audit_log_schema.md."""
    import re

    from mcpsec_core.models import PinStatus

    expected_statuses = {"pinned", "unpinned", "changed", "unchecked"}
    actual_statuses = {s.value for s in PinStatus}
    assert actual_statuses == expected_statuses

    schema_doc = Path("docs/audit_log_schema.md").read_text(encoding="utf-8")
    # Find the line defining pin_status in Section 3
    match = re.search(r"\|\s*`pin_status`\s*\|\s*enum\s*\|\s*(.*?)\|\s*$", schema_doc, re.MULTILINE)
    assert match is not None, "pin_status definition not found in docs/audit_log_schema.md"
    cell_content = match.group(1)
    parsed_enum = set(re.findall(r"`([a-z_]+)`", cell_content))
    assert parsed_enum == expected_statuses, (
        f"docs/audit_log_schema.md pin_status enum mismatch: {parsed_enum} != {expected_statuses}"
    )


def test_audit_log_rotation_and_tamper_evident_hash_chain_continuity(tmp_path: Path) -> None:
    """Test log rotation by max_bytes and tamper-evident hash chain continuity across rotated files."""
    from mcpsec_core.audit import verify_hash_chain

    log_file = tmp_path / "audit.jsonl"
    # Set small max_bytes so each event triggers rotation
    logger = AuditLogger(
        log_path=log_file,
        log_args="redacted",
        tamper_evident=True,
        max_bytes=350,
    )

    # Log 4 events across rotations
    for i in range(1, 5):
        logger.log_session_start(
            session_id=f"session-rot-{i}",
            agent_id=f"agent-{i}",
            policy_hash="test_policy_hash_12345",
        )

    assert len(logger.rotated_files) >= 1
    all_files = [*logger.rotated_files, log_file]

    # Verify each rotated file has valid events and seq restarts per file
    valid, err_msg = verify_hash_chain(all_files)
    assert valid is True, f"Hash chain verification failed: {err_msg}"


def test_audit_logger_bounded_queue_backpressure(tmp_path: Path) -> None:
    """Test bounded writer queue with backpressure and graceful flush/close."""
    log_file = tmp_path / "audit_queue.jsonl"
    logger = AuditLogger(
        log_path=log_file,
        log_args="redacted",
        queue_size=5,
    )

    for i in range(1, 15):
        logger.log_session_start(
            session_id=f"session-q-{i}",
            agent_id=f"agent-{i}",
            policy_hash="hash_q",
        )

    logger.flush()
    logger.close()

    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 14
    for idx, line in enumerate(lines, start=1):
        data = json.loads(line)
        assert data["seq"] == idx


def test_audit_logger_fsync_mode(tmp_path: Path) -> None:
    """Test audit logger with fsync enabled."""
    log_file = tmp_path / "audit_fsync.jsonl"
    logger = AuditLogger(
        log_path=log_file,
        fsync=True,
    )
    ev = logger.log_policy_loaded("proxy.yaml", "dummy_hash")
    assert ev.seq == 1
    assert log_file.exists()
    assert log_file.stat().st_size > 0


def test_audit_log_schema_enums_bidirectional_contract() -> None:
    """Assert every enum value emitted by code appears in docs/audit_log_schema.md and vice versa."""
    import typing

    from mcpsec_core.models import (
        ApprovalEvent,
        DecisionLayer,
        EffectiveDecision,
        PinEvent,
        PinStatus,
        PolicyLoadedEvent,
        SessionEndEvent,
        SessionStartEvent,
        ToolCallEvent,
    )

    schema_doc_path = Path(__file__).parent.parent / "docs" / "audit_log_schema.md"
    assert schema_doc_path.exists(), f"Missing schema doc at {schema_doc_path}"
    doc_text = schema_doc_path.read_text(encoding="utf-8")

    def extract_cell_enums(section_header: str, field_name: str) -> set[str]:
        import re

        section = doc_text.split(section_header)[1].split("\n## ")[0]
        for line in section.splitlines():
            line_str = line.strip()
            if line_str.startswith(f"| `{field_name}` |"):
                masked = line_str.replace(r"\|", "%%PIPE%%")
                parts = [p.strip().replace("%%PIPE%%", "|") for p in masked.strip("|").split("|")]
                if len(parts) >= 3:
                    cell = parts[2]
                    # Enum definitions appear before explanatory notes / secondary sentences
                    def_part = cell.split(". ")[0].split("(")[0]
                    return set(re.findall(r"`([a-z_]+)`", def_part))
        return set()

    # 1. pin_event.action
    code_pin_actions = set(typing.get_args(PinEvent.model_fields["action"].annotation))
    expected_pin_actions = {
        "first_seen",
        "changed",
        "approved",
        "list_changed_received",
        "server_info_changed",
    }
    assert code_pin_actions == expected_pin_actions
    doc_pin_actions = extract_cell_enums("## 5. `pin_event`", "action")
    assert code_pin_actions == doc_pin_actions, (
        f"pin_event.action mismatch: code={code_pin_actions}, doc={doc_pin_actions}"
    )

    # 2. decision_layer
    code_decision_layers = {x.value for x in DecisionLayer}
    expected_decision_layers = {"pinning", "policy", "flow", "approval", "none"}
    assert code_decision_layers == expected_decision_layers
    assert (
        set(typing.get_args(ToolCallEvent.model_fields["decision_layer"].annotation))
        == expected_decision_layers
    )
    doc_decision_layers = extract_cell_enums("## 3. `tool_call`", "decision_layer")
    assert code_decision_layers == doc_decision_layers, (
        f"decision_layer mismatch: code={code_decision_layers}, doc={doc_decision_layers}"
    )

    # 3. effective_decision
    code_eff_decisions = {x.value for x in EffectiveDecision}
    expected_eff_decisions = {"forwarded", "blocked", "held"}
    assert code_eff_decisions == expected_eff_decisions
    assert (
        set(typing.get_args(ToolCallEvent.model_fields["effective_decision"].annotation))
        == expected_eff_decisions
    )
    doc_eff_decisions = extract_cell_enums("## 3. `tool_call`", "effective_decision")
    assert code_eff_decisions == doc_eff_decisions, (
        f"effective_decision mismatch: code={code_eff_decisions}, doc={doc_eff_decisions}"
    )

    # 4. pin_status
    code_pin_statuses = {x.value for x in PinStatus}
    expected_pin_statuses = {"pinned", "unpinned", "changed", "unchecked"}
    assert code_pin_statuses == expected_pin_statuses
    assert (
        set(typing.get_args(ToolCallEvent.model_fields["pin_status"].annotation))
        == expected_pin_statuses
    )
    doc_pin_statuses = extract_cell_enums("## 3. `tool_call`", "pin_status")
    assert code_pin_statuses == doc_pin_statuses, (
        f"pin_status mismatch: code={code_pin_statuses}, doc={doc_pin_statuses}"
    )

    # 5. event_type
    code_event_types = {
        cls.model_fields["event_type"].default
        for cls in (
            PolicyLoadedEvent,
            SessionStartEvent,
            SessionEndEvent,
            ToolCallEvent,
            ApprovalEvent,
            PinEvent,
        )
    }
    expected_event_types = {
        "session_start",
        "session_end",
        "policy_loaded",
        "tool_call",
        "approval",
        "pin_event",
    }
    assert code_event_types == expected_event_types

    doc_event_types = set()
    sec1 = doc_text.split("## 1. Event types")[1].split("\n## ")[0]
    for line in sec1.splitlines():
        line_str = line.strip()
        if line_str.startswith("| `"):
            event_name = line_str.split("|")[1].strip().strip("`")
            if event_name and event_name != "event_type":
                doc_event_types.add(event_name)
    assert code_event_types == doc_event_types, (
        f"event_type mismatch: code={code_event_types}, doc={doc_event_types}"
    )
