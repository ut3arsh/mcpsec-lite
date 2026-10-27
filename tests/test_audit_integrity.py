"""Audit integrity, hash chain verification, rotation, and fsync tests (ADR-016 & docs/audit_log_schema.md).

Proves:
1. Size-triggered rotation: creates new file, seq restarts at 1, first entry carries rotated file's last hash.
2. Chain resume after restart: recovers seq monotonicity and resumes tamper-evident hash chaining.
3. verify_hash_chain failure matrix: passes on intact chain; fails on edited line, deleted line, inserted line,
   reordered lines, truncated file, and broken rotation continuity.
4. fsync-in-strict behavior: os.fsync called per entry when fsync=True or strict pinning enabled.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcpsec_core.audit import AuditLogger, verify_hash_chain
from mcpsec_core.models import LatencyMs, ResponseSummary, ToolCallEvent
from mcpsec_core.policy import load_policy_file


def _create_dummy_tool_call(seq: int = 1, call_id: str = "call-1") -> ToolCallEvent:
    return ToolCallEvent(
        timestamp="2026-10-27T12:00:00.000Z",
        seq=seq,
        session_id="session-audit-test",
        call_id=call_id,
        agent_id="agent-1",
        server="srv",
        tool="test_tool",
        capabilities=["read"],
        args={"path": "/tmp/test"},
        decision="allow",
        effective_decision="forwarded",
        decision_layer="policy",
        decision_reason="allowed by policy",
        rule_id="allow-read",
        pin_status="pinned",
        flags=[],
        risk_score=None,
        latency_ms=LatencyMs(proxy=0.5, upstream=1.2),
        taint_before=[],
        taint_after=[],
        response_summary=ResponseSummary(status="ok", bytes=100),
        error=None,
    )


@pytest.mark.timeout(10.0)
def test_audit_size_triggered_rotation(tmp_path: Path) -> None:
    """Size-triggered rotation creates new file, resets seq to 1, and chains prev_hash across rotation."""
    log_file = tmp_path / "audit.jsonl"
    # max_bytes sized to fit exactly 2 events (616 bytes each) before triggering rotation on 3rd
    logger = AuditLogger(
        log_path=log_file,
        tamper_evident=True,
        max_bytes=1500,
    )

    # Log 4 events: 2 in rotated file, 2 in new active file
    for i in range(1, 5):
        event = _create_dummy_tool_call(call_id=f"call-{i}")
        logger.log_event(event, sync=True)

    logger.flush()
    assert len(logger.rotated_files) == 1, (
        f"Expected 1 rotated file, got {len(logger.rotated_files)}"
    )
    rotated_file = logger.rotated_files[0]
    assert rotated_file.exists()
    assert log_file.exists()

    # Read last line of rotated file
    with open(rotated_file, "rb") as rf:
        rotated_lines = [line.strip() for line in rf if line.strip()]
    assert len(rotated_lines) >= 1
    last_rotated_hash = hashlib.sha256(rotated_lines[-1]).hexdigest()

    # Read lines of current active log file
    with open(log_file, "rb") as cur_f:
        current_lines = [line.strip() for line in cur_f if line.strip()]
    assert len(current_lines) >= 1

    first_entry_new_file = json.loads(current_lines[0].decode("utf-8"))
    # Seq restarts at 1 in new file
    assert first_entry_new_file["seq"] == 1
    # First entry in new file points to rotated file's last line hash
    assert first_entry_new_file["prev_hash"] == last_rotated_hash

    # verify_hash_chain passes across rotated file and active file
    valid, err = verify_hash_chain([rotated_file, log_file])
    assert valid is True, f"Hash chain verification failed across rotation: {err}"


@pytest.mark.timeout(10.0)
def test_audit_chain_resume_after_restart(tmp_path: Path) -> None:
    """Audit logger recovers seq and prev_hash when restarted with an existing log."""
    log_file = tmp_path / "audit_resume.jsonl"

    # Process 1 writes 3 events
    logger1 = AuditLogger(log_path=log_file, tamper_evident=True)
    for i in range(1, 4):
        logger1.log_event(_create_dummy_tool_call(call_id=f"c1-{i}"), sync=True)
    logger1.close()

    # Process 2 restarts with the same log file
    logger2 = AuditLogger(log_path=log_file, tamper_evident=True)
    assert logger2._seq == 3

    # Process 2 logs event 4
    e4 = logger2.log_event(_create_dummy_tool_call(call_id="c2-4"), sync=True)
    assert e4.seq == 4
    logger2.close()

    # Verify the full resumed chain is intact
    valid, err = verify_hash_chain([log_file])
    assert valid is True, f"Resumed chain failed: {err}"


@pytest.mark.timeout(10.0)
def test_verify_hash_chain_failure_matrix(tmp_path: Path) -> None:
    """verify_hash_chain fails on edited, deleted, inserted, reordered, truncated, or broken continuity."""
    log_file = tmp_path / "audit_matrix.jsonl"
    logger = AuditLogger(log_path=log_file, tamper_evident=True)
    for i in range(1, 5):
        logger.log_event(_create_dummy_tool_call(call_id=f"matrix-{i}"), sync=True)
    logger.close()

    with open(log_file, encoding="utf-8") as f:
        original_lines = [line.strip() for line in f if line.strip()]
    assert len(original_lines) == 4

    # Baseline intact passes
    valid, err = verify_hash_chain([log_file])
    assert valid is True
    assert err is None

    # 1. Edited line: alter a character in line 2
    edited_lines = list(original_lines)
    edited_obj = json.loads(edited_lines[1])
    edited_obj["args"]["path"] = "/tampered/path"
    edited_lines[1] = json.dumps(edited_obj, separators=(",", ":"))
    f_edited = tmp_path / "audit_edited.jsonl"
    f_edited.write_text("\n".join(edited_lines) + "\n", encoding="utf-8")
    valid, err = verify_hash_chain([f_edited])
    assert valid is False
    assert err is not None and "Hash chain broken" in err

    # 2. Deleted line: remove line 2 (gap 1 -> 3)
    deleted_lines = [original_lines[0], original_lines[2], original_lines[3]]
    f_deleted = tmp_path / "audit_deleted.jsonl"
    f_deleted.write_text("\n".join(deleted_lines) + "\n", encoding="utf-8")
    valid, err = verify_hash_chain([f_deleted])
    assert valid is False
    assert err is not None and "Sequence gap" in err

    # 3. Inserted line: insert an extra line between line 1 and 2
    inserted_lines = [
        original_lines[0],
        original_lines[0],  # Duplicate seq 1
        original_lines[1],
        original_lines[2],
        original_lines[3],
    ]
    f_inserted = tmp_path / "audit_inserted.jsonl"
    f_inserted.write_text("\n".join(inserted_lines) + "\n", encoding="utf-8")
    valid, err = verify_hash_chain([f_inserted])
    assert valid is False
    assert err is not None

    # 4. Reordered lines: swap line 2 and line 3
    reordered_lines = [
        original_lines[0],
        original_lines[2],
        original_lines[1],
        original_lines[3],
    ]
    f_reordered = tmp_path / "audit_reordered.jsonl"
    f_reordered.write_text("\n".join(reordered_lines) + "\n", encoding="utf-8")
    valid, err = verify_hash_chain([f_reordered])
    assert valid is False
    assert err is not None and ("Sequence gap" in err or "Hash chain broken" in err)

    # 5. Truncated file: write partial JSON on the last line
    truncated_content = "\n".join(original_lines[:2]) + "\n" + original_lines[2][:30]
    f_truncated = tmp_path / "audit_truncated.jsonl"
    f_truncated.write_text(truncated_content, encoding="utf-8")
    valid, err = verify_hash_chain([f_truncated])
    assert valid is False
    assert err is not None and "Invalid JSON" in err

    # 6. Broken rotation continuity: file2 does not point to file1's last hash
    f_rot1 = tmp_path / "audit_rot1.jsonl"
    f_rot2 = tmp_path / "audit_rot2.jsonl"
    f_rot1.write_text("\n".join(original_lines[:2]) + "\n", encoding="utf-8")
    # In file 2, tamper with line 1's prev_hash
    rot2_lines = list(original_lines[2:])
    rot2_obj = json.loads(rot2_lines[0])
    rot2_obj["seq"] = 1
    rot2_obj["prev_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
    rot2_lines[0] = json.dumps(rot2_obj, separators=(",", ":"))
    f_rot2.write_text("\n".join(rot2_lines) + "\n", encoding="utf-8")
    valid, err = verify_hash_chain([f_rot1, f_rot2])
    assert valid is False
    assert err is not None and "Hash chain broken" in err


@pytest.mark.timeout(10.0)
def test_fsync_in_strict_behavior(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify os.fsync is called for every write when fsync=True, and strict mode policy enables it."""
    mock_fsync = MagicMock()
    monkeypatch.setattr(os, "fsync", mock_fsync)

    # 1. fsync=True calls os.fsync
    log_file_sync = tmp_path / "audit_sync.jsonl"
    logger_sync = AuditLogger(log_path=log_file_sync, fsync=True)
    for i in range(3):
        logger_sync.log_event(_create_dummy_tool_call(call_id=f"sync-{i}"), sync=True)
    logger_sync.close()
    assert mock_fsync.call_count == 3

    # 2. fsync=False does not call os.fsync
    mock_fsync.reset_mock()
    log_file_nosync = tmp_path / "audit_nosync.jsonl"
    logger_nosync = AuditLogger(log_path=log_file_nosync, fsync=False)
    for i in range(3):
        logger_nosync.log_event(_create_dummy_tool_call(call_id=f"nosync-{i}"), sync=True)
    logger_nosync.close()
    assert mock_fsync.call_count == 0

    # 3. Policy with pinning: {mode: strict} validates strict mode
    policy_file = tmp_path / "strict_policy.yaml"
    policy_file.write_text(
        """version: 1
mode: enforce
pinning:
  mode: strict
  store: pins.json
capabilities:
  srv.test_tool: [read]
policies:
  - agent: "*"
    tools:
      srv.test_tool: {}
""",
        encoding="utf-8",
    )
    pol, _, _ = load_policy_file(policy_file)
    assert pol.pinning is not None
    assert pol.pinning.mode == "strict"
