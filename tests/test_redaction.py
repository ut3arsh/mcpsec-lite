"""Tests for argument and error redaction modes."""

from __future__ import annotations

from pathlib import Path

from mcpsec_core.audit import AuditLogger, canonical_json_hash
from mcpsec_core.models import LatencyMs, ToolCallEvent, parse_audit_event


def test_redaction_mode_full(tmp_path: Path) -> None:
    log_file = tmp_path / "full.jsonl"
    logger = AuditLogger(log_path=log_file, log_args="full")

    raw_args = {
        "password": "super-secret-password",
        "api_key": "AKIAIOSFODNN7EXAMPLE",
        "path": "/home/user/file.txt",
    }

    ev = logger.log_tool_call(
        session_id="s1",
        call_id="c1",
        agent_id="a1",
        server="fs",
        tool="read",
        capabilities=[],
        raw_args=raw_args,
        decision="allow",
        effective_decision="forwarded",
        decision_layer="none",
        decision_reason="ok",
        latency_ms=LatencyMs(proxy=1.0, upstream=2.0),
    )

    assert ev.args == raw_args


def test_redaction_mode_redacted(tmp_path: Path) -> None:
    log_file = tmp_path / "redacted.jsonl"
    logger = AuditLogger(log_path=log_file, log_args="redacted")

    raw_args = {
        "password": "secret-pass-val",
        "nested": {
            "token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "safe_field": "normal text with AKIA1234567890ABCDEF key embedded",
        },
        "items": [
            {"authorization": "Bearer xyz"},
            "plain string",
        ],
    }

    ev = logger.log_tool_call(
        session_id="s1",
        call_id="c1",
        agent_id="a1",
        server="fs",
        tool="read",
        capabilities=[],
        raw_args=raw_args,
        decision="allow",
        effective_decision="forwarded",
        decision_layer="none",
        decision_reason="ok",
        latency_ms=LatencyMs(proxy=1.0, upstream=2.0),
        error="Failed to connect with token ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    )

    assert ev.args["password"] == "[REDACTED]"
    assert ev.args["nested"]["token"] == "[REDACTED]"
    assert "AKIA" not in ev.args["nested"]["safe_field"]
    assert "[REDACTED]" in ev.args["nested"]["safe_field"]
    assert ev.args["items"][0]["authorization"] == "[REDACTED]"
    assert ev.error is not None
    assert "ghp_" not in ev.error
    assert "[REDACTED]" in ev.error


def test_redaction_mode_hash_only(tmp_path: Path) -> None:
    log_file = tmp_path / "hash_only.jsonl"
    logger = AuditLogger(log_path=log_file, log_args="hash_only")

    raw_args = {
        "repo": "acme/secret-repo",
        "token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    }

    ev = logger.log_tool_call(
        session_id="s1",
        call_id="c1",
        agent_id="a1",
        server="github",
        tool="clone",
        capabilities=[],
        raw_args=raw_args,
        decision="allow",
        effective_decision="forwarded",
        decision_layer="none",
        decision_reason="ok",
        latency_ms=LatencyMs(proxy=1.0, upstream=2.0),
    )

    expected_hash = canonical_json_hash(raw_args)
    assert isinstance(ev.args, dict)
    assert ev.args.get("sha256") == expected_hash

    # Verify parsed line
    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    parsed = parse_audit_event(lines[0])
    assert isinstance(parsed, ToolCallEvent)
    assert parsed.event_type == "tool_call"
    assert parsed.args == {"sha256": expected_hash}
