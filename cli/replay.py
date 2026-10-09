"""Audit log streaming replay and index CLI for mcpsec-lite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

from mcpsec_core.models import (
    AuditEvent,
    BaseAuditEvent,
    PolicyLoadedEvent,
    SessionEndEvent,
    SessionStartEvent,
    ToolCallEvent,
    parse_audit_event,
)

SAMPLE_BYTES = 4096


def compute_sample_hashes(file_path: Path) -> tuple[int, str, str]:
    """Compute file size and SHA-256 hashes of head and tail bytes for index validation."""
    size = file_path.stat().st_size
    if size == 0:
        return 0, hashlib.sha256(b"").hexdigest(), hashlib.sha256(b"").hexdigest()

    with open(file_path, "rb") as f:
        head_bytes = f.read(min(SAMPLE_BYTES, size))
        head_hash = hashlib.sha256(head_bytes).hexdigest()

        if size <= SAMPLE_BYTES:
            tail_hash = head_hash
        else:
            f.seek(max(0, size - SAMPLE_BYTES))
            tail_bytes = f.read(SAMPLE_BYTES)
            tail_hash = hashlib.sha256(tail_bytes).hexdigest()

    return size, head_hash, tail_hash


def build_sidecar_index(file_path: Path) -> dict[str, Any]:
    """Build or rebuild sidecar index mapping session_id -> list of byte offsets.

    Idempotent and atomic write. Never the authoritative source of truth.
    """
    size, head_hash, tail_hash = compute_sample_hashes(file_path)
    sessions_map: dict[str, list[int]] = {}

    with open(file_path, "rb") as f:
        offset = 0
        for line in f:
            line_len = len(line)
            stripped = line.strip()
            if stripped:
                try:
                    data = json.loads(stripped.decode("utf-8"))
                    sess_id = data.get("session_id")
                    if sess_id:
                        sessions_map.setdefault(sess_id, []).append(offset)
                except Exception:
                    pass
            offset += line_len

    idx_data: dict[str, Any] = {
        "version": 1,
        "file_size": size,
        "head_hash": head_hash,
        "tail_hash": tail_hash,
        "sessions": sessions_map,
    }

    # Write atomically in same directory
    idx_path = file_path.with_suffix(".jsonl.idx")
    temp_idx = file_path.with_suffix(f".tmp.{os.getpid()}.idx")
    try:
        with open(temp_idx, "w", encoding="utf-8") as f:
            json.dump(idx_data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_idx, idx_path)
    except Exception:
        if temp_idx.exists():
            try:
                temp_idx.unlink()
            except Exception:
                pass

    return idx_data


def get_or_create_index(file_path: Path) -> dict[str, Any]:
    """Retrieve existing index if valid, or rebuild if missing/stale."""
    idx_path = file_path.with_suffix(".jsonl.idx")
    if idx_path.exists():
        try:
            with open(idx_path, encoding="utf-8") as f:
                idx_data = json.load(f)
            curr_size, curr_head, curr_tail = compute_sample_hashes(file_path)
            if (
                isinstance(idx_data, dict)
                and idx_data.get("file_size") == curr_size
                and idx_data.get("head_hash") == curr_head
                and idx_data.get("tail_hash") == curr_tail
            ):
                return cast(dict[str, Any], idx_data)
        except Exception:
            pass

    return build_sidecar_index(file_path)


def stream_audit_events(
    file_path: Path,
    session_id: str | None = None,
) -> Generator[tuple[AuditEvent, int], None, tuple[int, int]]:
    """Stream audit events from log file in constant memory.

    Yields (AuditEvent, line_number).
    Returns (total_valid_events, malformed_count).
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Audit log file not found: {file_path}")

    malformed_count = 0
    valid_count = 0

    # If exact session_id given and indexed, we can seek by byte offsets
    idx = get_or_create_index(file_path) if session_id else None
    if idx and session_id in idx.get("sessions", {}):
        offsets = idx["sessions"][session_id]
        with open(file_path, "rb") as f:
            for offset in offsets:
                f.seek(offset)
                line_bytes = f.readline()
                stripped = line_bytes.strip()
                if not stripped:
                    continue
                try:
                    event = parse_audit_event(stripped.decode("utf-8"))
                    valid_count += 1
                    yield event, 0
                except Exception:
                    malformed_count += 1
        return valid_count, malformed_count

    # Otherwise stream sequentially line by line (constant memory)
    with open(file_path, "rb") as f:
        for line_num, line_bytes in enumerate(f, 1):
            stripped = line_bytes.strip()
            if not stripped:
                continue
            try:
                event = parse_audit_event(stripped.decode("utf-8"))
                valid_count += 1
                yield event, line_num
            except Exception:
                malformed_count += 1

    return valid_count, malformed_count


def matches_filter(
    event: AuditEvent,
    session_id: str | None = None,
    tool: str | None = None,
    decision: str | None = None,
    agent_id: str | None = None,
    decision_layer: str | None = None,
) -> bool:
    """Check if an audit event satisfies the filter criteria."""
    if session_id is not None:
        ev_session = getattr(event, "session_id", None)
        if not ev_session or not (ev_session == session_id or ev_session.startswith(session_id)):
            return False

    if agent_id is not None:
        ev_agent = getattr(event, "agent_id", None)
        if ev_agent is None or ev_agent != agent_id:
            return False

    if isinstance(event, ToolCallEvent):
        if tool is not None:
            full_tool = f"{event.server}.{event.tool}"
            if tool != event.tool and tool != full_tool and tool != event.server:
                return False

        if decision is not None:
            dec_lower = decision.lower()
            if (
                event.decision.lower() != dec_lower
                and event.effective_decision.lower() != dec_lower
            ):
                return False

        if decision_layer is not None:
            if event.decision_layer.lower() != decision_layer.lower():
                return False
    else:
        if tool is not None or decision is not None or decision_layer is not None:
            return False

    return True


def format_event_row(ev: AuditEvent) -> list[str]:
    """Format an individual event into rows for streaming output."""
    lines: list[str] = []
    ts = ev.timestamp
    seq_str = str(ev.seq)

    if isinstance(ev, ToolCallEvent):
        tool_label = f"{ev.server}.{ev.tool}"
        dec_str = f"{ev.decision}/{ev.effective_decision}"
        prox_ms = f"{ev.latency_ms.proxy:.2f}ms"
        up_ms = f"{ev.latency_ms.upstream:.2f}ms" if ev.latency_ms.upstream is not None else "n/a"
        lat_str = f"{prox_ms}/{up_ms}"
        row = f"{ts:<24} {seq_str:<5} {'tool_call':<14} {tool_label:<24} {dec_str:<10} {lat_str}"
        lines.append(row)
        if ev.taint_before != ev.taint_after:
            lines.append(f"  └─ Taint change: {ev.taint_before} -> {ev.taint_after}")
        if ev.response_summary:
            res_sum = (
                f"  └─ Summary: status={ev.response_summary.status}, "
                f"bytes={ev.response_summary.bytes}"
            )
            lines.append(res_sum)
        if ev.error:
            lines.append(f"  └─ Error: {ev.error}")

    elif isinstance(ev, SessionStartEvent):
        details = f"agent={ev.agent_id} mode={ev.mode}"
        row = f"{ts:<24} {seq_str:<5} {'session_start':<14} {details:<24} {'-':<10} -"
        lines.append(row)

    elif isinstance(ev, SessionEndEvent):
        details = f"reason={ev.reason} calls={ev.call_count}"
        row = f"{ts:<24} {seq_str:<5} {'session_end':<14} {details:<24} {'-':<10} -"
        lines.append(row)
        lines.append(f"  └─ Final taint: {ev.final_taint}, Denies: {ev.deny_count}")

    elif isinstance(ev, PolicyLoadedEvent):
        details = Path(ev.policy_path).name
        row = f"{ts:<24} {seq_str:<5} {'policy_loaded':<14} {details:<24} {'-':<10} -"
        lines.append(row)

    else:
        row = f"{ts:<24} {seq_str:<5} {ev.event_type:<14} {'-':<24} {'-':<10} -"
        lines.append(row)

    return lines


def main() -> None:
    """CLI entrypoint for mcpsec-replay with streaming execution."""
    parser = argparse.ArgumentParser(
        description="mcpsec-replay - Replay and inspect MCP audit logs."
    )
    parser.add_argument(
        "--file",
        "-f",
        type=Path,
        required=True,
        help="Path to the JSONL audit log file",
    )
    parser.add_argument(
        "--session",
        "-s",
        type=str,
        default=None,
        help="Filter by session ID (or prefix)",
    )
    parser.add_argument(
        "--tool",
        "-t",
        type=str,
        default=None,
        help="Filter by tool name (e.g. read_file or fs.read_file)",
    )
    parser.add_argument(
        "--decision",
        "-d",
        type=str,
        default=None,
        help="Filter by decision (allow, deny, require_approval, forwarded, blocked)",
    )
    parser.add_argument(
        "--agent",
        type=str,
        default=None,
        help="Filter by agent ID",
    )
    parser.add_argument(
        "--layer",
        type=str,
        default=None,
        help="Filter by decision layer (policy, flow, pinning, none)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output matching events as raw JSON Lines",
    )
    parser.add_argument(
        "--build-index",
        action="store_true",
        help="Explicitly rebuild the sidecar index file",
    )

    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File '{args.file}' not found", file=sys.stderr)
        sys.exit(1)

    if args.build_index:
        idx = build_sidecar_index(args.file)
        print(f"Sidecar index built for {args.file} ({len(idx['sessions'])} sessions indexed)")
        return

    if not args.json:
        header = (
            f"{'TIME (UTC)':<24} {'SEQ':<5} {'EVENT':<14} "
            f"{'TOOL / DETAILS':<24} {'DECISION':<10} {'LATENCY (PROX/UP)'}"
        )
        print("=" * 95)
        print(f"REPLAY LOG: {args.file}")
        print("=" * 95)
        print(header)
        print("-" * 95)

    count_matched = 0
    malformed_count = 0

    try:
        stream = stream_audit_events(args.file, session_id=args.session)
        for ev, _line_num in stream:
            if matches_filter(
                ev,
                session_id=args.session,
                tool=args.tool,
                decision=args.decision,
                agent_id=args.agent,
                decision_layer=args.layer,
            ):
                count_matched += 1
                if args.json:
                    if isinstance(ev, BaseAuditEvent):
                        print(ev.model_dump_json(exclude_none=False))
                    else:
                        print(json.dumps(ev))
                else:
                    for row in format_event_row(ev):
                        print(row)
    except Exception as exc:
        print(f"Error during replay streaming: {exc}", file=sys.stderr)
        sys.exit(1)

    if malformed_count > 0:
        print(f"\nWarning: Skipped {malformed_count} malformed line(s)", file=sys.stderr)

    if not args.json and count_matched == 0:
        print("No audit events match the specified filters.")


if __name__ == "__main__":
    main()
