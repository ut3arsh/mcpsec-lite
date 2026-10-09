"""Audit log replay and timeline inspection CLI for mcpsec-lite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcpsec_core.models import (
    AuditEvent,
    BaseAuditEvent,
    PolicyLoadedEvent,
    SessionEndEvent,
    SessionStartEvent,
    ToolCallEvent,
    parse_audit_event,
)


def load_audit_events(file_path: Path) -> list[AuditEvent]:
    """Read and parse all JSONL audit events from a file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Audit log file not found: {file_path}")

    events: list[AuditEvent] = []
    with open(file_path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                event = parse_audit_event(line_str)
                events.append(event)
            except Exception as exc:
                print(f"Warning: Failed to parse line {line_num}: {exc}", file=sys.stderr)
    return events


def filter_events(
    events: list[AuditEvent],
    session_id: str | None = None,
    tool: str | None = None,
    decision: str | None = None,
    agent_id: str | None = None,
    decision_layer: str | None = None,
) -> list[AuditEvent]:
    """Filter audit events based on specified criteria."""
    filtered: list[AuditEvent] = []

    for event in events:
        # Filter by session_id (exact or prefix)
        if session_id is not None:
            ev_session = getattr(event, "session_id", None)
            if not ev_session or not (
                ev_session == session_id or ev_session.startswith(session_id)
            ):
                continue

        # Filter by agent_id
        if agent_id is not None:
            ev_agent = getattr(event, "agent_id", None)
            if ev_agent is None or ev_agent != agent_id:
                continue

        # Criteria specific to ToolCallEvent
        if isinstance(event, ToolCallEvent):
            if tool is not None:
                full_tool = f"{event.server}.{event.tool}"
                if tool != event.tool and tool != full_tool and tool != event.server:
                    continue

            if decision is not None:
                dec_lower = decision.lower()
                if (
                    event.decision.lower() != dec_lower
                    and event.effective_decision.lower() != dec_lower
                ):
                    continue

            if decision_layer is not None:
                if event.decision_layer.lower() != decision_layer.lower():
                    continue
        else:
            # If filtering by tool, decision, or decision_layer, skip non-tool events
            if tool is not None or decision is not None or decision_layer is not None:
                continue

        filtered.append(event)

    return filtered


def format_timeline(events: list[AuditEvent]) -> str:
    """Format filtered events as a readable per-session timeline."""
    if not events:
        return "No audit events match the specified filters."

    # Group events by session (or global for policy_loaded)
    sessions: dict[str, list[AuditEvent]] = {}
    for ev in events:
        s_id = getattr(ev, "session_id", None) or "global"
        sessions.setdefault(s_id, []).append(ev)

    lines: list[str] = []

    for s_id, s_events in sessions.items():
        lines.append("=" * 95)
        lines.append(f"SESSION: {s_id}")
        lines.append("=" * 95)
        header = (
            f"{'TIME (UTC)':<24} {'SEQ':<5} {'EVENT':<14} "
            f"{'TOOL / DETAILS':<24} {'DECISION':<10} {'LATENCY (PROX/UP)'}"
        )
        lines.append(header)
        lines.append("-" * 95)

        for ev in s_events:
            ts = ev.timestamp
            seq_str = str(ev.seq)

            if isinstance(ev, ToolCallEvent):
                tool_label = f"{ev.server}.{ev.tool}"
                dec_str = f"{ev.decision}/{ev.effective_decision}"
                prox_ms = f"{ev.latency_ms.proxy:.2f}ms"
                up_ms = (
                    f"{ev.latency_ms.upstream:.2f}ms"
                    if ev.latency_ms.upstream is not None
                    else "n/a"
                )
                lat_str = f"{prox_ms}/{up_ms}"
                row = (
                    f"{ts:<24} {seq_str:<5} {'tool_call':<14} "
                    f"{tool_label:<24} {dec_str:<10} {lat_str}"
                )
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

        lines.append("")

    return "\n".join(lines)


def main() -> None:
    """CLI entrypoint for mcpsec-replay."""
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

    args = parser.parse_args()

    try:
        events = load_audit_events(args.file)
    except Exception as exc:
        print(f"Error loading audit log: {exc}", file=sys.stderr)
        sys.exit(1)

    filtered = filter_events(
        events,
        session_id=args.session,
        tool=args.tool,
        decision=args.decision,
        agent_id=args.agent,
        decision_layer=args.layer,
    )

    if args.json:
        for ev in filtered:
            if isinstance(ev, BaseAuditEvent):
                print(ev.model_dump_json(exclude_none=False))
            else:
                print(json.dumps(ev))
    else:
        print(format_timeline(filtered))


if __name__ == "__main__":
    main()
