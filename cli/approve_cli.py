"""Operator CLI for human-in-the-loop approval elevation.

Usage:
  mcpsec-approve list [--log <path>] [--audit-log <path>] [--json]
  mcpsec-approve approve <call_id> [--log <path>] [--operator <name>] [--reason <text>]
  mcpsec-approve deny <call_id> [--log <path>] [--operator <name>] [--reason <text>]
  mcpsec-approve clear-taint <session_id> <label> [--log <path>] [--force] [--operator <name>]
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcpsec_core.approvals import DEFAULT_CLI_LOCK_TIMEOUT_SECONDS, ApprovalManager
from mcpsec_core.audit import Redactor


def resolve_audit_log_path(explicit_path: Path | None, approvals_log_path: Path) -> Path | None:
    """Resolve path to the audit log for extracting taint origins."""
    if explicit_path is not None and explicit_path.exists():
        return explicit_path
    candidate_next_to_approvals = approvals_log_path.parent / "audit.jsonl"
    if candidate_next_to_approvals.exists():
        return candidate_next_to_approvals
    cwd_candidate = Path("audit.jsonl")
    if cwd_candidate.exists():
        return cwd_candidate
    return explicit_path if explicit_path is not None else None


def sanitize_untrusted_text(text: str, max_length: int = 160) -> str:
    r"""Sanitize attacker-influenced text for terminal / human display.

    Escapes C0/C1 control characters (including ANSI ESC and NUL) as visible \xNN literals.
    Escapes Unicode bidirectional overrides and zero-width/formatting characters as visible \uNNNN.
    Truncates strings exceeding max_length with '...[truncated]'.
    """
    if not isinstance(text, str):
        text = str(text)

    out: list[str] = []
    for c in text:
        cp = ord(c)
        if cp < 0x20 or cp == 0x7F or (0x80 <= cp <= 0x9F):
            out.append(f"\\x{cp:02x}")
        elif (
            unicodedata.category(c) in ("Cf", "Cs")
            or (0x200B <= cp <= 0x200F)
            or (0x202A <= cp <= 0x202E)
            or (0x2060 <= cp <= 0x2069)
            or cp == 0xFEFF
        ):
            out.append(f"\\u{cp:04x}")
        else:
            out.append(c)

    escaped = "".join(out)
    if len(escaped) > max_length:
        escaped = escaped[:max_length] + "...[truncated]"
    return escaped


def sanitize_display_value(val: Any, max_length: int = 160) -> Any:
    """Recursively sanitize text within data structures for display."""
    if isinstance(val, str):
        return sanitize_untrusted_text(val, max_length=max_length)
    if isinstance(val, dict):
        return {
            sanitize_untrusted_text(str(k), max_length=max_length): sanitize_display_value(
                v, max_length=max_length
            )
            for k, v in val.items()
        }
    if isinstance(val, list):
        return [sanitize_display_value(v, max_length=max_length) for v in val]
    return val


def load_taint_sources_from_audit(audit_log_path: Path | None) -> dict[str, dict[str, list[str]]]:
    """Parse audit log to map session_id -> {taint_label: [source_tool_ids_with_destination]}."""
    if audit_log_path is None or not audit_log_path.exists():
        return {}
    sources_by_session: dict[str, dict[str, list[str]]] = {}
    try:
        with open(audit_log_path, encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                except Exception:
                    continue
                if data.get("event_type") != "tool_call":
                    continue
                sess_id = data.get("session_id")
                if not sess_id:
                    continue
                before = set(data.get("taint_before") or [])
                after = set(data.get("taint_after") or [])
                new_labels = after - before
                if new_labels:
                    srv = data.get("server", "")
                    tool = data.get("tool", "")
                    tool_id = f"{srv}.{tool}" if srv else tool
                    args = data.get("args") or {}
                    dest_info = ""
                    if isinstance(args, dict):
                        if "url" in args and args["url"]:
                            dest_info = f"url: {args['url']}"
                        elif "path" in args and args["path"]:
                            dest_info = f"path: {args['path']}"
                        elif "paths" in args and args["paths"]:
                            dest_info = f"paths: {args['paths']}"

                    if dest_info:
                        source_entry = f"{tool_id} [{dest_info}]"
                    else:
                        source_entry = tool_id

                    sess_map = sources_by_session.setdefault(sess_id, {})
                    for lbl in new_labels:
                        sess_map.setdefault(lbl, [])
                        if source_entry not in sess_map[lbl]:
                            sess_map[lbl].append(source_entry)
    except Exception:
        pass
    return sources_by_session


def extract_destination(args: Any) -> str:
    """Extract destination domain, URL, or filesystem path from tool arguments."""
    if not isinstance(args, dict):
        return "none"
    if "url" in args and args["url"]:
        u = str(args["url"])
        try:
            netloc = urllib.parse.urlsplit(u).netloc
            return f"domain: {netloc} ({u})" if netloc else f"url: {u}"
        except Exception:
            return f"url: {u}"
    if "uri" in args and args["uri"]:
        return f"uri: {args['uri']}"
    if "path" in args and args["path"]:
        return f"path: {args['path']}"
    if "paths" in args and args["paths"]:
        return f"paths: {args['paths']}"
    if "filepath" in args and args["filepath"]:
        return f"path: {args['filepath']}"
    if "file" in args and args["file"]:
        return f"path: {args['file']}"
    return "none"


def compute_timing(created_at: str, expires_at: str) -> tuple[str, str]:
    """Compute human-readable age and remaining time before expiry."""
    now = datetime.now(UTC)
    age_str = "unknown"
    time_left_str = "unknown"
    if created_at:
        try:
            c_dt = datetime.fromisoformat(created_at)
            age_sec = max(0.0, (now - c_dt).total_seconds())
            age_str = f"{age_sec:.1f}s"
        except Exception:
            age_str = created_at
    if expires_at:
        try:
            e_dt = datetime.fromisoformat(expires_at)
            diff_sec = (e_dt - now).total_seconds()
            if diff_sec <= 0:
                time_left_str = f"expired ({abs(diff_sec):.1f}s ago)"
            else:
                time_left_str = f"{diff_sec:.1f}s"
        except Exception:
            time_left_str = expires_at
    return age_str, time_left_str


def main(argv: list[str] | None = None) -> int:
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--log",
        type=Path,
        default=Path("pending_approvals.jsonl"),
        help="Path to pending approvals JSONL log",
    )
    parent_parser.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Path to audit log (defaults to audit.jsonl next to pending approvals or current directory)",
    )

    parser = argparse.ArgumentParser(
        prog="mcpsec-approve",
        parents=[parent_parser],
        description="Operator CLI for human-in-the-loop approval elevation and taint management",
    )

    subparsers = parser.add_subparsers(dest="command", help="Approval command to execute")

    # list
    list_parser = subparsers.add_parser(
        "list", parents=[parent_parser], help="List all pending approval requests"
    )
    list_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # approve
    approve_parser = subparsers.add_parser(
        "approve", parents=[parent_parser], help="Approve a pending call"
    )
    approve_parser.add_argument("call_id", type=str, help="Call ID to approve")
    approve_parser.add_argument("--operator", type=str, default="operator", help="Operator ID")
    approve_parser.add_argument(
        "--reason", type=str, default="Approved by operator", help="Approval reason"
    )

    # deny
    deny_parser = subparsers.add_parser("deny", parents=[parent_parser], help="Deny a pending call")
    deny_parser.add_argument("call_id", type=str, help="Call ID to deny")
    deny_parser.add_argument("--operator", type=str, default="operator", help="Operator ID")
    deny_parser.add_argument(
        "--reason", type=str, default="Denied by operator", help="Denial reason"
    )

    # clear-taint
    clear_parser = subparsers.add_parser(
        "clear-taint", parents=[parent_parser], help="Clear a session taint label"
    )
    clear_parser.add_argument("session_id", type=str, help="Target session ID")
    clear_parser.add_argument("label", type=str, help="Taint label to clear")
    clear_parser.add_argument(
        "--force", action="store_true", help="Force clear even if private_data"
    )
    clear_parser.add_argument("--operator", type=str, default="operator", help="Operator ID")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1

    manager = ApprovalManager(log_path=args.log, lock_timeout=DEFAULT_CLI_LOCK_TIMEOUT_SECONDS)

    if args.command == "list":
        approvals = manager.get_all_approvals()
        pending = [a for a in approvals.values() if a.status == "pending"]
        redactor = Redactor(mode="redacted")
        audit_path = resolve_audit_log_path(args.audit_log, args.log)
        audit_sources = load_taint_sources_from_audit(audit_path)

        if getattr(args, "json", False):
            out_list = [
                {
                    "call_id": a.call_id,
                    "session_id": a.session_id,
                    "agent_id": a.agent_id,
                    "tool": f"{a.server}.{a.tool}",
                    "args": redactor.redact_args(a.args),
                    "destination": extract_destination(a.args),
                    "capabilities": a.capabilities,
                    "taint_state": a.taint_state,
                    "taint_sources": {
                        label: audit_sources.get(a.session_id, {}).get(label, [])
                        for label in a.taint_state
                    },
                    "rule_id": a.rule_id,
                    "created_at": a.created_at,
                    "expires_at": a.expires_at,
                }
                for a in pending
            ]
            print(json.dumps(out_list, indent=2))
        else:
            if not pending:
                print("No pending approval requests.")
            else:
                print(f"Pending approval requests ({len(pending)}):")
                for a in pending:
                    dest = extract_destination(a.args)
                    dest_sanitized = sanitize_untrusted_text(dest)
                    redacted_args = redactor.redact_args(a.args)
                    display_args = sanitize_display_value(redacted_args)
                    age_str, time_left_str = compute_timing(a.created_at, a.expires_at)
                    sess_sources = audit_sources.get(a.session_id, {})
                    taint_items = []
                    for label in a.taint_state:
                        srcs = sess_sources.get(label)
                        if srcs:
                            sanitized_srcs = [sanitize_untrusted_text(s) for s in srcs]
                            taint_items.append(f"{label} (via {', '.join(sanitized_srcs)})")
                        else:
                            taint_items.append(label)
                    taint_display = ", ".join(taint_items) if taint_items else "none"

                    print(f"  [{sanitize_untrusted_text(a.call_id)}]")
                    print(f"    Session:      {sanitize_untrusted_text(a.session_id)}")
                    print(f"    Tool:         {sanitize_untrusted_text(f'{a.server}.{a.tool}')}")
                    print(f"    Destination:  {dest_sanitized}")
                    print(f"    Rule ID:      {sanitize_untrusted_text(a.rule_id)}")
                    print(f"    Taint:        {taint_display}")
                    print(f"    Timing:       age: {age_str}, time left: {time_left_str}")
                    print(f"    Args:         {json.dumps(display_args)}")
        return 0

    elif args.command == "approve":
        ok = manager.approve(args.call_id, operator=args.operator, reason=args.reason)
        if ok:
            print(f"Call '{sanitize_untrusted_text(args.call_id)}' approved successfully.")
            return 0
        else:
            print(
                f"Error: Call '{sanitize_untrusted_text(args.call_id)}' not found or already in terminal state.",
                file=sys.stderr,
            )
            return 1

    elif args.command == "deny":
        ok = manager.deny(args.call_id, operator=args.operator, reason=args.reason)
        if ok:
            print(f"Call '{sanitize_untrusted_text(args.call_id)}' denied successfully.")
            return 0
        else:
            print(
                f"Error: Call '{sanitize_untrusted_text(args.call_id)}' not found or already in terminal state.",
                file=sys.stderr,
            )
            return 1

    elif args.command == "clear-taint":
        ok, msg = manager.clear_taint(
            session_id=args.session_id,
            label=args.label,
            operator=args.operator,
            force=args.force,
        )
        if ok:
            print(msg)
            return 0
        else:
            print(f"Error: {msg}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
