"""Operator CLI for human-in-the-loop approval elevation.

Usage:
  mcpsec-approve list [--log <path>] [--json]
  mcpsec-approve approve <call_id> [--log <path>] [--operator <name>] [--reason <text>]
  mcpsec-approve deny <call_id> [--log <path>] [--operator <name>] [--reason <text>]
  mcpsec-approve clear-taint <session_id> <label> [--log <path>] [--force] [--operator <name>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcpsec_core.approvals import ApprovalManager


def main(argv: list[str] | None = None) -> int:
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--log",
        type=Path,
        default=Path("pending_approvals.jsonl"),
        help="Path to pending approvals JSONL log",
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

    manager = ApprovalManager(log_path=args.log)

    if args.command == "list":
        approvals = manager.get_all_approvals()
        pending = [a for a in approvals.values() if a.status == "pending"]
        if getattr(args, "json", False):
            out_list = [
                {
                    "call_id": a.call_id,
                    "session_id": a.session_id,
                    "agent_id": a.agent_id,
                    "tool": f"{a.server}.{a.tool}",
                    "args": a.args,
                    "capabilities": a.capabilities,
                    "taint_state": a.taint_state,
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
                    print(
                        f"  [{a.call_id}] tool={a.server}.{a.tool} session={a.session_id} taint={a.taint_state}"
                    )
        return 0

    elif args.command == "approve":
        ok = manager.approve(args.call_id, operator=args.operator, reason=args.reason)
        if ok:
            print(f"Call '{args.call_id}' approved successfully.")
            return 0
        else:
            print(
                f"Error: Call '{args.call_id}' not found or already in terminal state.",
                file=sys.stderr,
            )
            return 1

    elif args.command == "deny":
        ok = manager.deny(args.call_id, operator=args.operator, reason=args.reason)
        if ok:
            print(f"Call '{args.call_id}' denied successfully.")
            return 0
        else:
            print(
                f"Error: Call '{args.call_id}' not found or already in terminal state.",
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
