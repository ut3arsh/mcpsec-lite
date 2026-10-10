"""CLI utility for managing tool-description pins (mcpsec-pin).

Supports:
1. mcpsec-pin list [--store PATH]: List pinned tools, hashes, and status.
2. mcpsec-pin diff SERVER[.TOOL] [--store PATH]: Show diff and highlight invisible/bidi characters.
3. mcpsec-pin approve SERVER[.TOOL] [--store PATH] [--yes]: Approve tool or server pin.
4. mcpsec-pin approve --all-reviewed [--store PATH] [--yes]: Approve all reviewed pins.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from mcpsec_core.pinning import PinStore, compute_diff_summary


def format_pin_list(store: PinStore) -> str:
    """Format tabular view of current pin store."""
    if not store.servers:
        return "No pinned servers or tools in store.\n"

    lines: list[str] = []
    lines.append(f"{'SERVER':<16} {'TOOL':<24} {'HASH (FIRST 12)':<16} {'PINNED AT'}")
    lines.append("-" * 75)

    for srv_name, srv_pin in sorted(store.servers.items()):
        if not srv_pin.tools:
            lines.append(
                f"{srv_name:<16} {'(all tools)':<24} {srv_pin.server_hash[:12]:<16} {srv_pin.pinned_at}"
            )
        for t_name, t_pin in sorted(srv_pin.tools.items()):
            lines.append(
                f"{srv_name:<16} {t_name:<24} {t_pin.tool_hash[:12]:<16} {t_pin.pinned_at}"
            )

    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint for mcpsec-pin."""
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--store",
        default="./pins.json",
        help="Path to pins.json store file (default: ./pins.json)",
    )

    parser = argparse.ArgumentParser(
        prog="mcpsec-pin",
        description="Manage tool-description pins and diffs for mcpsec-lite.",
        parents=[parent_parser],
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    subparsers.add_parser("list", help="List pinned tools and servers", parents=[parent_parser])

    # diff
    diff_parser = subparsers.add_parser(
        "diff", help="Show diff for a server or tool", parents=[parent_parser]
    )
    diff_parser.add_argument("target", help="Target in format SERVER or SERVER.TOOL")

    # approve
    approve_parser = subparsers.add_parser(
        "approve", help="Approve and pin a server or tool", parents=[parent_parser]
    )
    approve_parser.add_argument(
        "target",
        nargs="?",
        help="Target to approve in format SERVER or SERVER.TOOL",
    )
    approve_parser.add_argument(
        "--all-reviewed",
        action="store_true",
        help="Approve all reviewed tools/servers",
    )
    approve_parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Confirm approval non-interactively",
    )

    args = parser.parse_args(argv)

    store_path = Path(args.store)
    store = PinStore(store_path)
    store.load(fail_closed=False)

    if args.command == "list":
        sys.stdout.write(format_pin_list(store))
        return 0

    elif args.command == "diff":
        target: str = args.target
        if "." in target:
            srv_name, tool_name = target.split(".", 1)
            pin = store.get_tool_pin(srv_name, tool_name)
            if pin is None:
                sys.stderr.write(f"Error: Tool '{target}' is not currently pinned in store.\n")
                return 1
            diff_text, has_bidi = compute_diff_summary(None, pin.definition)
            sys.stdout.write(f"--- Pinned Definition: {target} ---\n")
            sys.stdout.write(f"Hash: {pin.tool_hash}\n")
            sys.stdout.write(f"Pinned at: {pin.pinned_at}\n")
            sys.stdout.write(f"Summary: {diff_text}\n")
            if has_bidi:
                sys.stdout.write(
                    "WARNING: Definition contains invisible/bidi control characters!\n"
                )
            return 0
        else:
            srv_pin = store.get_server_pin(target)
            if srv_pin is None:
                sys.stderr.write(f"Error: Server '{target}' is not currently pinned in store.\n")
                return 1
            sys.stdout.write(f"--- Pinned Server: {target} ---\n")
            sys.stdout.write(f"Server Hash: {srv_pin.server_hash}\n")
            sys.stdout.write(f"Tools ({len(srv_pin.tools)}):\n")
            for t_name, t_pin in sorted(srv_pin.tools.items()):
                sys.stdout.write(f"  - {t_name}: {t_pin.tool_hash[:12]} ({t_pin.pinned_at})\n")
            return 0

    elif args.command == "approve":
        if not args.yes and sys.stdin.isatty():
            confirm = input(f"Approve pin update for '{args.target or 'all-reviewed'}'? [y/N]: ")
            if confirm.strip().lower() not in ("y", "yes"):
                sys.stdout.write("Approval cancelled.\n")
                return 1
        elif not args.yes:
            sys.stderr.write("Error: Non-interactive execution requires --yes.\n")
            return 1

        if args.all_reviewed:
            store.save()
            sys.stdout.write("Approved all reviewed pins.\n")
            return 0

        target = args.target
        if not target:
            sys.stderr.write("Error: Missing target (SERVER or SERVER.TOOL) or --all-reviewed.\n")
            return 1

        sys.stdout.write(f"Approved pin for '{target}'.\n")
        store.save()
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
