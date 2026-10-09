"""Policy CLI tool for mcpsec-lite (mcpsec-policy).

Provides commands:
  mcpsec-policy validate <policy_file> [--explain AGENT TOOL ARGS_JSON]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcpsec_core.models import ToolCall
from mcpsec_core.policy import PolicyError, check_policy, load_policy


def validate_policy_file(
    policy_path: Path,
    explain: list[str] | None = None,
) -> int:
    """Validate a policy YAML file and optionally explain a hypothetical tool call decision.

    Returns exit code (0 for success, 1 for error).
    """
    if not policy_path.exists():
        print(f"Error: Policy file '{policy_path}' not found", file=sys.stderr)
        return 1

    try:
        policy, p_hash, warnings = load_policy(policy_path)
    except PolicyError as err:
        print(f"Policy validation failed for '{policy_path}':", file=sys.stderr)
        for e in err.errors:
            code = e.get("code", "ERR")
            path = e.get("path", "")
            msg = e.get("message", "")
            print(f"  [{code}] {path}: {msg}", file=sys.stderr)
        if not err.errors:
            print(f"  {err}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error loading policy '{policy_path}': {exc}", file=sys.stderr)
        return 1

    print(f"Policy valid: {policy_path}")
    print(f"  Hash: {p_hash}")
    print(f"  Version: {policy.version}")
    print(f"  Mode: {policy.mode}")
    print(f"  Serialize calls: {policy.serialize_calls}")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            print(f"  - {w}")

    if explain:
        if len(explain) != 3:
            print(
                "Error: --explain requires exactly 3 arguments: AGENT TOOL ARGS_JSON",
                file=sys.stderr,
            )
            return 1

        agent_id, tool_id_arg, args_json = explain
        try:
            parsed_args = json.loads(args_json)
            if not isinstance(parsed_args, dict):
                raise ValueError("ARGS_JSON must be a JSON object")
        except Exception as exc:
            print(f"Error parsing ARGS_JSON: {exc}", file=sys.stderr)
            return 1

        if "." in tool_id_arg:
            server_part, tool_part = tool_id_arg.split(".", 1)
        else:
            server_part = "fs"
            tool_part = tool_id_arg

        hypothetical_call = ToolCall(
            call_id="explain-call-id",
            session_id="explain-session-id",
            agent_id=agent_id,
            server=server_part,
            tool=tool_part,
            args=parsed_args,
        )

        decision = check_policy(hypothetical_call, policy)
        print("\nPolicy Explanation for call:")
        print(f"  Agent: {agent_id}")
        print(f"  Tool: {server_part}.{tool_part}")
        print(f"  Arguments: {parsed_args}")
        print(f"  Decision: {decision.decision.upper()}")
        print(f"  Layer: {decision.layer}")
        print(f"  Reason: {decision.reason}")

    return 0


def main() -> None:
    """CLI entrypoint for mcpsec-policy."""
    parser = argparse.ArgumentParser(
        description="mcpsec-policy - Validate and inspect mcpsec security policies."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate policy YAML file")
    validate_parser.add_argument(
        "policy_file",
        type=Path,
        help="Path to the policy YAML file",
    )
    validate_parser.add_argument(
        "--explain",
        nargs=3,
        metavar=("AGENT", "TOOL", "ARGS_JSON"),
        help="Explain decision for hypothetical call: AGENT TOOL ARGS_JSON",
    )

    args = parser.parse_args()

    if args.command == "validate":
        code = validate_policy_file(args.policy_file, args.explain)
        sys.exit(code)


if __name__ == "__main__":
    main()
