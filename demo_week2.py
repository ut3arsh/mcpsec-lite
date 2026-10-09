#!/usr/bin/env python3
"""Week 2 Demo Script for mcpsec-lite.

Demonstrates:
1. Allowed in-allowlist file read.
2. Denied path traversal escape (../../).
3. Denied symlink escape.
4. Denied non-allowlisted tool call.
5. Inspection of resulting audit log entries (generic agent response vs full audit forensic record).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import parse_audit_event
from mcpsec_core.policy import load_policy
from proxy.session import ProxySession
from tests.test_server import create_test_fs_server


async def run_demo() -> None:
    print("=" * 80)
    print("MCPSEC-LITE WEEK 2 DEMO: Policy Engine & Default-Deny Enforcement")
    print("=" * 80)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()

        allowed_file = sandbox / "report.txt"
        allowed_file.write_text("Confidential Project Status: On Track.", encoding="utf-8")

        secret_file = secrets / "passwords.txt"
        secret_file.write_text("ADMIN_PASSWORD=super_secret_token_12345", encoding="utf-8")

        symlink_supported = True
        symlink_file = sandbox / "symlink_escape.txt"
        try:
            symlink_file.symlink_to(secret_file)
        except (OSError, NotImplementedError):
            symlink_supported = False

        # 1. Define Policy
        policy_yaml = f"""version: 1
capabilities:
  fs.read_file: [read]
  fs.list_directory: [read]
  fs.write_file: [write]

policies:
  - agent: "analyst-agent"
    tools:
      fs.read_file:
        path_allowlist: ["{sandbox.as_posix()}/**"]
      fs.list_directory:
        path_allowlist: ["{sandbox.as_posix()}/**"]
"""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(policy_yaml, encoding="utf-8", newline="\n")

        print(f"\n[+] Loading policy from: {policy_file}")
        policy, policy_hash, warnings = load_policy(policy_file)
        print(f"    Policy Hash: {policy_hash}")
        print(f"    Loaded rules for agents: {list(policy.agent_rules.keys())}")
        if warnings:
            print(f"    Warnings: {warnings}")

        audit_log = tmp_path / "audit.jsonl"
        audit_logger = AuditLogger(log_path=audit_log)

        # 2. Setup Upstream Server and Proxy Session
        upstream_server = create_test_fs_server(tmp_path)

        up_c2s_w, up_c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        up_s2c_w, up_s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

        agent_c2s_w, agent_c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        agent_s2c_w, agent_s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

        proxy_server = Server("mcpsec-proxy")

        async with anyio.create_task_group() as tg:

            async def run_upstream() -> None:
                await upstream_server.run(
                    up_c2s_r,
                    up_s2c_w,
                    upstream_server.create_initialization_options(),
                    raise_exceptions=True,
                )

            tg.start_soon(run_upstream)

            async with ClientSession(up_s2c_r, up_c2s_w) as upstream_client:
                await upstream_client.initialize()

                proxy_session = ProxySession(
                    session_id="demo-session-w2",
                    upstream_session=upstream_client,
                    audit_logger=audit_logger,
                    server_name="fs",
                    policy_hash=policy_hash,
                    agent_id="analyst-agent",
                    mode="enforce",
                    policy_data=policy,
                )
                proxy_session.start()

                async def handle_list_tools(
                    req_ctx: Any,
                    params: types.PaginatedRequestParams,
                ) -> types.ListToolsResult:
                    return await proxy_session.list_tools()

                async def handle_call_tool(
                    req_ctx: Any,
                    params: types.CallToolRequestParams,
                ) -> types.CallToolResult:
                    return await proxy_session.call_tool(
                        name=params.name,
                        arguments=params.arguments,
                    )

                proxy_server.add_request_handler(
                    "tools/list", types.PaginatedRequestParams, handle_list_tools
                )
                proxy_server.add_request_handler(
                    "tools/call", types.CallToolRequestParams, handle_call_tool
                )

                async def run_proxy_srv() -> None:
                    await proxy_server.run(
                        agent_c2s_r,
                        agent_s2c_w,
                        proxy_server.create_initialization_options(),
                        raise_exceptions=True,
                    )

                tg.start_soon(run_proxy_srv)

                async with ClientSession(agent_s2c_r, agent_c2s_w) as client:
                    await client.initialize()

                    # Test Case 1: In-allowlist read (ALLOWED)
                    print("\n" + "-" * 80)
                    print("TEST 1: In-allowlist read (sandbox/report.txt)")
                    print("-" * 80)
                    res1 = await client.call_tool("read_file", {"path": str(allowed_file)})
                    print(f"Agent received is_error: {res1.is_error}")
                    if isinstance(res1.content[0], types.TextContent):
                        print(f"Agent received content : '{res1.content[0].text}'")

                    # Test Case 2: Path traversal escape (DENIED)
                    print("\n" + "-" * 80)
                    print("TEST 2: Path traversal escape (sandbox/../../secrets/passwords.txt)")
                    print("-" * 80)
                    traversal_path = str(sandbox / ".." / "secrets" / "passwords.txt")
                    res2 = await client.call_tool("read_file", {"path": traversal_path})
                    print(f"Agent received is_error: {res2.is_error}")
                    if isinstance(res2.content[0], types.TextContent):
                        print(f"Agent received content : '{res2.content[0].text}'")

                    # Test Case 3: Symlink escape (DENIED)
                    print("\n" + "-" * 80)
                    print("TEST 3: Symlink escape attempt")
                    print("-" * 80)
                    if symlink_supported:
                        res3 = await client.call_tool("read_file", {"path": str(symlink_file)})
                        print(f"Agent received is_error: {res3.is_error}")
                        if isinstance(res3.content[0], types.TextContent):
                            print(f"Agent received content : '{res3.content[0].text}'")
                    else:
                        print("  [i] Symlinks not supported/permitted without privilege; skipping.")

                    # Test Case 4: Non-allowlisted tool (DENIED)
                    print("\n" + "-" * 80)
                    print("TEST 4: Non-allowlisted tool call (fs.write_file)")
                    print("-" * 80)
                    res4 = await client.call_tool(
                        "write_file", {"path": str(allowed_file), "content": "pwned"}
                    )
                    print(f"Agent received is_error: {res4.is_error}")
                    if isinstance(res4.content[0], types.TextContent):
                        print(f"Agent received content : '{res4.content[0].text}'")

                    proxy_session.close(reason="shutdown")
                    tg.cancel_scope.cancel()

        print("\n" + "=" * 80)
        print("AUDIT LOG INSPECTION (Structured JSONL)")
        print("=" * 80)
        audit_lines = audit_log.read_text(encoding="utf-8").strip().split("\n")
        for i, line in enumerate(audit_lines, 1):
            _ = parse_audit_event(line)
            ev_json = json.loads(line)
            print(f"\n[Event #{i}] {ev_json.get('event_type')}")
            print(f"  Timestamp : {ev_json.get('ts')}")
            if ev_json.get("event_type") == "tool_call":
                print(f"  Tool      : {ev_json.get('tool')}")
                print(
                    f"  Decision  : {ev_json.get('decision')} "
                    f"(effective: {ev_json.get('effective_decision')})"
                )
                print(f"  Reason    : {ev_json.get('decision_reason')}")
                print(f"  Layer     : {ev_json.get('decision_layer')}")
                print(f"  Caps      : {ev_json.get('capabilities')}")
                print(f"  Pin Status: {ev_json.get('pin_status')}")
            elif ev_json.get("event_type") == "policy_loaded":
                print(f"  Hash      : {ev_json.get('policy_hash')}")
            elif ev_json.get("event_type") == "session_start":
                print(f"  Agent     : {ev_json.get('agent_id')} | Mode: {ev_json.get('mode')}")

    print("\n[+] Demo completed successfully.")


if __name__ == "__main__":
    anyio.run(run_demo)
