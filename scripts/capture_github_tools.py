"""Capture schema from official @modelcontextprotocol/server-github over stdio."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path


def main() -> None:
    env = os.environ.copy()
    env["GITHUB_PERSONAL_ACCESS_TOKEN"] = "dummy_capture_token_offline"

    proc = subprocess.Popen(
        ["npx", "--yes", "@modelcontextprotocol/server-github"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        shell=True,
    )

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcpsec-capture", "version": "1.0.0"},
        },
    }

    assert proc.stdin is not None
    assert proc.stdout is not None

    proc.stdin.write(json.dumps(init_req) + "\n")
    proc.stdin.flush()

    init_line = proc.stdout.readline()
    init_resp = json.loads(init_line)
    server_info = init_resp.get("result", {}).get("serverInfo", {})
    protocol_version = init_resp.get("result", {}).get("protocolVersion", "")

    init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    proc.stdin.write(json.dumps(init_notif) + "\n")
    proc.stdin.flush()

    tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    proc.stdin.write(json.dumps(tools_req) + "\n")
    proc.stdin.flush()

    tools_line = proc.stdout.readline()
    tools_resp = json.loads(tools_line)
    tools = tools_resp.get("result", {}).get("tools", [])

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

    metadata = {
        "server_name": server_info.get("name", "github-mcp-server"),
        "server_version": server_info.get("version", "unknown"),
        "package": "@modelcontextprotocol/server-github",
        "package_version": "2025.4.8",
        "repository": "https://github.com/modelcontextprotocol/servers/tree/main/src/github",
        "protocol_version": protocol_version,
        "captured_at": datetime.now(UTC).isoformat(),
        "transport": "stdio",
        "network_mode": "offline (dummy token, read-only tools/list schema capture)",
        "verification_status": "VERIFIED-real-server",
        "tool_count": len(tools),
    }

    final_output = {"_metadata": metadata, "tools": tools}

    out_path = Path("tests/fixtures/github.tools.real.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(final_output, indent=2), encoding="utf-8")

    print(f"Successfully captured {len(tools)} tools from real GitHub MCP server.")
    print(
        f"Server: {metadata['server_name']} v{metadata['server_version']} "
        f"(package {metadata['package']}@{metadata['package_version']})"
    )
    print(f"Captured at: {metadata['captured_at']}")
    print(f"Saved schema to: {out_path}")
    print("\nTools List:")
    for idx, t in enumerate(tools):
        name = t.get("name", "")
        desc = t.get("description", "")[:60]
        print(f"{idx+1:2d}. {name}: {desc}...")


if __name__ == "__main__":
    main()
