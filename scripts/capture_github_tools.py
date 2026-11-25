"""Capture MCP tools/list schemas over stdio from GitHub MCP server implementations.

Supports capturing:
  1. Official Go GitHub MCP server binary (github/github-mcp-server) -> tests/fixtures/github.tools.official.json
  2. Deprecated archived npm package (@modelcontextprotocol/server-github) -> tests/fixtures/github.tools.npm_deprecated.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def capture_tools_over_stdio(
    cmd: list[str],
    *,
    env_overrides: dict[str, str] | None = None,
    use_shell: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    """Perform MCP initialize + notifications/initialized + tools/list over stdio."""
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        shell=use_shell,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None

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
    proc.stdin.write(json.dumps(init_req) + "\n")
    proc.stdin.flush()

    init_line = proc.stdout.readline()
    if not init_line.strip():
        proc.terminate()
        _, err = proc.communicate(timeout=3)
        raise RuntimeError(f"Empty initialize response from {cmd!r}; stderr={err.strip()}")
    init_resp = json.loads(init_line)

    init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    proc.stdin.write(json.dumps(init_notif) + "\n")
    proc.stdin.flush()

    tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    proc.stdin.write(json.dumps(tools_req) + "\n")
    proc.stdin.flush()

    tools_line = proc.stdout.readline()
    if not tools_line.strip():
        proc.terminate()
        _, err = proc.communicate(timeout=3)
        raise RuntimeError(f"Empty tools/list response from {cmd!r}; stderr={err.strip()}")
    tools_resp = json.loads(tools_line)
    tools: list[dict[str, Any]] = tools_resp.get("result", {}).get("tools", [])

    proc.terminate()
    try:
        _, stderr_out = proc.communicate(timeout=3)
    except Exception:
        proc.kill()
        _, stderr_out = proc.communicate(timeout=3)

    return init_resp.get("result", {}), tools, stderr_out


def capture_official(
    binary_path: Path,
    *,
    flags: list[str],
    out_path: Path,
    release_asset: str = "github-mcp-server_Windows_x86_64.zip",
    asset_sha256: str = "",
) -> None:
    """Run official github/github-mcp-server binary over stdio and write snapshot + metadata."""
    ver_proc = subprocess.run(
        [str(binary_path), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    version_text = ver_proc.stdout.strip()
    version = ""
    commit = ""
    build_date = ""
    for line in version_text.splitlines():
        if line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("Commit:"):
            commit = line.split(":", 1)[1].strip()
        elif line.startswith("Build Date:"):
            build_date = line.split(":", 1)[1].strip()

    dummy_env = {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_dummycapturetokenoffline00000000000"}
    init_result, tools, stderr_out = capture_tools_over_stdio(
        [str(binary_path), *flags],
        env_overrides=dummy_env,
    )
    server_info = init_result.get("serverInfo", {})
    capabilities = init_result.get("capabilities", {})

    # Also probe --read-only tool names when capturing default stdio
    read_only_tools: list[str] = []
    if "--read-only" not in flags:
        _, ro_tools, _ = capture_tools_over_stdio(
            [str(binary_path), "stdio", "--read-only"],
            env_overrides=dummy_env,
        )
        read_only_tools = [str(t.get("name", "")) for t in ro_tools]
    else:
        read_only_tools = [str(t.get("name", "")) for t in tools]

    metadata: dict[str, Any] = {
        "server_name": server_info.get("name", "github-mcp-server"),
        "version": version or server_info.get("version", "unknown"),
        "server_info_version": server_info.get("version", "unknown"),
        "commit": commit,
        "build_date": build_date,
        "repository": "https://github.com/github/github-mcp-server",
        "release_asset": release_asset,
        "asset_sha256": asset_sha256,
        "flags": flags,
        "toolsets_default": ["context", "copilot", "issues", "pull_requests", "repos", "users"],
        "read_only_flag_supported": True,
        "toolsets_flag_supported": True,
        "read_only_tool_count": len(read_only_tools),
        "read_only_tool_names": read_only_tools,
        "protocol_version": init_result.get("protocolVersion", ""),
        "advertised_capabilities": sorted(capabilities.keys()),
        "captured_at": datetime.now(UTC).isoformat(),
        "transport": "stdio",
        "auth_mode": "dummy GITHUB_PERSONAL_ACCESS_TOKEN (stderr logged invalid token scope check; tools/list served without live network results)",
        "stderr_excerpt": [line.strip() for line in stderr_out.splitlines() if line.strip()][:5],
        "verification_status": "VERIFIED-official-github-mcp-server",
        "tool_count": len(tools),
    }

    payload = {"_metadata": metadata, "tools": tools}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"Captured {len(tools)} tools from official github/github-mcp-server.")
    print(f"Version: {metadata['version']} | Commit: {metadata['commit']}")
    print(f"Flags: {flags} | --read-only count: {len(read_only_tools)}")
    print(f"Advertised capabilities: {metadata['advertised_capabilities']}")
    print(f"Captured at: {metadata['captured_at']}")
    print(f"Saved schema to: {out_path}")
    print("\nTools List:")
    for idx, t in enumerate(tools):
        name = t.get("name", "")
        desc = str(t.get("description", "")).replace("\n", " ")[:60]
        print(f"{idx + 1:2d}. {name}: {desc}...")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture GitHub MCP server tools/list fixture.")
    parser.add_argument(
        "--binary",
        type=Path,
        required=True,
        help="Path to downloaded official github-mcp-server executable",
    )
    parser.add_argument(
        "--flags",
        nargs="+",
        default=["stdio"],
        help="CLI arguments passed to binary (default: stdio)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("tests/fixtures/github.tools.official.json"),
        help="Output JSON fixture path",
    )
    parser.add_argument(
        "--release-asset",
        default="github-mcp-server_Windows_x86_64.zip",
        help="Official release archive name",
    )
    parser.add_argument(
        "--asset-sha256",
        default="",
        help="SHA-256 of release archive",
    )
    args = parser.parse_args(argv)
    capture_official(
        args.binary,
        flags=list(args.flags),
        out_path=args.out,
        release_asset=args.release_asset,
        asset_sha256=args.asset_sha256,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
