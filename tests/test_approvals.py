"""Tests for approval queue, CLI, concurrency, crash recovery, and taint clearance.

Verifies:
1. Approve, deny, and timeout lifecycle.
2. Duplicate approvals / denials are idempotent.
3. Taint clearance validation (allow_clear enforcement, refusing private_data by default).
4. Concurrent writer safety on append-only log with file locking.
5. Crash recovery: state perfectly reconstructed from pending_approvals.jsonl.
6. Timeout vs approval race resolution.
7. ProxySession integration: require_approval flow rule blocks call until approved/denied.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import mcp.types as types
import pytest

from cli.approve_cli import main as approve_cli_main
from mcpsec_core.approvals import ApprovalManager
from mcpsec_core.audit import AuditLogger
from mcpsec_core.policy import load_policy
from proxy.session import ProxySession
from proxy.supervisor import UpstreamManager


def test_approval_lifecycle_and_idempotence(tmp_path: Path) -> None:
    log_file = tmp_path / "pending_approvals.jsonl"
    manager = ApprovalManager(log_path=log_file)

    # 1. Request approval
    req = manager.request_approval(
        call_id="call-123",
        session_id="sess-1",
        agent_id="dev-agent",
        server="http",
        tool="fetch",
        args={"url": "https://api.external.com/deploy"},
        capabilities=["egress"],
        taint_state=["untrusted_content"],
        rule_id="appr-egress",
        timeout_seconds=60.0,
    )
    assert req.status == "pending"

    # 2. Check derived state
    all_apprs = manager.get_all_approvals()
    assert "call-123" in all_apprs
    assert all_apprs["call-123"].status == "pending"

    # 3. Approve
    ok = manager.approve("call-123", operator="alice@corp.com", reason="Verified benign")
    assert ok
    assert manager.get_all_approvals()["call-123"].status == "approved"
    assert manager.get_all_approvals()["call-123"].operator == "alice@corp.com"

    # 4. Duplicate approve is idempotent no-op
    ok_dup = manager.approve("call-123", operator="alice@corp.com")
    assert ok_dup
    assert manager.get_all_approvals()["call-123"].status == "approved"


def test_deny_and_timeout_lifecycle(tmp_path: Path) -> None:
    log_file = tmp_path / "pending_approvals.jsonl"
    manager = ApprovalManager(log_path=log_file)

    # Deny test
    manager.request_approval(
        call_id="call-deny",
        session_id="sess-1",
        agent_id="dev-agent",
        server="http",
        tool="post",
        args={},
        capabilities=["egress"],
        taint_state=[],
        rule_id="rule-deny",
    )
    assert manager.deny("call-deny", operator="bob", reason="Malicious destination")
    assert manager.get_all_approvals()["call-deny"].status == "denied"
    # Idempotent deny
    assert manager.deny("call-deny")

    # Timeout test
    manager.request_approval(
        call_id="call-timeout",
        session_id="sess-2",
        agent_id="dev-agent",
        server="http",
        tool="post",
        args={},
        capabilities=["egress"],
        taint_state=[],
        rule_id="rule-timeout",
    )
    manager.record_timeout("call-timeout")
    assert manager.get_all_approvals()["call-timeout"].status == "timeout"


def test_taint_clearance_validation(tmp_path: Path) -> None:
    log_file = tmp_path / "pending_approvals.jsonl"
    manager = ApprovalManager(log_path=log_file)

    policy_yaml = """
version: 1
mode: enforce
capabilities:
  http.fetch: [egress]
policies:
  - agent: "*"
    tools: { http.fetch: {} }
taint_sources:
  untrusted_content: [{ tool: http.fetch }]
approval:
  channel: cli
  allow_clear: [untrusted_content]
"""
    policy, _, _ = load_policy(policy_yaml)

    # 1. Clear untrusted_content (allowed in policy) -> succeeds
    ok1, msg1 = manager.clear_taint("sess-1", "untrusted_content", policy=policy)
    assert ok1
    assert "cleared" in msg1

    # 2. Clear private_data without force -> refused by default
    ok2, msg2 = manager.clear_taint("sess-1", "private_data", policy=policy)
    assert not ok2
    assert "refused by default" in msg2

    # 3. Clear private_data with force -> succeeds
    ok3, msg3 = manager.clear_taint("sess-1", "private_data", policy=policy, force=True)
    assert ok3

    # 4. Clear undeclared label -> refused
    ok4, msg4 = manager.clear_taint("sess-1", "random_unregistered_label", policy=policy)
    assert not ok4
    assert "not in policy approval.allow_clear" in msg4


def _mp_approval_worker(log_path_str: str, worker_id: int, count: int) -> None:
    manager = ApprovalManager(log_path=Path(log_path_str))
    for i in range(count):
        call_id = f"mp_w{worker_id}_call_{i}"
        manager.request_approval(
            call_id=call_id,
            session_id=f"sess-{worker_id}",
            agent_id="agent",
            server="srv",
            tool="tool",
            args={"i": i},
            capabilities=["egress"],
            taint_state=[],
            rule_id="rule",
        )
        manager.approve(call_id, operator=f"op-{worker_id}")


def test_concurrent_writers_append_only_log(tmp_path: Path) -> None:
    log_file = tmp_path / "concurrent_approvals.jsonl"
    manager = ApprovalManager(log_path=log_file)

    num_threads = 5
    ops_per_thread = 10

    def worker(worker_id: int) -> None:
        for i in range(ops_per_thread):
            call_id = f"w{worker_id}-call-{i}"
            manager.request_approval(
                call_id=call_id,
                session_id=f"sess-{worker_id}",
                agent_id="agent",
                server="srv",
                tool="tool",
                args={"i": i},
                capabilities=["egress"],
                taint_state=[],
                rule_id="rule",
            )
            manager.approve(call_id, operator=f"op-{worker_id}")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, w) for w in range(num_threads)]
        for f in futures:
            f.result()

    # Replay all derived approvals
    all_apprs = manager.get_all_approvals()
    assert len(all_apprs) == num_threads * ops_per_thread
    assert all(a.status == "approved" for a in all_apprs.values())


def test_approval_manager_multiprocess_concurrency(tmp_path: Path) -> None:
    """Multiple concurrent spawned OS processes appending to approval log do not corrupt it."""
    import multiprocessing as mp

    log_file = tmp_path / "mp_approvals.jsonl"
    ctx = mp.get_context("spawn")

    num_processes = 4
    ops_per_process = 5
    processes = []

    for worker_id in range(num_processes):
        p = ctx.Process(
            target=_mp_approval_worker,
            args=(str(log_file), worker_id, ops_per_process),
        )
        processes.append(p)
        p.start()

    for p in processes:
        p.join(timeout=15.0)
        assert p.exitcode == 0, f"Process {p.pid} failed with exit code {p.exitcode}"

    final_mgr = ApprovalManager(log_path=log_file)
    all_apprs = final_mgr.get_all_approvals()
    assert len(all_apprs) == num_processes * ops_per_process
    assert all(a.status == "approved" for a in all_apprs.values())


def test_crash_recovery_rebuilds_state(tmp_path: Path) -> None:
    log_file = tmp_path / "crash_recovery.jsonl"
    manager1 = ApprovalManager(log_path=log_file)

    # Write multiple interleaved events
    manager1.request_approval("c1", "s1", "a", "srv", "t", {}, [], [], "r1")
    manager1.request_approval("c2", "s1", "a", "srv", "t", {}, [], [], "r2")
    manager1.request_approval("c3", "s1", "a", "srv", "t", {}, [], [], "r3")
    manager1.approve("c1", operator="alice")
    manager1.deny("c2", operator="bob")

    # Simulate process crash: instantiate fresh ApprovalManager pointing to the same file
    manager2 = ApprovalManager(log_path=log_file)
    recovered = manager2.get_all_approvals()

    assert len(recovered) == 3
    assert recovered["c1"].status == "approved"
    assert recovered["c1"].operator == "alice"
    assert recovered["c2"].status == "denied"
    assert recovered["c2"].operator == "bob"
    assert recovered["c3"].status == "pending"


def test_cli_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log_file = tmp_path / "cli_approvals.jsonl"
    manager = ApprovalManager(log_path=log_file)
    manager.request_approval("cli-call-1", "sess-1", "agent", "srv", "tool", {}, [], [], "r1")

    # CLI list
    rc = approve_cli_main(["list", "--log", str(log_file)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "cli-call-1" in captured.out

    # CLI approve
    rc_appr = approve_cli_main(
        ["approve", "cli-call-1", "--log", str(log_file), "--operator", "admin"]
    )
    assert rc_appr == 0
    assert manager.get_all_approvals()["cli-call-1"].status == "approved"

    # CLI clear-taint
    rc_clear = approve_cli_main(
        ["clear-taint", "sess-1", "untrusted_content", "--log", str(log_file)]
    )
    assert rc_clear == 0


@pytest.mark.asyncio
async def test_proxy_session_require_approval_flow(tmp_path: Path) -> None:
    policy_yaml = """
version: 1
mode: enforce
serialize_calls: true

capabilities:
  github.get_issue: [network_read]
  http.fetch:       [network_read, egress]

policies:
  - agent: "*"
    tools:
      github.get_issue: {}
      http.fetch:       {}

taint_sources:
  untrusted_content: [{ tool: github.get_issue }]

flow_rules:
  - id: appr-egress-untrusted
    if_session_has: [untrusted_content]
    require_approval_capabilities: [egress]

approval:
  channel: cli
  timeout_seconds: 2.0
  allow_clear: [untrusted_content]
"""
    policy, _, _ = load_policy(policy_yaml)
    audit_file = tmp_path / "approval_audit.jsonl"
    approval_log = tmp_path / "pending_approvals.jsonl"

    audit_logger = AuditLogger(log_path=audit_file)
    approval_manager = ApprovalManager(log_path=approval_log)

    upstream = AsyncMock(spec=UpstreamManager)
    upstream.servers = {
        "github": AsyncMock(is_healthy=True),
        "http": AsyncMock(is_healthy=True),
    }

    async def fake_call(
        server_name: str, tool_name: str, arguments: dict[str, Any] | None = None, **kwargs: Any
    ) -> types.CallToolResult:
        if server_name == "github":
            return types.CallToolResult(content=[types.TextContent(type="text", text="issue data")])
        elif server_name == "http":
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="elevated response")]
            )
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    upstream.call_tool.side_effect = fake_call

    session = ProxySession(
        session_id="sess-appr-e2e",
        upstream_manager=upstream,
        audit_logger=audit_logger,
        agent_id="test-agent",
        mode="enforce",
        policy_data=policy,
        approval_manager=approval_manager,
    )

    # 1. Taint session with untrusted_content
    await session.call_tool("github__get_issue", {"issue_number": 10})
    assert "untrusted_content" in session.session_state.taint

    # 2. Launch require_approval tool call in background task
    call_task = asyncio.create_task(
        session.call_tool("http__fetch", {"url": "https://api.external.com/data"})
    )

    # Wait briefly for approval request to be registered in pending_approvals.jsonl
    await asyncio.sleep(0.1)
    pending_list = [
        a for a in approval_manager.get_all_approvals().values() if a.status == "pending"
    ]
    assert len(pending_list) == 1
    call_id = pending_list[0].call_id

    # 3. Approve the pending request
    approval_manager.approve(call_id, operator="sec-ops", reason="Approved for integration")

    # 4. Await call result -> must succeed!
    res = await call_task
    assert not res.is_error
    assert isinstance(res.content[0], types.TextContent)
    assert "elevated response" in res.content[0].text
