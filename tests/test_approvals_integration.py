"""Approval queue wake latency, race condition, and session isolation tests.

Proves:
1. A held call wakes on approve, deny, and timeout with measurable sub-millisecond to low-millisecond latency.
2. Exactly one terminal outcome is recorded when approve races timeout under concurrent contention.
3. Holds belonging to two different sessions are strictly isolated.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import anyio
import pytest

from mcpsec_core.approvals import ApprovalManager
from proxy.session import ProxySession


class _DummyUpstreamManager:
    async def call_tool(self, server_name: str, tool_name: str, arguments: dict[str, Any]) -> Any:
        return MagicMock()


def _create_test_session(
    tmp_path: Path, session_id: str, approval_manager: ApprovalManager
) -> ProxySession:
    dummy_audit = MagicMock()
    return ProxySession(
        session_id=session_id,
        upstream_manager=_DummyUpstreamManager(),  # type: ignore[arg-type]
        audit_logger=dummy_audit,
        approval_manager=approval_manager,
    )


@pytest.mark.asyncio
@pytest.mark.timeout(10.0)
async def test_held_call_wakes_on_approve_measure_latency(tmp_path: Path) -> None:
    """A held call wakes immediately when approved; measure wake latency."""
    log_file = tmp_path / "approvals_wake_approve.jsonl"
    mgr = ApprovalManager(log_file)
    session = _create_test_session(tmp_path, "session-1", mgr)

    call_id = "call-wake-appr"
    mgr.request_approval(
        call_id=call_id,
        session_id="session-1",
        agent_id="dev-agent",
        server="srv",
        tool="dangerous_tool",
        args={},
        capabilities=["write"],
        taint_state=[],
        rule_id="require-approval",
        timeout_seconds=5.0,
    )

    t_signal = 0.0

    async def _approve_after_delay() -> None:
        nonlocal t_signal
        await asyncio.sleep(0.05)
        t_signal = time.perf_counter()
        mgr.approve(call_id, operator="admin", reason="approved for test")

    async with anyio.create_task_group() as tg:
        tg.start_soon(_approve_after_delay)
        res = await session._await_approval(call_id, timeout_seconds=5.0)
        t_wake = time.perf_counter()

    wake_latency_ms = (t_wake - t_signal) * 1000.0
    assert res is True
    assert 0.0 <= wake_latency_ms < 50.0, f"Wake latency {wake_latency_ms:.2f}ms exceeded 50ms"
    assert mgr.get_all_approvals()[call_id].status == "approved"


@pytest.mark.asyncio
@pytest.mark.timeout(10.0)
async def test_held_call_wakes_on_deny_measure_latency(tmp_path: Path) -> None:
    """A held call wakes immediately when denied; measure wake latency."""
    log_file = tmp_path / "approvals_wake_deny.jsonl"
    mgr = ApprovalManager(log_file)
    session = _create_test_session(tmp_path, "session-1", mgr)

    call_id = "call-wake-deny"
    mgr.request_approval(
        call_id=call_id,
        session_id="session-1",
        agent_id="dev-agent",
        server="srv",
        tool="dangerous_tool",
        args={},
        capabilities=["write"],
        taint_state=[],
        rule_id="require-approval",
        timeout_seconds=5.0,
    )

    t_signal = 0.0

    async def _deny_after_delay() -> None:
        nonlocal t_signal
        await asyncio.sleep(0.05)
        t_signal = time.perf_counter()
        mgr.deny(call_id, operator="admin", reason="denied for test")

    async with anyio.create_task_group() as tg:
        tg.start_soon(_deny_after_delay)
        res = await session._await_approval(call_id, timeout_seconds=5.0)
        t_wake = time.perf_counter()

    wake_latency_ms = (t_wake - t_signal) * 1000.0
    assert res is False
    assert 0.0 <= wake_latency_ms < 50.0, f"Wake latency {wake_latency_ms:.2f}ms exceeded 50ms"
    assert mgr.get_all_approvals()[call_id].status == "denied"


@pytest.mark.asyncio
@pytest.mark.timeout(10.0)
async def test_held_call_wakes_on_timeout_measure_latency(tmp_path: Path) -> None:
    """A held call wakes cleanly when timeout duration expires."""
    log_file = tmp_path / "approvals_wake_timeout.jsonl"
    mgr = ApprovalManager(log_file)
    session = _create_test_session(tmp_path, "session-1", mgr)

    call_id = "call-wake-timeout"
    mgr.request_approval(
        call_id=call_id,
        session_id="session-1",
        agent_id="dev-agent",
        server="srv",
        tool="dangerous_tool",
        args={},
        capabilities=["write"],
        taint_state=[],
        rule_id="require-approval",
        timeout_seconds=0.1,
    )

    t_start = time.perf_counter()
    res = await session._await_approval(call_id, timeout_seconds=0.1)
    duration_ms = (time.perf_counter() - t_start) * 1000.0

    assert res is False
    assert 90.0 <= duration_ms < 250.0, f"Duration {duration_ms:.2f}ms outside expected range"
    assert mgr.get_all_approvals()[call_id].status == "timeout"


@pytest.mark.timeout(15.0)
def test_approve_races_timeout_exactly_one_outcome(tmp_path: Path) -> None:
    """Concurrent race between approve and record_timeout produces exactly one outcome."""
    log_file = tmp_path / "approvals_race.jsonl"
    mgr = ApprovalManager(log_file)

    for i in range(30):
        call_id = f"race-call-{i}"
        mgr.request_approval(
            call_id=call_id,
            session_id=f"sess-{i}",
            agent_id="dev-agent",
            server="srv",
            tool="tool",
            args={},
            capabilities=["read"],
            taint_state=[],
            rule_id="r1",
            timeout_seconds=1.0,
        )

        def do_approve(target_id: str = call_id) -> None:
            mgr.approve(target_id, operator="admin", reason="race approve")

        def do_timeout(target_id: str = call_id) -> None:
            mgr.record_timeout(target_id)

        t1 = threading.Thread(target=do_approve)
        t2 = threading.Thread(target=do_timeout)

        # Start almost simultaneously
        t1.start()
        t2.start()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)

        # Check final derived state
        apprs = mgr.get_all_approvals()
        assert call_id in apprs
        status = apprs[call_id].status
        assert status in ("approved", "timeout"), f"Invalid terminal status: {status}"

    # Verify JSONL log: each call_id must have exactly 1 'requested' and exactly 1 terminal event
    with open(log_file, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    for i in range(30):
        cid = f"race-call-{i}"
        cid_events = [e for e in events if e.get("call_id") == cid]
        assert len(cid_events) == 2, f"Expected exactly 2 events for {cid}, got {len(cid_events)}"
        assert cid_events[0]["event"] == "requested"
        assert cid_events[1]["event"] in ("approved", "timeout")


@pytest.mark.asyncio
@pytest.mark.timeout(10.0)
async def test_two_sessions_holds_are_isolated(tmp_path: Path) -> None:
    """Holds for two distinct sessions are completely isolated."""
    log_file = tmp_path / "approvals_isolated.jsonl"
    mgr = ApprovalManager(log_file)
    session1 = _create_test_session(tmp_path, "session-A", mgr)
    session2 = _create_test_session(tmp_path, "session-B", mgr)
    assert session2.session_id == "session-B"

    call_1 = "call-sess-A"
    call_2 = "call-sess-B"

    mgr.request_approval(
        call_id=call_1,
        session_id="session-A",
        agent_id="dev-agent",
        server="srv",
        tool="toolA",
        args={},
        capabilities=["write"],
        taint_state=[],
        rule_id="ruleA",
        timeout_seconds=5.0,
    )
    mgr.request_approval(
        call_id=call_2,
        session_id="session-B",
        agent_id="dev-agent",
        server="srv",
        tool="toolB",
        args={},
        capabilities=["write"],
        taint_state=[],
        rule_id="ruleB",
        timeout_seconds=5.0,
    )

    apprs = mgr.get_all_approvals()
    assert apprs[call_1].status == "pending"
    assert apprs[call_2].status == "pending"

    # Background task approves ONLY call_1
    async def _approve_call_1_only() -> None:
        await asyncio.sleep(0.02)
        mgr.approve(call_1, operator="op1", reason="ok")

    async with anyio.create_task_group() as tg:
        tg.start_soon(_approve_call_1_only)
        res1 = await session1._await_approval(call_1, timeout_seconds=2.0)

    assert res1 is True
    # Session 2's call_2 MUST still be pending!
    apprs = mgr.get_all_approvals()
    assert apprs[call_1].status == "approved"
    assert apprs[call_2].status == "pending"

    # Now deny call_2
    mgr.deny(call_2, operator="op2", reason="denied")
    apprs = mgr.get_all_approvals()
    assert apprs[call_1].status == "approved"
    assert apprs[call_2].status == "denied"

    # Terminal state rejections:
    # 1. Denying an already approved call returns False
    assert mgr.deny(call_1) is False
    # 2. Approving an already denied call returns False
    assert mgr.approve(call_2) is False
    # 3. Approving or denying a non-existent call returns False
    assert mgr.approve("non_existent_call") is False
    assert mgr.deny("non_existent_call") is False

    # 4. Listener callback as callable
    called = False

    def listener_cb() -> None:
        nonlocal called
        called = True

    mgr.register_listener("call-cb", listener_cb)
    mgr._notify_listener("call-cb")
    assert called is True
    mgr.unregister_listener("call-cb")


@pytest.mark.asyncio
@pytest.mark.timeout(15.0)
async def test_cross_process_approval_with_real_cli(tmp_path: Path) -> None:
    """ProxySession holds a call, real mcpsec-approve CLI approves in separate process, measuring latency."""
    log_file = tmp_path / "approvals_cli.jsonl"
    mgr = ApprovalManager(log_file)
    session = _create_test_session(tmp_path, "session-cli", mgr)

    call_id = "call-cross-proc-1"
    mgr.request_approval(
        call_id=call_id,
        session_id="session-cli",
        agent_id="dev-agent",
        server="srv",
        tool="write_file",
        args={"path": "test.txt"},
        capabilities=["write"],
        taint_state=[],
        rule_id="req-appr",
        timeout_seconds=5.0,
    )

    wake_latency_ms: float = 0.0

    async def _cli_approver() -> None:
        # Wait until request is on disk
        await asyncio.sleep(0.05)
        nonlocal wake_latency_ms
        cli_proc = await anyio.to_thread.run_sync(
            lambda: subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "cli.approve_cli",
                    "approve",
                    call_id,
                    "--log",
                    str(log_file),
                    "--operator",
                    "security-admin",
                    "--reason",
                    "CLI cross-process approved",
                ],
                capture_output=True,
                text=True,
            )
        )
        cli_finish = time.perf_counter()
        assert cli_proc.returncode == 0, f"CLI stderr: {cli_proc.stderr}"
        # Record CLI finish time to compare against session wake
        _cli_approver.finish_time = cli_finish  # type: ignore[attr-defined]

    _cli_approver.finish_time = time.perf_counter()  # type: ignore[attr-defined]

    async with anyio.create_task_group() as tg:
        tg.start_soon(_cli_approver)
        res = await session._await_approval(call_id, timeout_seconds=5.0, poll_interval=0.03)
        wake_time = time.perf_counter()

    assert res is True
    wake_latency_ms = (wake_time - _cli_approver.finish_time) * 1000.0  # type: ignore[attr-defined]
    # Wake latency should be under 150ms with 30ms polling interval
    assert wake_latency_ms < 150.0, f"Wake latency was {wake_latency_ms:.2f}ms (must be < 150ms)"

    appr = mgr.get_approval(call_id)
    assert appr is not None
    assert appr.status == "approved"
    assert appr.operator == "security-admin"
    assert appr.reason == "CLI cross-process approved"


@pytest.mark.asyncio
@pytest.mark.timeout(15.0)
async def test_proxy_restart_rebuilds_state_and_rejects_late_approval(tmp_path: Path) -> None:
    """Proxy restart rebuilds approval state; late approval never releases an expired/timed-out call."""
    log_file = tmp_path / "approvals_restart.jsonl"
    mgr1 = ApprovalManager(log_file)
    session1 = _create_test_session(tmp_path, "session-restart", mgr1)

    call_id = "call-timed-out-before-restart"
    mgr1.request_approval(
        call_id=call_id,
        session_id="session-restart",
        agent_id="dev-agent",
        server="srv",
        tool="write_file",
        args={"path": "test.txt"},
        capabilities=["write"],
        taint_state=[],
        rule_id="req-appr",
        timeout_seconds=0.2,
    )

    # Let the call time out in session 1
    res = await session1._await_approval(call_id, timeout_seconds=0.2, poll_interval=0.03)
    assert res is False
    assert mgr1.get_approval(call_id) is not None
    assert mgr1.get_approval(call_id).status == "timeout"  # type: ignore[union-attr]

    # --- SIMULATE PROXY RESTART ---
    # New ApprovalManager and new session connected to the existing approvals log
    mgr2 = ApprovalManager(log_file)
    _session2 = _create_test_session(tmp_path, "session-restarted", mgr2)

    # 1. State is accurately reconstructed from the file
    reconstructed = mgr2.get_approval(call_id)
    assert reconstructed is not None
    assert reconstructed.status == "timeout"

    # 2. Late approval from real CLI fails closed and does NOT release the timed out call
    cli_proc = await anyio.to_thread.run_sync(
        lambda: subprocess.run(
            [
                sys.executable,
                "-m",
                "cli.approve_cli",
                "approve",
                call_id,
                "--log",
                str(log_file),
                "--operator",
                "late-admin",
            ],
            capture_output=True,
            text=True,
        )
    )
    # CLI must fail with non-zero exit code because request already reached terminal state
    assert cli_proc.returncode != 0
    assert "terminal state" in cli_proc.stderr

    # In-memory and on-disk state remains timeout
    appr_after_cli = mgr2.get_approval(call_id)
    assert appr_after_cli is not None
    assert appr_after_cli.status == "timeout"

    # 3. Late approval on expired request (expires_at passed while proxy was offline)
    call_id_expired = "call-expired-during-downtime"
    mgr2.request_approval(
        call_id=call_id_expired,
        session_id="session-restarted",
        agent_id="dev-agent",
        server="srv",
        tool="write_file",
        args={},
        capabilities=["write"],
        taint_state=[],
        rule_id="req-appr",
        timeout_seconds=0.05,
    )
    # Wait for expires_at to pass
    await asyncio.sleep(0.1)

    # New proxy manager instance comes online
    mgr3 = ApprovalManager(log_file)
    ok = mgr3.approve(call_id_expired, operator="admin", reason="late approve attempt")
    # Must reject late approval on expired call
    assert ok is False
    assert mgr3.get_approval(call_id_expired) is not None
    assert mgr3.get_approval(call_id_expired).status == "timeout"  # type: ignore[union-attr]
