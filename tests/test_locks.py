"""Cross-platform fault-injection tests for PinStore and ApprovalManager locks.

Proves:
1. When another process holds the file lock, acquiring with a timeout raises LockTimeout.
2. Nothing is written to pins.json or pending_approvals.jsonl while locked.
3. Once the other process releases the lock, subsequent operations succeed cleanly.
4. In-process threading lock timeout raises LockTimeout fail-closed.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mcpsec_core.approvals import _APPROVAL_PROCESS_LOCK, ApprovalManager, file_lock
from mcpsec_core.approvals import LockTimeout as ApprovalLockTimeout
from mcpsec_core.pinning import _PIN_PROCESS_LOCK, PinStore, _pin_file_lock
from mcpsec_core.pinning import LockTimeout as PinLockTimeout

_LOCK_HELPER_SCRIPT = """
import os, sys

lock_path = sys.argv[1]
with open(lock_path, "a+b") as f:
    fd = f.fileno()
    if sys.platform == "win32":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    sys.stdout.write("LOCKED\\n")
    sys.stdout.flush()
    try:
        sys.stdin.read()
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
    else:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:
            pass
"""


@pytest.mark.timeout(15.0)
def test_pin_store_lock_fault_injection(tmp_path: Path) -> None:
    """When another process holds the lock, PinStore raises LockTimeout and writes nothing."""
    store_file = tmp_path / "pins.json"
    lock_file = tmp_path / "pins.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_file.touch()

    proc = subprocess.Popen(
        [sys.executable, "-c", _LOCK_HELPER_SCRIPT, str(lock_file)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        ready = proc.stdout.readline().strip()
        assert ready == "LOCKED", f"Helper failed to lock: {ready}"

        store = PinStore(store_file, lock_timeout=0.2)

        # 1. Assert save raises LockTimeout and writes nothing
        with pytest.raises(PinLockTimeout):
            store.save()
        assert not store_file.exists(), "pins.json should not have been created"

        # 2. Assert approve_tool raises LockTimeout and writes nothing
        with pytest.raises(PinLockTimeout):
            store.approve_tool(
                "srv",
                {"name": "test_tool", "description": "desc", "inputSchema": {}},
            )
        assert not store_file.exists(), "pins.json should not exist after failed approve_tool"

    finally:
        if proc.stdin:
            try:
                proc.stdin.close()
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

    # 3. Once other process releases, operation succeeds
    store = PinStore(store_file, lock_timeout=2.0)
    pin = store.approve_tool(
        "srv",
        {"name": "test_tool", "description": "desc", "inputSchema": {}},
    )
    assert pin.tool_hash != ""
    assert store_file.exists()


@pytest.mark.timeout(15.0)
def test_approval_manager_lock_fault_injection(tmp_path: Path) -> None:
    """When another process holds the lock, ApprovalManager raises LockTimeout and writes nothing."""
    log_file = tmp_path / "pending_approvals.jsonl"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.touch()

    proc = subprocess.Popen(
        [sys.executable, "-c", _LOCK_HELPER_SCRIPT, str(log_file)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        ready = proc.stdout.readline().strip()
        assert ready == "LOCKED", f"Helper failed to lock: {ready}"

        mgr = ApprovalManager(log_file, lock_timeout=0.2)

        # 1. Assert request_approval raises LockTimeout and writes nothing
        with pytest.raises(ApprovalLockTimeout):
            mgr.request_approval(
                call_id="call-fail-1",
                session_id="session-1",
                agent_id="agent-1",
                server="server-1",
                tool="tool-1",
                args={"cmd": "ls"},
                capabilities=["read"],
                taint_state=[],
                rule_id="rule-1",
            )

        assert log_file.stat().st_size == 0, "log file should be empty after failed write"

    finally:
        if proc.stdin:
            try:
                proc.stdin.close()
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

    # 2. Once released, request_approval succeeds
    mgr = ApprovalManager(log_file, lock_timeout=2.0)
    req = mgr.request_approval(
        call_id="call-ok-1",
        session_id="session-1",
        agent_id="agent-1",
        server="server-1",
        tool="tool-1",
        args={"cmd": "ls"},
        capabilities=["read"],
        taint_state=[],
        rule_id="rule-1",
    )
    assert req.call_id == "call-ok-1"
    assert log_file.stat().st_size > 0


@pytest.mark.timeout(10.0)
def test_in_process_thread_lock_timeout_pinning(tmp_path: Path) -> None:
    """When another thread holds _PIN_PROCESS_LOCK, acquire raises LockTimeout."""
    lock_file = tmp_path / "pins.lock"
    lock_file.touch()

    acquired_evt = threading.Event()
    release_evt = threading.Event()

    def hold_lock() -> None:
        with _PIN_PROCESS_LOCK:
            acquired_evt.set()
            release_evt.wait(timeout=5.0)

    th = threading.Thread(target=hold_lock, daemon=True)
    th.start()
    assert acquired_evt.wait(timeout=2.0)

    try:
        with open(lock_file, "a+b") as f:
            with pytest.raises(PinLockTimeout) as exc_info:
                with _pin_file_lock(f, timeout=0.1):
                    pass
            assert "in-process PinStore lock" in str(exc_info.value)
    finally:
        release_evt.set()
        th.join(timeout=2.0)


@pytest.mark.timeout(10.0)
def test_in_process_thread_lock_timeout_approvals(tmp_path: Path) -> None:
    """When another thread holds _APPROVAL_PROCESS_LOCK, acquire raises LockTimeout."""
    lock_file = tmp_path / "appr.lock"
    lock_file.touch()

    acquired_evt = threading.Event()
    release_evt = threading.Event()

    def hold_lock() -> None:
        with _APPROVAL_PROCESS_LOCK:
            acquired_evt.set()
            release_evt.wait(timeout=5.0)

    th = threading.Thread(target=hold_lock, daemon=True)
    th.start()
    assert acquired_evt.wait(timeout=2.0)

    try:
        with open(lock_file, "a+b") as f:
            with pytest.raises(ApprovalLockTimeout) as exc_info:
                with file_lock(f, timeout=0.1):
                    pass
            assert "in-process approvals lock" in str(exc_info.value)
    finally:
        release_evt.set()
        th.join(timeout=2.0)
