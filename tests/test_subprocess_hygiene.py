"""Subprocess hygiene tests ensuring full process tree teardown and zero orphan processes."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import anyio
import pytest

from proxy.supervisor import UpstreamConfig, UpstreamManager, kill_process_tree


def _is_pid_alive(pid: int) -> bool:
    """Check whether a given PID is currently active and running."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        import ctypes.wintypes

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        code = ctypes.wintypes.DWORD()
        res = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        # 259 is STILL_ACTIVE on Windows
        return bool(res and code.value == 259)
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def _wait_for_pid(pid_file: Path, max_attempts: int = 50, delay: float = 0.1) -> int:
    """Poll for a PID to be written to a file."""
    for _ in range(max_attempts):
        if pid_file.exists():
            try:
                content = pid_file.read_text().strip()
                if content:
                    return int(content)
            except Exception:
                pass
        time.sleep(delay)
    raise TimeoutError(f"PID file '{pid_file}' was not written in time")


@pytest.mark.integration
def test_kill_process_tree_terminates_all_descendants(tmp_path: Path) -> None:
    """Verify that kill_process_tree terminates both parent and child processes in new session."""
    pid_file = tmp_path / "child.pid"

    # Child-spawning worker script
    worker_code = f"""
import subprocess, sys, time
p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open(r"{pid_file}", "w") as f:
    f.write(str(p.pid))
time.sleep(60)
"""

    kwargs: dict[str, Any] = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True

    parent_proc = subprocess.Popen([sys.executable, "-c", worker_code], **kwargs)
    parent_pid = parent_proc.pid

    # Wait for child PID to be written
    child_pid = _wait_for_pid(pid_file)

    assert _is_pid_alive(parent_pid), "Parent process should be alive before kill"
    assert _is_pid_alive(child_pid), "Child process should be alive before kill"

    # Terminate process tree
    kill_process_tree(parent_pid)
    time.sleep(0.5)

    if sys.platform != "win32":
        try:
            parent_proc.poll()
        except Exception:
            pass

    # Assert no descendants survive
    assert not _is_pid_alive(parent_pid), (
        f"Parent process PID {parent_pid} survived kill_process_tree"
    )
    assert not _is_pid_alive(child_pid), f"Child process PID {child_pid} survived kill_process_tree"
    assert _is_pid_alive(os.getpid()), "Test runner should survive kill_process_tree"


@pytest.mark.integration
def test_kill_process_tree_shared_pgid_descendant_walk(tmp_path: Path) -> None:
    """Verify that descendant walk kills descendants even when child shares proxy's PGID."""
    pid_file = tmp_path / "child_shared.pid"

    # Child-spawning worker script without start_new_session (inherits PGID)
    worker_code = f"""
import subprocess, sys, time
p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open(r"{pid_file}", "w") as f:
    f.write(str(p.pid))
time.sleep(60)
"""

    parent_proc = subprocess.Popen([sys.executable, "-c", worker_code])
    parent_pid = parent_proc.pid

    child_pid = _wait_for_pid(pid_file)

    assert _is_pid_alive(parent_pid), "Parent process should be alive before kill"
    assert _is_pid_alive(child_pid), "Child process should be alive before kill"

    # Terminate process tree
    kill_process_tree(parent_pid)
    time.sleep(0.5)

    if sys.platform != "win32":
        try:
            parent_proc.poll()
        except Exception:
            pass

    # Assert descendants are dead, but test runner survived
    assert not _is_pid_alive(parent_pid), (
        f"Parent process PID {parent_pid} survived kill_process_tree"
    )
    assert not _is_pid_alive(child_pid), f"Child process PID {child_pid} survived kill_process_tree"
    assert _is_pid_alive(os.getpid()), "Test runner must survive kill_process_tree on shared PGID"


@pytest.mark.integration
@pytest.mark.anyio
async def test_production_upstream_process_hygiene_and_crash_restart(tmp_path: Path) -> None:
    """Production path test: UpstreamManager + stdio_client spawning upstream + grandchild.

    Asserts:
    1. On clean shutdown: upstream AND grandchild are gone, test runner survives.
    2. On crash-restart: old upstream AND old grandchild are gone, new upstream is running,
       and on final shutdown, all remaining descendants are gone.
    """
    fake_script = Path(__file__).parent / "fakes" / "fake_upstream_grandchild.py"
    up_pid_file = tmp_path / "up.pid"
    gc_pid_file = tmp_path / "gc.pid"

    # -------------------------------------------------------------------------
    # Part 1: Clean shutdown path
    # -------------------------------------------------------------------------
    cfg = UpstreamConfig(
        name="hygiene-srv",
        command=sys.executable,
        args=[
            str(fake_script),
            "--upstream-pid-file",
            str(up_pid_file),
            "--grandchild-pid-file",
            str(gc_pid_file),
        ],
        required=True,
        start_timeout=10.0,
    )
    mgr = UpstreamManager([cfg])

    async with anyio.create_task_group() as tg:
        warnings = await mgr.start_all(tg)
        assert len(warnings) == 0

        up_pid = _wait_for_pid(up_pid_file)
        gc_pid = _wait_for_pid(gc_pid_file)

        assert _is_pid_alive(up_pid), "Upstream process should be alive"
        assert _is_pid_alive(gc_pid), "Grandchild process should be alive"

        # Clean shutdown
        await mgr.shutdown_all()
        tg.cancel_scope.cancel()

    await anyio.sleep(0.5)
    assert not _is_pid_alive(up_pid), f"Upstream process {up_pid} survived shutdown"
    assert not _is_pid_alive(gc_pid), f"Grandchild process {gc_pid} survived shutdown"
    assert _is_pid_alive(os.getpid()), "Test runner must survive shutdown"

    # -------------------------------------------------------------------------
    # Part 2: Crash-restart path
    # -------------------------------------------------------------------------
    up_pid_file_2 = tmp_path / "up2.pid"
    gc_pid_file_2 = tmp_path / "gc2.pid"

    cfg_restart = UpstreamConfig(
        name="crash-srv",
        command=sys.executable,
        args=[
            str(fake_script),
            "--upstream-pid-file",
            str(up_pid_file_2),
            "--grandchild-pid-file",
            str(gc_pid_file_2),
        ],
        required=True,
        start_timeout=10.0,
        max_restarts=2,
    )
    mgr_restart = UpstreamManager([cfg_restart])

    async with anyio.create_task_group() as tg_restart:
        await mgr_restart.start_all(tg_restart)

        up_pid_1 = _wait_for_pid(up_pid_file_2)
        gc_pid_1 = _wait_for_pid(gc_pid_file_2)

        assert _is_pid_alive(up_pid_1), "Upstream instance 1 should be alive"
        assert _is_pid_alive(gc_pid_1), "Grandchild instance 1 should be alive"

        # Remove pid files so we can detect when the new instance writes them
        up_pid_file_2.unlink(missing_ok=True)
        gc_pid_file_2.unlink(missing_ok=True)

        # Trigger crash of instance 1 by calling the crash tool
        try:
            await mgr_restart.call_tool("crash-srv", "crash", {})
        except Exception:
            pass  # Expected to fail due to process crash

        # Wait for supervisor to restart the upstream server
        proc = mgr_restart.servers["crash-srv"]
        await proc.wait_ready()

        up_pid_2 = _wait_for_pid(up_pid_file_2)
        gc_pid_2 = _wait_for_pid(gc_pid_file_2)

        # Instance 1 and its grandchild must be GONE
        assert not _is_pid_alive(up_pid_1), f"Crashed upstream {up_pid_1} should be dead"
        assert not _is_pid_alive(gc_pid_1), (
            f"Orphan grandchild {gc_pid_1} should be dead after crash-restart"
        )

        # Instance 2 and its grandchild must be ALIVE
        assert _is_pid_alive(up_pid_2), f"Restarted upstream {up_pid_2} should be alive"
        assert _is_pid_alive(gc_pid_2), f"Restarted grandchild {gc_pid_2} should be alive"
        assert up_pid_2 != up_pid_1, "Restarted upstream should have a new PID"
        assert _is_pid_alive(os.getpid()), "Test runner must survive crash-restart"

        # Final clean shutdown
        await mgr_restart.shutdown_all()
        tg_restart.cancel_scope.cancel()

    await anyio.sleep(0.5)
    assert not _is_pid_alive(up_pid_2), f"Restarted upstream {up_pid_2} survived shutdown"
    assert not _is_pid_alive(gc_pid_2), f"Restarted grandchild {gc_pid_2} survived shutdown"
    assert _is_pid_alive(os.getpid()), "Test runner must survive final shutdown"
