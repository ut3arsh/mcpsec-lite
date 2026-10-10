"""Subprocess hygiene tests ensuring full process tree teardown and zero orphan processes."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from proxy.supervisor import kill_process_tree


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


@pytest.mark.integration
def test_kill_process_tree_terminates_all_descendants(tmp_path: Path) -> None:
    """Verify that kill_process_tree terminates both parent and child processes without leaks."""
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
    child_pid = None
    for _ in range(50):
        if pid_file.exists():
            try:
                child_pid = int(pid_file.read_text().strip())
                break
            except Exception:
                pass
        time.sleep(0.1)

    assert child_pid is not None, "Worker script failed to spawn child process"
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
