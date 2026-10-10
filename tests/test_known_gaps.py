"""Known architectural gaps and future security milestones.

These tests are marked xfail(strict=True) to document security boundaries
that will be addressed in future weeks (Week 4-7 taint tracking, egress proxy, etc.).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import cast

import pytest

from mcpsec_core.models import ToolCall
from mcpsec_core.policy import check_policy, load_policy


@pytest.mark.xfail(
    strict=True,
    reason="Known Gap: HTTP redirect bypass. Policy evaluates initial URL domain; upstream HTTP client follows redirects to non-allowlisted internal IPs (addressed in egress filtering / Week 6).",
)
def test_known_gap_http_redirect_ssrf_bypass() -> None:
    """Demonstrate that domain allowlist checks initial URL, missing HTTP redirect to internal metadata."""
    policy_yaml = """
version: 1
mode: enforce
capabilities:
  fetch.fetch: [network_read]
policies:
  - agent: dev-agent
    tools:
      fetch.fetch:
        domain_allowlist: ["public-redirector.com"]
"""
    policy, _, _ = load_policy(policy_yaml)

    # Initial URL passes allowlist
    call = ToolCall(
        call_id="call-redirect-1",
        session_id="sess-redirect-1",
        agent_id="dev-agent",
        server="fetch",
        tool="fetch",
        args={
            "url": "https://public-redirector.com/redirect?to=http://169.254.169.254/latest/meta-data"
        },
    )
    res = check_policy(call, policy)
    assert res.decision == "allow"

    # In a future week with egress interception / redirect tracing, this call or its redirect must be blocked.
    # Currently, strict=True xfail expects this security assertion to fail.
    decision_val = cast(str, res.decision)
    assert decision_val == "deny", "Expected policy to block redirection to internal link"


@pytest.mark.xfail(
    strict=True,
    reason="Known Gap: Path TOCTOU. Symlink or directory swap between policy validation and upstream server filesystem read (addressed via file descriptor pinning / kernel namespace isolation).",
)
def test_known_gap_filesystem_symlink_toctou(tmp_path: Path) -> None:
    """Demonstrate potential TOCTOU when a directory or link is swapped concurrently after policy check."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    secret_dir = tmp_path / "secret_dir"
    secret_dir.mkdir()
    secret_file = secret_dir / "secret.env"
    secret_file.write_text("AWS_KEY=SECRET12345", encoding="utf-8")

    safe_dir = sandbox / "safe_dir"
    safe_dir.mkdir()
    safe_file = safe_dir / "safe.txt"
    safe_file.write_text("safe content", encoding="utf-8")

    junction_path = sandbox / "active_dir"

    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(safe_dir), str(junction_path))
    else:
        try:
            os.symlink(safe_dir, junction_path)
        except OSError:
            pytest.skip("Symlink creation not supported in this environment")

    policy_yaml = f"""
version: 1
mode: enforce
capabilities:
  fs.read_file: [read]
policies:
  - agent: dev-agent
    tools:
      fs.read_file:
        path_allowlist: ["{sandbox.as_posix()}/**"]
"""
    policy, _, _ = load_policy(policy_yaml)

    # 1. At check time, junction points to safe_dir inside sandbox -> ALLOW
    target_arg = junction_path / "safe.txt"
    call = ToolCall(
        call_id="call-toctou-1",
        session_id="sess-toctou-1",
        agent_id="dev-agent",
        server="fs",
        tool="read_file",
        args={"path": str(target_arg)},
    )
    res1 = check_policy(call, policy)
    assert res1.decision == "allow"

    # 2. Concurrently, attacker swaps junction to point to secret_dir outside sandbox
    if sys.platform == "win32":
        import _winapi

        os.rmdir(junction_path)
        _winapi.CreateJunction(str(secret_dir), str(junction_path))
    else:
        junction_path.unlink()
        os.symlink(secret_dir, junction_path)

    # Without open-by-handle or kernel namespace guarantees, the check was already passed
    # but subsequent read would resolve to secret outside sandbox.
    pytest.fail(
        "Resolved path cannot detect dynamic TOCTOU junction swap without kernel descriptor pinning"
    )
