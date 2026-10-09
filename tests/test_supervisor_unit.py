"""Unit tests for supervisor lifecycle, backoff, timeouts, and fake clock/sleep injection."""

from __future__ import annotations

import pytest

from proxy.supervisor import UpstreamConfig, UpstreamManager, UpstreamProcess, sanitize_upstream_env


class FakeClock:
    """Deterministic fake clock and sleep recorder for millisecond unit testing."""

    def __init__(self, start_time: float = 1000.0) -> None:
        self.current_time = start_time
        self.sleep_durations: list[float] = []

    def time(self) -> float:
        return self.current_time

    async def sleep(self, duration: float) -> None:
        self.sleep_durations.append(duration)
        self.current_time += duration


def test_sanitize_upstream_env_strips_sensitive_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure parent process secrets like AWS/GitHub keys are not inherited by upstreams."""
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", "ghp_secret123456")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws_secret_abcdef")
    monkeypatch.setenv("MY_CUSTOM_VAR", "should_be_stripped")

    # Base clean environment should not have these
    clean = sanitize_upstream_env(user_env={"DECLARED_ALLOWED": "true"})
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in clean
    assert "AWS_SECRET_ACCESS_KEY" not in clean
    assert "MY_CUSTOM_VAR" not in clean
    assert clean["DECLARED_ALLOWED"] == "true"


def test_upstream_manager_name_validation() -> None:
    """Validate server naming constraints: ^[a-z][a-z0-9-]*$, no dots or double underscores."""
    # Valid names
    UpstreamManager([UpstreamConfig(name="github", command="python")])
    UpstreamManager([UpstreamConfig(name="fetch-server", command="python")])

    # Duplicate names
    with pytest.raises(ValueError, match="Duplicate upstream"):
        UpstreamManager(
            [
                UpstreamConfig(name="github", command="python"),
                UpstreamConfig(name="github", command="python"),
            ]
        )

    # Invalid names (uppercase, dots, underscores, double underscores)
    for bad_name in ["GitHub", "git_hub", "git..hub", "git__hub", "123git", "-git"]:
        with pytest.raises(ValueError, match="Invalid"):
            UpstreamManager([UpstreamConfig(name=bad_name, command="python")])


@pytest.mark.asyncio
async def test_supervisor_with_fake_clock_injection() -> None:
    """Verify that UpstreamProcess and UpstreamManager accept injected fake clock/sleep."""
    clock = FakeClock()

    cfg = UpstreamConfig(
        name="test-server",
        command="python",
        args=["-c", "import sys; sys.exit(1)"],
        start_timeout=5.0,
        call_timeout=2.0,
    )

    proc = UpstreamProcess(cfg, sleep_fn=clock.sleep, time_fn=clock.time)
    assert proc.time_fn() == 1000.0

    # Calling tool on unhealthy process fails fast
    with pytest.raises(RuntimeError, match="unhealthy or degraded"):
        await proc.call_tool("some_tool", {})
