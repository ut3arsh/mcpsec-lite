"""Pytest fixtures and configuration for mcpsec-lite test suite."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings

# ---------------------------------------------------------------------------
# Hypothesis Profile Configuration
# ---------------------------------------------------------------------------
settings.register_profile(
    "dev",
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

settings.register_profile(
    "ci",
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

profile_name = os.environ.get("HYPOTHESIS_PROFILE", "dev")
settings.load_profile(profile_name)


# ---------------------------------------------------------------------------
# Session-Scoped Server Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def local_filesystem_server_info() -> tuple[str, list[str]]:
    """Return command and args for locally installed @modelcontextprotocol/server-filesystem.

    Avoids using 'npx -y' or network downloads inside tests.
    """
    root_dir = Path(__file__).parent.parent
    local_script = (
        root_dir
        / "node_modules"
        / "@modelcontextprotocol"
        / "server-filesystem"
        / "dist"
        / "index.js"
    )

    node_bin = shutil.which("node.exe") or shutil.which("node")

    if local_script.exists() and node_bin:
        return node_bin, [str(local_script)]

    # Fallback to npx if node_modules not yet present
    npx_bin = shutil.which("npx.cmd") or shutil.which("npx")
    if npx_bin:
        return npx_bin, ["-y", "@modelcontextprotocol/server-filesystem"]

    pytest.skip("Neither local node script nor npx found for filesystem server")
    return "", []


@pytest.fixture(scope="session")
def fake_github_server_info() -> tuple[str, list[str]]:
    """Return command and args for in-process fake GitHub server."""
    import sys

    return sys.executable, ["-m", "tests.fakes.fake_github"]


@pytest.fixture(scope="session")
def fake_fetch_server_info() -> tuple[str, list[str]]:
    """Return command and args for in-process fake Fetch server."""
    import sys

    return sys.executable, ["-m", "tests.fakes.fake_fetch"]
