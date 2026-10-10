"""Helper to run GitHub CLI commands with credentials from Git Credential Manager."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def get_token() -> str:
    env_tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if env_tok:
        return env_tok
    try:
        proc = subprocess.Popen(
            ["git-credential-manager", "get"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, _ = proc.communicate(input="protocol=https\nhost=github.com\n\n", timeout=5)
        for line in out.splitlines():
            if line.startswith("password="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def run_gh(args: list[str]) -> subprocess.CompletedProcess[str]:
    token = get_token()
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token
        env["GITHUB_TOKEN"] = token
    gh_bin = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "bin" / "gh.exe"
    if not gh_bin.exists():
        gh_bin = Path("gh")
    return subprocess.run(
        [str(gh_bin), *args],
        env=env,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    res = run_gh(sys.argv[1:])
    if res.stdout:
        print(res.stdout, end="")
    if res.stderr:
        print(res.stderr, file=sys.stderr, end="")
    sys.exit(res.returncode)
