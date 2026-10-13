"""Audit dependencies from hashed lock file and enforce dated, justified ignores."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


def load_ignores(ignore_file: Path) -> list[tuple[str, str, str]]:
    """Load and validate dated, justified ignores from ignore file.

    Returns a list of (vuln_id, date_str, justification).
    Fails closed if any uncommented line fails format validation.
    """
    if not ignore_file.exists():
        return []

    date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    ignores: list[tuple[str, str, str]] = []

    with open(ignore_file, encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                raise ValueError(
                    f"{ignore_file}:{line_no}: Invalid ignore entry. "
                    "Must follow format: <VULN_ID> <YYYY-MM-DD> <JUSTIFICATION>"
                )

            vuln_id, date_str, justification = parts
            if not date_pattern.match(date_str):
                raise ValueError(
                    f"{ignore_file}:{line_no}: Invalid date '{date_str}'. "
                    "Must be in YYYY-MM-DD format."
                )

            ignores.append((vuln_id, date_str, justification))

    return ignores


def append_github_step_summary(
    lock_file: Path,
    ignores: list[tuple[str, str, str]],
    returncode: int,
    stdout: str,
    stderr: str,
) -> None:
    """Write pip-audit result to $GITHUB_STEP_SUMMARY if running in GitHub Actions."""
    summary_path_str = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path_str:
        return

    summary_path = Path(summary_path_str)
    lines: list[str] = [
        "### 🔒 Dependency Vulnerability Audit (`pip-audit`)",
        f"- **Audited Lockfile:** `{lock_file}` (Hashed Lockfile, `--require-hashes --strict`)",
    ]

    if returncode == 0:
        lines.append("- **Audit Status:** ✅ **PASSED** (No unignored vulnerabilities found)")
    else:
        lines.append(f"- **Audit Status:** ❌ **FAILED** (Exit code: {returncode})")

    if ignores:
        lines.append(f"- **Active Ignores ({len(ignores)}):**")
        lines.append("| Vulnerability ID | Date | Justification |")
        lines.append("|---|---|---|")
        for vuln_id, date_str, just in ignores:
            lines.append(f"| `{vuln_id}` | {date_str} | {just} |")
    else:
        lines.append(
            "- **Active Ignores:** None (0 active ignores configured in `audit-ignores.txt`)"
        )

    if stdout.strip():
        lines.extend(["", "```text", stdout.strip(), "```"])
    if stderr.strip():
        lines.extend(["", "```text", stderr.strip(), "```"])

    lines.append("")

    with open(summary_path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    """Execute pip-audit against hashed lockfile."""
    lock_file = Path("requirements.lock")
    if not lock_file.exists():
        sys.stderr.write(f"Error: Required lock file '{lock_file}' not found.\n")
        return 1

    ignore_file = Path("audit-ignores.txt")
    try:
        ignores = load_ignores(ignore_file)
    except Exception as exc:
        sys.stderr.write(f"Error validating ignore file: {exc}\n")
        return 1

    cmd: list[str] = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(lock_file),
        "--require-hashes",
        "--strict",
    ]

    for vuln_id, _, _ in ignores:
        cmd.extend(["--ignore-vuln", vuln_id])

    sys.stdout.write(f"Running dependency security audit: {' '.join(cmd)}\n")
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)

    append_github_step_summary(
        lock_file=lock_file,
        ignores=ignores,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )

    return proc.returncode


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
