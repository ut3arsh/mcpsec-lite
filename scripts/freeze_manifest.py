"""Generate a read-only pre-freeze manifest of git HEAD, artifacts, tree hashes, and owner tag commands.

IMPORTANT: This script NEVER creates or pushes git tags. It prints cryptographic hashes
and the exact commands for the repository owner to run when ready to freeze defenses.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

DEV_MANIFESTS: tuple[str, ...] = (
    "benchmark/attacks/dev/manifest.json",
    "benchmark/benign/manifest.json",
    "benchmark/benign/manifest_v2.json",
    "benchmark/benign/manifest_v3.json",
    "benchmark/benign/manifest_v4.json",
)

TREE_DIRS: tuple[str, ...] = ("mcpsec_core", "proxy")
DEPENDENCY_LOCKS: tuple[str, ...] = ("requirements.lock", "uv.lock", "package-lock.json")


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args],
        text=True,
        encoding="utf-8",
        errors="replace",
    ).strip()


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file's raw bytes."""
    if not path.exists():
        raise FileNotFoundError(f"Required artifact not found: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_tracked_tree(dir_name: str) -> tuple[str, str, int]:
    """Return (git_tree_oid, deterministic_sha256_of_tracked_files, file_count) for a directory."""
    git_tree_oid = _git("rev-parse", f"HEAD:{dir_name}")
    tracked = _git("ls-files", dir_name).splitlines()
    h = hashlib.sha256()
    count = 0
    for rel in sorted(tracked):
        p = Path(rel)
        if not p.is_file():
            continue
        file_hash = hashlib.sha256(p.read_bytes()).hexdigest()
        h.update(f"{rel}:{file_hash}\n".encode())
        count += 1
    return git_tree_oid, h.hexdigest(), count


def build_manifest() -> str:
    """Assemble the complete pre-freeze manifest report without mutating git state."""
    head_sha = _git("rev-parse", "HEAD")
    head_subject = _git("log", "-1", "--format=%h %s", "HEAD")
    dirty_lines = [line for line in _git("status", "--porcelain").splitlines() if line.strip()]
    tree_clean = len(dirty_lines) == 0

    c6_path = Path("benchmark/configs/C6.yaml")
    c6_sha = sha256_file(c6_path)
    reg_commit = "273b22f"
    try:
        reg_bytes = subprocess.check_output(
            ["git", "show", f"{reg_commit}:benchmark/configs/C6.yaml"],
            stderr=subprocess.PIPE,
        )
        c6_reg_sha = hashlib.sha256(reg_bytes).hexdigest()
        c6_matches_reg = c6_sha == c6_reg_sha
    except subprocess.CalledProcessError:
        c6_reg_sha = "UNAVAILABLE"
        c6_matches_reg = False

    lines: list[str] = [
        "# Pre-Freeze Defense Manifest (Read-Only — No Tag Applied)",
        "",
        f"git_head:           {head_sha}",
        f"git_head_summary:   {head_subject}",
        f"working_tree_clean: {tree_clean}",
    ]
    if not tree_clean:
        lines.append(f"dirty_entries:      {len(dirty_lines)} ({', '.join(dirty_lines[:5])})")

    lines.extend(
        [
            "",
            "## 1. Candidate Default Policy Config (C6)",
            f"- benchmark/configs/C6.yaml: {c6_sha}",
            f"- pre_reg ({reg_commit}) C6.yaml: {c6_reg_sha} (matches_HEAD={c6_matches_reg})",
            "",
            "## 2. Development Benchmark Manifests (SHA-256)",
        ]
    )
    for m in DEV_MANIFESTS:
        lines.append(f"- {m}: {sha256_file(Path(m))}")

    lines.extend(
        [
            "",
            "## 3. Core Defense & Proxy Directory Hashes",
        ]
    )
    for d in TREE_DIRS:
        git_oid, disk_sha, fcount = sha256_tracked_tree(d)
        lines.append(
            f"- {d}/: git_tree={git_oid} | working_tree_sha256={disk_sha} ({fcount} tracked files)"
        )

    lines.extend(
        [
            "",
            "## 4. Pinned Dependency Lock Hashes (SHA-256)",
        ]
    )
    for lock in DEPENDENCY_LOCKS:
        lp = Path(lock)
        if lp.exists():
            lines.append(f"- {lock}: {sha256_file(lp)}")
        else:
            lines.append(f"- {lock}: MISSING")

    lines.extend(
        [
            "",
            "## 5. Exact Owner Tagging Commands (Do NOT run automatically)",
            "# Run after verifying clean working tree and green CI on HEAD:",
            f'git tag -a v0.2-frozen -m "Freeze defenses at C6 candidate (C6 sha256={c6_sha[:12]})" {head_sha}',
            "git push origin v0.2-frozen",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    sys.stdout.write(build_manifest())
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
