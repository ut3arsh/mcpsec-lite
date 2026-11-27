"""Generate a read-only pre-freeze manifest of git HEAD, artifacts, tree hashes, and owner tag commands.

IMPORTANT: This script NEVER creates or pushes git tags. It prints cryptographic hashes
and the exact commands for the repository owner to run when ready to freeze defenses.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from mcpsec_core.adapters import (
    BUILTIN_TOOL_TAINT_CLASSES,
    OFFICIAL_GITHUB_TOOL_TABLE,
    UNTRUSTED_CONTENT_BUILTIN_TOOLS,
)

DEV_MANIFESTS: tuple[str, ...] = (
    "benchmark/attacks/dev/manifest.json",
    "benchmark/benign/manifest.json",
    "benchmark/benign/manifest_v2.json",
    "benchmark/benign/manifest_v3.json",
    "benchmark/benign/manifest_v4.json",
)

OFFICIAL_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("benchmark/configs/C7.yaml", "f962612"),
    ("benchmark/configs/C6.yaml", "273b22f"),
    ("benchmark/github_official_map.json", "f962612"),
    ("tests/fixtures/github.tools.official.json", "7b32a65"),
    ("mcpsec_core/adapters.py", "HEAD"),
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


def sha256_file_lf(path: Path) -> str:
    """Compute OS-independent SHA-256 hex digest normalizing CRLF -> LF."""
    if not path.exists():
        raise FileNotFoundError(f"Required artifact not found: {path}")
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _pre_reg_sha256(rel_path: str, commit_ref: str) -> str:
    try:
        reg_bytes = subprocess.check_output(
            ["git", "show", f"{commit_ref}:{rel_path}"],
            stderr=subprocess.PIPE,
        )
        return hashlib.sha256(reg_bytes.replace(b"\r\n", b"\n")).hexdigest()
    except subprocess.CalledProcessError:
        return "UNAVAILABLE"


def sha256_adapters_table() -> tuple[str, int, int]:
    """Compute canonical SHA-256 over the reviewed 46-tool table and built-in U classification data."""
    canonical = {
        "official_github_tool_table": {
            name: {
                "tool_id": spec.tool_id,
                "path_args": list(spec.adapter.path_args),
                "domain_args": list(spec.adapter.domain_args),
                "all_args": sorted(spec.adapter.all_args),
                "capabilities": list(spec.capabilities),
                "taint_class": spec.taint_class,
                "read_only": spec.read_only,
            }
            for name, spec in sorted(OFFICIAL_GITHUB_TOOL_TABLE.items())
        },
        "builtin_tool_taint_classes": dict(sorted(BUILTIN_TOOL_TAINT_CLASSES.items())),
        "untrusted_content_builtin_tools": sorted(UNTRUSTED_CONTENT_BUILTIN_TOOLS),
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return (
        hashlib.sha256(encoded).hexdigest(),
        len(OFFICIAL_GITHUB_TOOL_TABLE),
        len(UNTRUSTED_CONTENT_BUILTIN_TOOLS),
    )


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

    c7_sha = sha256_file(Path("benchmark/configs/C7.yaml"))
    c6_sha = sha256_file(Path("benchmark/configs/C6.yaml"))
    adapters_table_sha, official_count, u_count = sha256_adapters_table()

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
            "## 1. Freeze Candidate (C7), Baseline (C6) & Official GitHub Artifacts (SHA-256)",
        ]
    )
    for rel_path, reg_ref in OFFICIAL_ARTIFACTS:
        p = Path(rel_path)
        cur_sha = sha256_file(p)
        cur_lf = sha256_file_lf(p)
        if reg_ref == "HEAD":
            lines.append(f"- {rel_path}: {cur_sha} (lf_sha256={cur_lf})")
        else:
            reg_sha = _pre_reg_sha256(rel_path, reg_ref)
            lines.append(
                f"- {rel_path}: {cur_sha} (lf_sha256={cur_lf}, pre_reg {reg_ref}={reg_sha}, matches={cur_lf == reg_sha})"
            )
    lines.append(
        f"- adapters_table_canonical ({official_count} official tools, {u_count} built-in U): {adapters_table_sha}"
    )

    lines.extend(
        [
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
            f'git tag -a v0.2-frozen -m "Freeze defenses at C7 candidate (C7 sha256={c7_sha[:12]}, C6 baseline={c6_sha[:12]})" {head_sha}',
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
