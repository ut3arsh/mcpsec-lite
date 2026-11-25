"""Parse pytest -rsx -q output or CI step-summary skip tables and validate test IDs.

Verifies every skipped/xfailed test ID against `pytest --collect-only -q` (and AST line
mappings for `SKIPPED [N] file:line: reason` entries) and emits a verified Markdown table.
Fails closed (non-zero exit) if any entry cannot be resolved to an existing collected test ID.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SkipEntry:
    outcome: str  # "SKIPPED" | "XFAIL" | "XPASS"
    nodeid: str
    location: str
    reason: str


class SkipValidationError(ValueError):
    """Raised when a reported skipped/xfailed test ID cannot be verified against pytest collection."""


_SKIP_LINE_RE = re.compile(
    r"^(SKIPPED)\s+\[(\d+)\]\s+(.+?):(\d+):\s*(.*)$"
)
_XFAIL_LINE_RE = re.compile(
    r"^(XFAIL|XPASS|SKIPPED)\s+([^\s]+::[^\s]+?)\s*(?:-\s*(.*))?$"
)
_MD_TABLE_ROW_RE = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*(.*?)\s*\|$"
)


def read_text_auto_encoding(path: Path) -> str:
    """Read file handling UTF-8, UTF-8-SIG, and Windows PowerShell UTF-16LE/BE BOMs."""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    return raw.decode("utf-8", errors="replace")


def parse_collected_nodeids(collect_output: str) -> set[str]:
    """Extract normalized test nodeids from `pytest --collect-only -q` output."""
    nodeids: set[str] = set()
    for line in collect_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("=") or "::" not in stripped:
            continue
        # Ignore summary lines if any
        if " " in stripped and "[" not in stripped:
            continue
        nodeids.add(stripped.replace("\\", "/"))
    return nodeids


def collect_valid_test_ids(*, plain_only: bool = False) -> set[str]:
    """Run pytest --collect-only -q and return all valid test nodeids."""
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-q"]
    if not plain_only:
        cmd.extend(["-o", "addopts="])
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if proc.returncode not in (0, 5):
        raise RuntimeError(
            f"pytest --collect-only -q failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return parse_collected_nodeids(proc.stdout)


def resolve_line_to_nodeid(
    file_path: str,
    lineno: int,
    root_dir: Path = Path("."),
) -> str:
    """Map `<file>:<lineno>` inside a Python test module to its `<file>::[Class::]<func>` nodeid."""
    norm_rel = file_path.replace("\\", "/")
    full_path = root_dir / norm_rel
    if not full_path.exists():
        raise SkipValidationError(f"Skipped file does not exist: {norm_rel}:{lineno}")

    try:
        tree = ast.parse(full_path.read_text(encoding="utf-8"), filename=norm_rel)
    except SyntaxError as exc:
        raise SkipValidationError(f"Failed to AST-parse {norm_rel}: {exc}") from exc

    best_nodeid: str | None = None
    best_span: int | None = None

    def _visit(node: ast.AST, class_stack: list[str]) -> None:
        nonlocal best_nodeid, best_span
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                _visit(child, [*class_stack, child.name])
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = child.lineno
                # Account for decorators before def
                if child.decorator_list:
                    start = min(start, *(d.lineno for d in child.decorator_list))
                end = child.end_lineno or child.lineno
                if start <= lineno <= end:
                    span = end - start
                    parts = [norm_rel, *class_stack, child.name]
                    candidate = "::".join(parts)
                    if best_span is None or span < best_span:
                        best_span = span
                        best_nodeid = candidate

    _visit(tree, [])
    if best_nodeid is None:
        raise SkipValidationError(
            f"Line {norm_rel}:{lineno} does not fall inside any test function"
        )
    return best_nodeid


def _validate_nodeid_in_collection(nodeid: str, valid_nodeids: set[str]) -> str:
    """Verify nodeid exists in collected test IDs (supporting exact or parameterized base match)."""
    norm = nodeid.replace("\\", "/")
    if norm in valid_nodeids:
        return norm
    # If unparameterized name resolved from line number matches parameterized collected tests, accept canonical base match
    if "[" not in norm:
        prefix = f"{norm}["
        for cid in sorted(valid_nodeids):
            if cid.startswith(prefix):
                return norm
    raise SkipValidationError(
        f"Test ID '{norm}' is ABSENT from pytest --collect-only -q output"
    )


def parse_rsx_text(
    text: str,
    valid_nodeids: set[str],
    root_dir: Path = Path("."),
) -> list[SkipEntry]:
    """Parse pytest -rsx -q short summary info or CI step_summary.md skip tables."""
    entries: list[SkipEntry] = []
    in_skip_table = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # 1. Explicit nodeid format: XFAIL tests/foo.py::test_bar - reason (or SKIPPED tests/foo.py::test_bar)
        m_xfail = _XFAIL_LINE_RE.match(line)
        if m_xfail:
            outcome, raw_nodeid, reason = m_xfail.groups()
            verified = _validate_nodeid_in_collection(raw_nodeid, valid_nodeids)
            entries.append(
                SkipEntry(
                    outcome=outcome,
                    nodeid=verified,
                    location=verified,
                    reason=(reason or "").strip(),
                )
            )
            continue

        # 2. Pytest SKIPPED summary format: SKIPPED [1] tests\test_contract.py:89: reason
        m_skip = _SKIP_LINE_RE.match(line)
        if m_skip:
            outcome, _count, fpath, lineno_s, reason = m_skip.groups()
            lineno = int(lineno_s)
            resolved = resolve_line_to_nodeid(fpath, lineno, root_dir=root_dir)
            verified = _validate_nodeid_in_collection(resolved, valid_nodeids)
            entries.append(
                SkipEntry(
                    outcome=outcome,
                    nodeid=verified,
                    location=f"{fpath.replace(chr(92), '/')}:{lineno}",
                    reason=reason.strip(),
                )
            )
            continue

        # Catch malformed / unmatched SKIPPED or XFAIL/XPASS lines instead of silently skipping them!
        if re.match(r"^(SKIPPED|XFAIL|XPASS)\b", line):
            raise SkipValidationError(f"Unrecognized or invalid skip/xfail line: {line}")

        # 3. Markdown step_summary.md Skipped Tests table
        if line.startswith("### ") and "Skipped Tests" in line:
            in_skip_table = True
            continue
        if in_skip_table and line.startswith("### "):
            in_skip_table = False
            continue
        if in_skip_table:
            m_row = _MD_TABLE_ROW_RE.match(line)
            if m_row:
                test_name, class_or_file, reason = m_row.groups()
                # Convert dotted module e.g. `tests.test_contract` or `tests.test_foo.TestClass`
                mod_parts = class_or_file.split(".")
                # Build longest existing .py module prefix from root_dir
                candidate_nodeid: str | None = None
                for split_idx in range(len(mod_parts), 0, -1):
                    py_rel = "/".join(mod_parts[:split_idx]) + ".py"
                    if (root_dir / py_rel).exists():
                        cls_parts = mod_parts[split_idx:]
                        candidate_nodeid = "::".join([py_rel, *cls_parts, test_name])
                        break
                if candidate_nodeid is None:
                    raise SkipValidationError(
                        f"Could not resolve step_summary entry `{class_or_file}`::`{test_name}` to any test file"
                    )
                verified = _validate_nodeid_in_collection(candidate_nodeid, valid_nodeids)
                outcome = "XFAIL" if reason.startswith("Known Gap:") else "SKIPPED"
                entries.append(
                    SkipEntry(
                        outcome=outcome,
                        nodeid=verified,
                        location=class_or_file,
                        reason=reason.strip(),
                    )
                )

    return entries


def format_markdown_table(entries: list[SkipEntry], source_label: str) -> str:
    """Render verified skipped/xfailed entries as a Markdown table."""
    lines = [
        f"#### Verified Skip / XFail Report (`{source_label}`)",
        "",
    ]
    if not entries:
        lines.append("- **Total:** 0 skipped/xfailed entries.")
        return "\n".join(lines) + "\n"

    skip_cnt = sum(1 for e in entries if e.outcome == "SKIPPED")
    xfail_cnt = sum(1 for e in entries if e.outcome == "XFAIL")
    xpass_cnt = sum(1 for e in entries if e.outcome == "XPASS")
    lines.append(
        f"- **Verified Total:** {len(entries)} (`SKIPPED`: {skip_cnt}, `XFAIL`: {xfail_cnt}, `XPASS`: {xpass_cnt})"
    )
    lines.append("")
    lines.append("| Outcome | Verified Test ID (`nodeid`) | Source Location | Reason |")
    lines.append("|---|---|---|---|")
    for e in entries:
        clean_reason = e.reason.replace("|", "\\|")
        lines.append(f"| `{e.outcome}` | `{e.nodeid}` | `{e.location}` | {clean_reason} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate pytest -rsx -q or CI step_summary.md skip/xfail entries against pytest collection."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="One or more pytest -rsx -q output files or CI step_summary.md files",
    )
    parser.add_argument(
        "--collect-file",
        type=Path,
        default=None,
        help="Optional pre-captured `pytest --collect-only -q` output file (avoids invoking pytest)",
    )
    parser.add_argument(
        "--plain-collect",
        action="store_true",
        help="Run default `pytest --collect-only -q` without clearing addopts (excludes live/integration marks)",
    )
    parser.add_argument(
        "--root-dir",
        type=Path,
        default=Path("."),
        help="Repository root directory for AST line resolution",
    )
    args = parser.parse_args(argv)

    try:
        if args.collect_file is not None:
            valid_nodeids = parse_collected_nodeids(read_text_auto_encoding(args.collect_file))
        else:
            valid_nodeids = collect_valid_test_ids(plain_only=args.plain_collect)

        outputs: list[str] = []
        for in_path in args.inputs:
            if not in_path.exists():
                raise FileNotFoundError(f"Input report file not found: {in_path}")
            content = read_text_auto_encoding(in_path)
            entries = parse_rsx_text(content, valid_nodeids, root_dir=args.root_dir)
            outputs.append(format_markdown_table(entries, source_label=in_path.as_posix()))

        sys.stdout.write("\n".join(outputs))
        return 0
    except (SkipValidationError, FileNotFoundError, RuntimeError) as exc:
        sys.stderr.write(f"SkipValidationError: {exc}\n")
        return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
