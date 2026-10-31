"""Enforce exact combined coverage gate (statements >= 90.00% and branches >= 90.00%).

Reads coverage.py JSON report, prints a formatted summary to $GITHUB_STEP_SUMMARY
and stdout, and fails closed if statement or branch coverage falls below 90.00%.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any


def check_coverage_gate(json_path: Path) -> int:
    if isinstance(sys.stdout, io.TextIOWrapper) and sys.stdout.encoding:
        if sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
            try:
                sys.stdout.reconfigure(encoding="utf-8")
            except Exception:
                pass

    if not json_path.exists():
        sys.stderr.write(f"Error: Coverage report not found at {json_path}\n")
        return 1

    with open(json_path, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    totals = data.get("totals", {})
    num_statements = int(totals.get("num_statements", 0))
    covered_lines = int(totals.get("covered_lines", 0))
    stmt_pct = (covered_lines / num_statements * 100.0) if num_statements else 0.0

    num_branches = int(totals.get("num_branches", 0))
    covered_branches = int(totals.get("covered_branches", 0))
    branch_pct = (covered_branches / num_branches * 100.0) if num_branches else 100.0

    total_elements = num_statements + num_branches
    total_covered = covered_lines + covered_branches
    overall_pct = (total_covered / total_elements * 100.0) if total_elements else 0.0

    files_data = data.get("files", {})
    file_rows: list[dict[str, Any]] = []
    for filepath, f_stats in sorted(files_data.items()):
        summary = f_stats.get("summary", {})
        f_stmts = summary.get("num_statements", 0)
        f_cov_lines = summary.get("covered_lines", 0)
        f_branches = summary.get("num_branches", 0)
        f_cov_branches = summary.get("covered_branches", 0)
        file_rows.append(
            {
                "file": filepath.replace("\\", "/"),
                "covered_lines": f_cov_lines,
                "num_statements": f_stmts,
                "stmt_pct": (f_cov_lines / f_stmts * 100.0) if f_stmts else 0.0,
                "covered_branches": f_cov_branches,
                "num_branches": f_branches,
                "branch_pct": (f_cov_branches / f_branches * 100.0) if f_branches else 100.0,
                "missing_branches": f_stats.get("missing_branches", []),
            }
        )

    REQUIRED_CORE_STEMS = frozenset(
        {"audit", "pinning", "flow", "matching", "policy", "taint", "approvals", "detectors"}
    )
    floor_failures: list[str] = []
    checked_stems: set[str] = set()

    for row in file_rows:
        stem = Path(row["file"]).stem
        if stem in REQUIRED_CORE_STEMS:
            checked_stems.add(stem)
            if row["stmt_pct"] < 85.00 or row["branch_pct"] < 85.00:
                floor_failures.append(
                    f"`{row['file']}`: stmts={row['stmt_pct']:.2f}% (min 85.00%), "
                    f"branches={row['branch_pct']:.2f}% (min 85.00%)"
                )

    missing_core = REQUIRED_CORE_STEMS - checked_stems
    if missing_core:
        floor_failures.append(f"Missing core modules in coverage report: {sorted(missing_core)}")

    # Markdown summary output
    lines: list[str] = [
        "## 🛡️ Combined Cross-Platform Coverage Gate (`mcpsec_core`)",
        "",
        f"- **Combined Statement Coverage:** **`{stmt_pct:.2f}%`** ({covered_lines}/{num_statements}) — Target: $\\ge 90.00\\%$",
        f"- **Combined Branch Coverage:** **`{branch_pct:.2f}%`** ({covered_branches}/{num_branches}) — Target: $\\ge 90.00\\%$",
        f"- **Combined Total Coverage:** **`{overall_pct:.2f}%`** ({total_covered}/{total_elements})",
    ]

    if not floor_failures:
        lines.append(
            "- **Per-Module Floor (>= 85.00% stmts & branches):** ✅ **PASSED** "
            "(all 8 core modules: audit, pinning, flow, matching, policy, taint, approvals, detectors)"
        )
    else:
        lines.append(
            f"- **Per-Module Floor (>= 85.00% stmts & branches):** ❌ **FAILED** — {'; '.join(floor_failures)}"
        )

    lines.extend(
        [
            "",
            "| Module | Statements | Statement (%) | Branches | Branch (%) |",
            "|---|---|---|---|---|",
        ]
    )

    for row in file_rows:
        lines.append(
            f"| `{row['file']}` | {row['covered_lines']}/{row['num_statements']} | "
            f"{row['stmt_pct']:.2f}% | {row['covered_branches']}/{row['num_branches']} | "
            f"{row['branch_pct']:.2f}% |"
        )

    lines.append("")

    overall_gate_passed = (stmt_pct >= 90.00) and (branch_pct >= 90.00)
    floor_gate_passed = len(floor_failures) == 0
    gate_passed = overall_gate_passed and floor_gate_passed

    if gate_passed:
        lines.append(
            "✅ **GATE STATUS: PASSED** — Both statement and branch coverage meet or exceed 90.00%, "
            "and all 8 core modules meet or exceed the 85.00% floor."
        )
    else:
        failure_reasons: list[str] = []
        if not overall_gate_passed:
            failure_reasons.append(
                f"overall stmts={stmt_pct:.2f}% or branches={branch_pct:.2f}% below 90.00%"
            )
        if not floor_gate_passed:
            failure_reasons.append(f"module floor failed: {'; '.join(floor_failures)}")
        lines.append(f"❌ **GATE STATUS: FAILED** — Gate violation: {'; '.join(failure_reasons)}.")

    summary_text = "\n".join(lines) + "\n"
    print(summary_text)

    # Persist locally for artifact upload
    Path("step_summary_gate.md").write_text(summary_text, encoding="utf-8")

    # Append to GitHub Step Summary if running in GitHub Actions
    summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_env:
        with open(summary_env, "a", encoding="utf-8") as f:
            f.write(summary_text)

    if not gate_passed:
        sys.stderr.write(
            f"CoverageGateError: Coverage failed gate! "
            f"Statements: {stmt_pct:.2f}% (min 90.00%), Branches: {branch_pct:.2f}% (min 90.00%), "
            f"Floor failures: {floor_failures}\n"
        )
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = argv if argv is not None else sys.argv[1:]
    target = Path(args[0]) if args else Path("coverage_core_combined.json")
    if not target.exists() and Path("coverage_core.json").exists():
        target = Path("coverage_core.json")
    return check_coverage_gate(target)


if __name__ == "__main__":
    sys.exit(main())
