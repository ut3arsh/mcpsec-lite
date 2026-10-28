"""Record core test coverage and skipped tests to $GITHUB_STEP_SUMMARY."""

from __future__ import annotations

import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def parse_coverage(coverage_json_path: Path) -> tuple[float, float, float, list[dict[str, Any]]]:
    """Parse branch coverage with 2 decimals from coverage.py json report."""
    if not coverage_json_path.exists():
        return 0.0, 0.0, 0.0, []

    with open(coverage_json_path, encoding="utf-8") as f:
        data = json.load(f)

    totals = data.get("totals", {})
    percent_covered = float(totals.get("percent_covered", 0.0))
    percent_branches = float(totals.get("percent_branches_covered", 0.0))
    percent_stmts = float(totals.get("percent_statements_covered", 0.0))

    files_data = data.get("files", {})
    file_rows: list[dict[str, Any]] = []
    for filepath, f_stats in sorted(files_data.items()):
        summary = f_stats.get("summary", {})
        file_rows.append(
            {
                "file": filepath.replace("\\", "/"),
                "covered_lines": summary.get("covered_lines", 0),
                "num_statements": summary.get("num_statements", 0),
                "percent_covered": float(summary.get("percent_covered", 0.0)),
                "num_branches": summary.get("num_branches", 0),
                "covered_branches": summary.get("covered_branches", 0),
                "percent_branches": float(summary.get("percent_branches_covered", 0.0))
                if summary.get("num_branches", 0) > 0
                else 100.0,
            }
        )

    return percent_covered, percent_branches, percent_stmts, file_rows


def parse_skipped_tests(junit_xml_path: Path) -> list[tuple[str, str, str]]:
    """Parse skipped tests from JUnit XML report."""
    if not junit_xml_path.exists():
        return []

    skipped_items: list[tuple[str, str, str]] = []
    try:
        tree = ET.parse(junit_xml_path)
        root = tree.getroot()
        for testcase in root.iter("testcase"):
            skipped_elem = testcase.find("skipped")
            if skipped_elem is not None:
                classname = testcase.get("classname", "")
                name = testcase.get("name", "")
                message = skipped_elem.get("message", "") or (skipped_elem.text or "").strip()
                skipped_items.append((classname, name, message))
    except Exception as exc:
        sys.stderr.write(f"Warning: could not parse JUnit XML: {exc}\n")

    return skipped_items


def main(argv: list[str] | None = None) -> int:
    """Generate Markdown test & coverage summary for GitHub Actions."""
    cov_path = Path("coverage_core.json")
    junit_path = Path("test-results.xml")

    pct_cov, pct_branch, pct_stmt, file_rows = parse_coverage(cov_path)
    skipped_tests = parse_skipped_tests(junit_path)

    lines: list[str] = [
        "### 📊 Core Test Suite Coverage (`mcpsec_core`)",
        f"- **Total Branch-Aware Coverage:** **`{pct_cov:.2f}%`** (Gate: $\\ge 90.00\\%$)",
        f"- **Branch Coverage:** **`{pct_branch:.2f}%`**",
        f"- **Statement Coverage:** **`{pct_stmt:.2f}%`**",
        "",
        "| Module | Stmts | Cover (%) | Branches | Branch Cover (%) |",
        "|---|---|---|---|---|",
    ]

    for row in file_rows:
        lines.append(
            f"| `{row['file']}` | {row['covered_lines']}/{row['num_statements']} | "
            f"{row['percent_covered']:.2f}% | {row['covered_branches']}/{row['num_branches']} | "
            f"{row['percent_branches']:.2f}% |"
        )

    lines.extend(
        [
            "",
            "### ⏭️ Skipped Tests (`pytest -rs`)",
        ]
    )

    if skipped_tests:
        lines.append(f"**Total Skipped:** {len(skipped_tests)}")
        lines.append("")
        lines.append("| Test Case | Class / File | Skip Reason |")
        lines.append("|---|---|---|")
        for classname, name, reason in skipped_tests:
            lines.append(f"| `{name}` | `{classname}` | {reason} |")
    else:
        lines.append("- **Total Skipped:** 0 tests skipped.")

    proxy_cov_path = Path("coverage_proxy.json")
    if proxy_cov_path.exists():
        _, _, _, proxy_rows = parse_coverage(proxy_cov_path)
        session_row = next((r for r in proxy_rows if r["file"].endswith("proxy/session.py")), None)
        if session_row:
            cov_stmts = session_row["covered_lines"]
            tot_stmts = session_row["num_statements"]
            stmt_pct = (cov_stmts / tot_stmts * 100.0) if tot_stmts else 0.0
            cov_branches = session_row["covered_branches"]
            tot_branches = session_row["num_branches"]
            branch_pct = session_row["percent_branches"]
            tot_cov = session_row["percent_covered"]
            lines.extend(
                [
                    "",
                    "### 🛡️ Proxy Session Coverage (`proxy/session.py`)",
                    f"- **Total Coverage:** **`{tot_cov:.2f}%`**",
                    f"- **Branch Coverage:** **`{branch_pct:.2f}%`** ({cov_branches}/{tot_branches})",
                    f"- **Statement Coverage:** **`{stmt_pct:.2f}%`** ({cov_stmts}/{tot_stmts})",
                ]
            )

    lines.append("")

    summary_text = "\n".join(lines) + "\n"

    # Always persist locally to step_summary.md for artifact upload
    Path("step_summary.md").write_text(summary_text, encoding="utf-8")

    summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_env:
        with open(summary_env, "a", encoding="utf-8") as f:
            f.write(summary_text)
        sys.stdout.write("Recorded test & coverage summary to $GITHUB_STEP_SUMMARY\n")
    else:
        sys.stdout.write(summary_text)

    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
