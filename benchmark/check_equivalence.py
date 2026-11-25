"""Machine-generated equivalence checker comparing C6 (handwritten) vs C7 (official GitHub schema)."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from benchmark.analysis import (
    ConfigIntegrityError,
    TrialCompletenessError,
    load_manifest,
    load_run_config,
    load_trials,
    validate_config_integrity,
    validate_trial_completeness,
)


def _sha256_or_missing(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_equivalence_report(
    left_dir: Path,
    right_dir: Path,
    left_config: str = "C6",
    right_config: str = "C7",
    config_dir: Path = Path("benchmark/configs"),
    attack_manifest_path: Path = Path("benchmark/attacks/dev/manifest.json"),
    benign_manifest_paths: list[Path] | None = None,
) -> tuple[str, list[dict[str, str]]]:
    """Validate completeness/config integrity and compare (status, blocking_layer, rule_id).

    Returns (markdown_report, mismatches_list).
    """
    if benign_manifest_paths is None:
        benign_manifest_paths = [
            Path("benchmark/benign/manifest.json"),
            Path("benchmark/benign/manifest_v2.json"),
            Path("benchmark/benign/manifest_v3.json"),
            Path("benchmark/benign/manifest_v4.json"),
        ]

    left_trials = load_trials(left_dir / "trials.csv")
    right_trials = load_trials(right_dir / "trials.csv")
    left_run = load_run_config(left_dir / "run.json", left_dir / "trials.csv")
    right_run = load_run_config(right_dir / "run.json", right_dir / "trials.csv")

    attack_manifest = load_manifest(attack_manifest_path)
    benign_manifests = [load_manifest(p) for p in benign_manifest_paths if p.exists()]

    all_attacks = list(attack_manifest.get("scenarios", []))
    all_benign = [sc for m in benign_manifests for sc in m.get("scenarios", [])]
    expected_ids = [s["id"] for s in all_attacks] + [s["id"] for s in all_benign]
    approval_modes = ["deny_all", "approve_all"]

    # Validate config integrity and trial matrix completeness for both runs
    validate_config_integrity(left_run, config_dir=config_dir)
    validate_config_integrity(right_run, config_dir=config_dir)
    validate_trial_completeness(left_trials, expected_ids, [left_config], approval_modes)
    validate_trial_completeness(right_trials, expected_ids, [right_config], approval_modes)

    left_map = {(r["id"], r["approval_mode"]): r for r in left_trials if r["config"] == left_config}
    right_map = {
        (r["id"], r["approval_mode"]): r for r in right_trials if r["config"] == right_config
    }

    mismatches: list[dict[str, str]] = []
    comparisons: list[dict[str, str]] = []
    taint_diffs = 0
    approvals_diffs = 0

    for sc_id in expected_ids:
        for mode in approval_modes:
            lr = left_map[(sc_id, mode)]
            rr = right_map[(sc_id, mode)]

            l_tuple = (lr["status"], lr["blocking_layer"], lr["rule_id"])
            r_tuple = (rr["status"], rr["blocking_layer"], rr["rule_id"])
            same_decision = l_tuple == r_tuple

            if lr.get("taint_acquired", "") != rr.get("taint_acquired", ""):
                taint_diffs += 1
            if lr.get("approvals_count", "") != rr.get("approvals_count", ""):
                approvals_diffs += 1

            row_info = {
                "id": sc_id,
                "category": lr.get("category", ""),
                "approval_mode": mode,
                "left_status": lr["status"],
                "right_status": rr["status"],
                "left_layer": lr["blocking_layer"],
                "right_layer": rr["blocking_layer"],
                "left_rule": lr["rule_id"],
                "right_rule": rr["rule_id"],
                "left_taint": lr.get("taint_acquired", "") or "*clean*",
                "right_taint": rr.get("taint_acquired", "") or "*clean*",
                "left_approvals": lr.get("approvals_count", "0"),
                "right_approvals": rr.get("approvals_count", "0"),
                "equivalent": "MATCH" if same_decision else "MISMATCH",
            }
            comparisons.append(row_info)
            if not same_decision:
                mismatches.append(row_info)

    total_pairs = len(comparisons)
    matched_pairs = total_pairs - len(mismatches)
    attack_pairs = [r for r in comparisons if r["category"] == "attack"]
    benign_pairs = [r for r in comparisons if r["category"] == "benign"]
    attack_matches = sum(1 for r in attack_pairs if r["equivalent"] == "MATCH")
    benign_matches = sum(1 for r in benign_pairs if r["equivalent"] == "MATCH")

    github_attack_ids = {
        s["id"]
        for s in all_attacks
        if any(st.get("server") == "github" for st in s.get("steps", []))
    }
    github_benign_ids = {
        s["id"]
        for s in all_benign
        if any(st.get("server") == "github" for st in s.get("steps", []))
    }
    github_ids = github_attack_ids | github_benign_ids
    github_pairs = [r for r in comparisons if r["id"] in github_ids]
    github_matches = sum(1 for r in github_pairs if r["equivalent"] == "MATCH")

    left_sha = (left_run.get("config_hashes") or {}).get(
        left_config, _sha256_or_missing(config_dir / f"{left_config}.yaml")
    )
    right_sha = (right_run.get("config_hashes") or {}).get(
        right_config, _sha256_or_missing(config_dir / f"{right_config}.yaml")
    )
    reg_left = str(left_run.get("registration_commit", "UNSET"))
    reg_right = str(right_run.get("registration_commit", "UNSET"))

    lines: list[str] = [
        f"# Equivalence Report: {left_config} (Handwritten) vs {right_config} (Official GitHub v2.3.0)",
        "",
        "> **Document Status:** Machine-generated by `benchmark/check_equivalence.py`. Zero hand-typed numbers.",
        "",
        "## 1. Run Provenance & Integrity Validation",
        "",
        "| Field | Left (Handwritten Baseline) | Right (Official Alignment) |",
        "|---|---|---|",
        f"| Config | `{left_config}` | `{right_config}` |",
        f"| Schema Mode | `{left_run.get('github_schema', 'handwritten')}` | `{right_run.get('github_schema', 'official')}` |",
        f"| Run Directory | `{left_dir.as_posix()}` | `{right_dir.as_posix()}` |",
        f"| Pre-Reg Commit | `{reg_left}` | `{reg_right}` |",
        f"| Policy SHA-256 | `{left_sha}` | `{right_sha}` |",
        f"| Trial Rows Validated | {len(left_trials)} | {len(right_trials)} |",
        "| Completeness & Config Integrity | PASS | PASS |",
        "",
        "## 2. Equivalence Summary (`(status, blocking_layer, rule_id)`)",
        "",
        "| Slice | Matched Pairs | Mismatched Pairs | Match Rate (%) |",
        "|---|---|---|---|",
        f"| **All (scenario, mode) pairs** | {matched_pairs}/{total_pairs} | {len(mismatches)}/{total_pairs} | {(matched_pairs / total_pairs * 100.0) if total_pairs else 0.0:.2f}% |",
        f"| Attack scenarios | {attack_matches}/{len(attack_pairs)} | {len(attack_pairs) - attack_matches}/{len(attack_pairs)} | {(attack_matches / len(attack_pairs) * 100.0) if attack_pairs else 0.0:.2f}% |",
        f"| Benign workflows | {benign_matches}/{len(benign_pairs)} | {len(benign_pairs) - benign_matches}/{len(benign_pairs)} | {(benign_matches / len(benign_pairs) * 100.0) if benign_pairs else 0.0:.2f}% |",
        f"| GitHub-containing subset | {github_matches}/{len(github_pairs)} | {len(github_pairs) - github_matches}/{len(github_pairs)} | {(github_matches / len(github_pairs) * 100.0) if github_pairs else 0.0:.2f}% |",
        "",
        f"- **Diagnostic secondary differences:** `taint_acquired` differences = `{taint_diffs}/{total_pairs}`; `approvals_count` differences = `{approvals_diffs}/{total_pairs}`.",
        "",
    ]

    if mismatches:
        lines.extend(
            [
                "## 3. Detected Equivalence Bugs (Mismatches)",
                "",
                "| ID | Mode | Left Status / Layer / Rule | Right Status / Layer / Rule |",
                "|---|---|---|---|",
            ]
        )
        for m in mismatches:
            lines.append(
                f"| `{m['id']}` | `{m['approval_mode']}` | "
                f"`{m['left_status']}` / `{m['left_layer']}` / `{m['left_rule']}` | "
                f"`{m['right_status']}` / `{m['right_layer']}` / `{m['right_rule']}` |"
            )
        lines.append("")
    else:
        lines.extend(
            [
                "## 3. Detected Equivalence Bugs (Mismatches)",
                "",
                f"Zero mismatches observed across all {total_pairs} `(scenario, mode)` pairs.",
                "",
            ]
        )

    lines.extend(
        [
            "## 4. Complete Per-(Scenario, Mode) Comparison for GitHub Subset",
            "",
            "| ID | Mode | Left (`C6` status / layer / rule / taint) | Right (`C7` status / layer / rule / taint) | Result |",
            "|---|---|---|---|---|",
        ]
    )
    for row in github_pairs:
        l_desc = (
            f"{row['left_status']} / {row['left_layer']} / {row['left_rule']} / {row['left_taint']}"
        )
        r_desc = f"{row['right_status']} / {row['right_layer']} / {row['right_rule']} / {row['right_taint']}"
        lines.append(
            f"| `{row['id']}` | `{row['approval_mode']}` | `{l_desc}` | `{r_desc}` | **{row['equivalent']}** |"
        )

    return "\n".join(lines) + "\n", mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify equivalence between C6 and C7 trial runs")
    parser.add_argument(
        "--left-dir", required=True, help="Directory with C6 trials.csv and run.json"
    )
    parser.add_argument(
        "--right-dir", required=True, help="Directory with C7 trials.csv and run.json"
    )
    parser.add_argument("--left-config", default="C6")
    parser.add_argument("--right-config", default="C7")
    parser.add_argument("--output", required=True, help="Output Markdown equivalence report path")
    args = parser.parse_args(argv)

    try:
        report, mismatches = generate_equivalence_report(
            left_dir=Path(args.left_dir),
            right_dir=Path(args.right_dir),
            left_config=args.left_config,
            right_config=args.right_config,
        )
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8", newline="\n")
        sys.stdout.write(
            f"Equivalence check complete: output={out_path}, mismatches={len(mismatches)}\n"
        )
        return 1 if mismatches else 0
    except (TrialCompletenessError, ConfigIntegrityError, FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"EquivalenceCheckError: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
