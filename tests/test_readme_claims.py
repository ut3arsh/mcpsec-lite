"""Tests verifying README.md claims and approvals/task figures match generated analysis output."""

from __future__ import annotations

import re
from pathlib import Path

from benchmark.analysis import (
    generate_analysis_report,
    load_manifest,
    load_run_config,
    load_trials,
)


def _extract_table_cells(markdown: str, config_name: str) -> list[str]:
    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if f"**{config_name}**" in stripped:
            parts = [cell.strip() for cell in stripped.strip("|").split("|")]
            if parts and parts[0].startswith(f"**{config_name}**"):
                return parts
    raise AssertionError(f"Could not locate table row for {config_name}")


def test_readme_approvals_per_task_and_scope_match_generated_report() -> None:
    """Assert README.md Approvals/Task figures (overall C0-C6 + per-set C6 v1..v4) match generated report."""
    readme_text = Path("README.md").read_text(encoding="utf-8")

    trials_path = Path("benchmark/results/dev_20261110_c6/trials.csv")
    run_json_path = Path("benchmark/results/dev_20261110_c6/run.json")
    trials = load_trials(trials_path)
    run_config = load_run_config(run_json_path, trials_path)
    attack_manifest = load_manifest(Path("benchmark/attacks/dev/manifest.json"))
    benign_manifests = [
        load_manifest(Path("benchmark/benign/manifest.json")),
        load_manifest(Path("benchmark/benign/manifest_v2.json")),
        load_manifest(Path("benchmark/benign/manifest_v3.json")),
        load_manifest(Path("benchmark/benign/manifest_v4.json")),
    ]
    generated = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )

    # 1. Verify overall C0, C1, C2, C5, C6 Approvals/Task figures in README match generated Section 1 table
    for cfg in ("C0", "C1", "C2", "C5", "C6"):
        # Extract generated '(d) Approvals / Task' cell: e.g. '0.40 (20/50) PASS'
        gen_cells = _extract_table_cells(generated, cfg)
        gen_bar_d = gen_cells[4]
        m_gen = re.match(r"(\d+\.\d+\s+\(\d+/\d+\))", gen_bar_d)
        assert m_gen is not None, f"Unexpected generated format for {cfg}: {gen_bar_d}"
        expected_val = m_gen.group(1)

        readme_cells = _extract_table_cells(readme_text, cfg)
        readme_bar_d = readme_cells[3].replace("*", "").strip()
        assert readme_bar_d == expected_val, (
            f"README Approvals/Task mismatch for {cfg}: got {readme_bar_d!r}, expected {expected_val!r}"
        )

    # 2. Verify C6 per-set (v1, v2, v3, v4, Combined) Approvals/Task match generated Bar (d) breakdown table
    gen_perset_section = generated.split("### Bar (d) Approvals / Task Breakdown Per Benign Set")[1]
    gen_perset_c6 = _extract_table_cells(gen_perset_section, "C6")
    # Columns: Configuration | v1 | v2 | v3 | v4 | Combined | All Sets <= 1.0
    expected_perset = {
        "v1": gen_perset_c6[1],  # e.g. "0.28 (9/32)"
        "v2": gen_perset_c6[2],
        "v3": gen_perset_c6[3],
        "v4": gen_perset_c6[4],
        "Combined": gen_perset_c6[5],
    }

    for set_label, expected_ratio in expected_perset.items():
        val, ratio = expected_ratio.split(" ", 1)
        pattern = re.compile(
            rf"{re.escape(set_label)}.*?Approvals\s*/\s*task\s*=\s*`?{re.escape(val)}`?\s*\(`?{re.escape(ratio[1:-1])}`?\)",
            re.IGNORECASE,
        )
        assert pattern.search(readme_text), (
            f"README missing or mismatched C6 {set_label} Approvals/task figure `{expected_ratio}`"
        )

    # 3. Verify honesty/scope requirements in README.md
    lowered = readme_text.lower()
    assert "development set, scripted attacker, not final benchmark results" in lowered
    assert "default profile c6 (candidate, owner has not tagged)" in lowered
    assert "fake github server" in lowered
    assert "verified" not in lowered, "README must not claim 'verified'"
    assert "frozen" not in lowered, (
        "README must use 'candidate, owner has not tagged' rather than 'frozen'"
    )
