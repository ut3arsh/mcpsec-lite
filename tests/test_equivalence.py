"""Tests for official GitHub translation map, harness --github-schema flag, and equivalence checker."""

from __future__ import annotations

import copy
import csv
import json
from pathlib import Path

import pytest

from benchmark.check_equivalence import generate_equivalence_report
from benchmark.check_equivalence import main as equiv_main
from benchmark.dev.benchmark_dev import (
    Scenario,
    ScenarioStep,
    execute_scenario_through_proxy,
    load_github_official_map,
    load_scenarios_from_manifests,
    translate_scenario_to_official,
)
from mcpsec_core.pinning import PinStore, clean_tool_definition
from mcpsec_core.policy import load_policy_file
from tests.fakes.fake_github_official import load_official_snapshot_tools


def test_translate_scenario_to_official_and_fail_closed() -> None:
    """Valid handwritten GitHub steps translate deterministically; unknown tools/args fail closed."""
    omap = load_github_official_map(Path("benchmark/github_official_map.json"))
    sc = Scenario(
        id="TEST-TR",
        name="Test translation",
        category="benign",
        description="Read issue and comment",
        steps=[
            ScenarioStep(
                server="github",
                tool="get_issue",
                args={"owner": "org", "repo": "app", "issue_number": 42},
                capabilities=("network_read",),
                description="Read issue",
            ),
            ScenarioStep(
                server="github",
                tool="create_issue_comment",
                args={"owner": "org", "repo": "app", "issue_number": 42, "body": "ok"},
                capabilities=("write", "egress"),
                description="Post comment",
            ),
            ScenarioStep(
                server="filesystem",
                tool="read_file",
                args={"path": "sandbox/README.md"},
                capabilities=("read",),
                description="Non-github untouched",
            ),
        ],
    )
    pred = {"type": "sink_received_marker", "target_tool": "github.get_issue", "marker": "42"}
    tr_sc, tr_pred = translate_scenario_to_official(sc, omap, pred)

    assert tr_sc.steps[0].tool == "issue_read"
    assert tr_sc.steps[0].args == {
        "owner": "org",
        "repo": "app",
        "issue_number": 42,
        "method": "get",
    }
    assert tr_sc.steps[1].tool == "add_issue_comment"
    assert tr_sc.steps[1].args == {
        "owner": "org",
        "repo": "app",
        "issue_number": 42,
        "body": "ok",
    }
    assert tr_sc.steps[2].server == "filesystem"
    assert tr_sc.steps[2].tool == "read_file"
    assert tr_pred is not None
    assert tr_pred["target_tool"] == "github.issue_read"

    # Unmapped tool fails closed
    bad_tool = Scenario(
        id="BAD-1",
        name="Bad tool",
        category="attack",
        description="",
        steps=[ScenarioStep("github", "nonexistent_hw_tool", {}, ("network_read",), "")],
    )
    with pytest.raises(KeyError, match="nonexistent_hw_tool"):
        translate_scenario_to_official(bad_tool, omap)

    # Unmapped arg fails closed
    bad_arg = Scenario(
        id="BAD-2",
        name="Bad arg",
        category="attack",
        description="",
        steps=[ScenarioStep("github", "get_issue", {"unexpected": 1}, ("network_read",), "")],
    )
    with pytest.raises(ValueError, match="Unmapped GitHub arg"):
        translate_scenario_to_official(bad_arg, omap)


@pytest.mark.asyncio
async def test_proxy_execution_equivalence_subset_c6_vs_c7(tmp_path: Path) -> None:
    """Spot-check C6 handwritten vs C7 official execution equivalence on key GitHub scenarios."""
    c6, _, _ = load_policy_file(Path("benchmark/configs/C6.yaml"))
    c7, _, _ = load_policy_file(Path("benchmark/configs/C7.yaml"))
    attacks, benigns, preds = load_scenarios_from_manifests()

    by_id = {s.id: s for s in attacks + benigns}
    subset_ids = [
        "ATTACK-01",
        "ATTACK-19",
        "ATTACK-23",
        "ATTACK-27",
        "BENIGN-01",
        "BENIGN-36",
        "BENIGN-42",
    ]

    hw_pins = PinStore(tmp_path / "pins_hw.json")
    for s in ["fs", "filesystem", "fetch", "http", "github"]:
        for t, d in {
            "read_file": "Read file",
            "write_file": "Write file",
            "list_directory": "List directory",
            "fetch": "Fetch HTTP",
            "get_issue": "Get issue",
            "create_issue_comment": "Comment",
            "list_issues": "List issues",
            "search_repositories": "Search",
        }.items():
            hw_pins.approve_tool(s, {"name": t, "description": d, "inputSchema": {}})

    off_pins = PinStore(tmp_path / "pins_off.json")
    for s in ["fs", "filesystem", "fetch", "http"]:
        for t, d in {
            "read_file": "Read file",
            "write_file": "Write file",
            "list_directory": "List directory",
            "fetch": "Fetch HTTP",
        }.items():
            off_pins.approve_tool(s, {"name": t, "description": d, "inputSchema": {}})
    off_tools, _ = load_official_snapshot_tools(read_only=False)
    for t_obj in off_tools:
        off_pins.approve_tool(
            "github",
            clean_tool_definition(t_obj.model_dump(by_alias=True, exclude_none=True)),
        )

    for sc_id in subset_ids:
        sc = by_id[sc_id]
        for mode in ("deny_all", "approve_all"):
            r6 = await execute_scenario_through_proxy(
                sc,
                c6,
                "C6",
                hw_pins,
                tmp_path,
                approval_mode=mode,
                predicate_meta=preds.get(sc_id),
                github_schema="handwritten",
            )
            r7 = await execute_scenario_through_proxy(
                sc,
                c7,
                "C7",
                off_pins,
                tmp_path,
                approval_mode=mode,
                predicate_meta=preds.get(sc_id),
                github_schema="official",
            )
            # (status, blocking_layer, rule_id)
            assert (r6[10], r6[4], r6[5]) == (r7[10], r7[4], r7[5]), (
                f"Equivalence mismatch on {sc_id} ({mode}): C6={r6} vs C7={r7}"
            )


def test_equivalence_checker_detects_mismatches_and_completeness_errors(tmp_path: Path) -> None:
    """Equivalence checker passes when aligned, and fails closed on decision mismatches or missing rows."""
    attacks, benigns, _ = load_scenarios_from_manifests()
    all_scenarios = attacks + benigns

    left_dir = tmp_path / "left"
    right_dir = tmp_path / "right"
    left_dir.mkdir()
    right_dir.mkdir()

    fieldnames = [
        "id",
        "name",
        "category",
        "classification",
        "config",
        "approval_mode",
        "status",
        "approvals_count",
        "blocking_layer",
        "rule_id",
        "decision_reason",
        "success_check_passed",
        "taint_expected",
        "taint_acquired",
        "outcome",
        "approvals_requested",
        "denied_step_index",
        "approval_rules",
    ]

    def _write_run(out_dir: Path, cfg: str, schema: str, override_bad: bool = False) -> None:
        rows = []
        for sc in all_scenarios:
            for mode in ("deny_all", "approve_all"):
                status = "blocked" if sc.category == "attack" else "completed clean"
                layer = "flow" if sc.category == "attack" else "none"
                rule = "deny-private-egress" if sc.category == "attack" else "none"
                if override_bad and sc.id == "ATTACK-01" and mode == "deny_all":
                    status = "succeeded"
                    layer = "none"
                    rule = "none"
                rows.append(
                    {
                        "id": sc.id,
                        "name": sc.name,
                        "category": sc.category,
                        "classification": sc.classification,
                        "config": cfg,
                        "approval_mode": mode,
                        "status": status,
                        "approvals_count": "0",
                        "blocking_layer": layer,
                        "rule_id": rule,
                        "decision_reason": "ok",
                        "success_check_passed": "true",
                        "taint_expected": "",
                        "taint_acquired": "",
                        "outcome": "blocked" if status == "blocked" else "completed",
                        "approvals_requested": "0",
                        "denied_step_index": "",
                        "approval_rules": "",
                    }
                )
        with open(out_dir / "trials.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        (out_dir / "run.json").write_text(
            json.dumps({"configs": [cfg], "github_schema": schema}), encoding="utf-8"
        )

    _write_run(left_dir, "C6", "handwritten")
    _write_run(right_dir, "C7", "official")

    report, mismatches = generate_equivalence_report(left_dir, right_dir)
    assert len(mismatches) == 0
    assert "Zero mismatches observed across all 166" in report

    out_md = tmp_path / "equiv_ok.md"
    assert (
        equiv_main(
            [
                "--left-dir",
                str(left_dir),
                "--right-dir",
                str(right_dir),
                "--output",
                str(out_md),
            ]
        )
        == 0
    )

    # Inject mismatch on ATTACK-01 deny_all -> non-zero exit & listed in report
    bad_right = copy.deepcopy(right_dir)
    _write_run(bad_right, "C7", "official", override_bad=True)
    out_bad = tmp_path / "equiv_bad.md"
    assert (
        equiv_main(
            [
                "--left-dir",
                str(left_dir),
                "--right-dir",
                str(bad_right),
                "--output",
                str(out_bad),
            ]
        )
        == 1
    )
    bad_text = out_bad.read_text(encoding="utf-8")
    assert "ATTACK-01" in bad_text
    assert "Detected Equivalence Bugs" in bad_text

    # Delete a row from right -> completeness failure (exit 1)
    rows_minus_one = list(csv.DictReader((right_dir / "trials.csv").open(encoding="utf-8")))[:-1]
    with open(right_dir / "trials.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_minus_one)
    assert (
        equiv_main(
            [
                "--left-dir",
                str(left_dir),
                "--right-dir",
                str(right_dir),
                "--output",
                str(out_md),
            ]
        )
        == 1
    )
