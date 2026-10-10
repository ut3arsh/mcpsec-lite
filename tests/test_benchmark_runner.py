"""Unit tests for the benchmark runner skeleton and statistical functions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.runner import BenchmarkRunner, BenchmarkScenario, Step, wilson_interval


def test_wilson_interval_edge_cases() -> None:
    """Test Wilson interval for boundary conditions and standard proportions."""
    # n = 0 edge case
    low, high = wilson_interval(0, 0)
    assert low == 0.0
    assert high == 0.0

    # k = 0, n = 100
    low, high = wilson_interval(0, 100)
    assert low == 0.0
    assert 0.0 < high < 0.05  # ~0.0368

    # k = 100, n = 100
    low, high = wilson_interval(100, 100)
    assert 0.95 < low < 1.0
    assert high == 1.0

    # k = 50, n = 100
    low, high = wilson_interval(50, 100)
    assert 0.40 < low < 0.41
    assert 0.59 < high < 0.60

    # n = 1, k = 1
    low, high = wilson_interval(1, 1)
    assert 0.20 < low < 0.30
    assert high == 1.0


@pytest.mark.asyncio
async def test_benchmark_runner_dry_run_artifacts(tmp_path: Path) -> None:
    """Test BenchmarkRunner produces manifest.json, trials.csv, and summary.csv on dry-run."""
    configs_dir = tmp_path / "configs"
    configs_dir.mkdir()
    c0_file = configs_dir / "C0.yaml"
    c0_file.write_text(
        """version: 1
mode: audit
capabilities:
  "*": [read, write, network_read, egress, exec]
policies:
  - agent: "*"
    tools:
      "*": {}
""",
        encoding="utf-8",
    )

    runner = BenchmarkRunner(config_dir=configs_dir, output_root=tmp_path / "runs")
    scenario = BenchmarkScenario(
        id="TEST-01",
        name="Test scenario",
        category="attack",
        steps=[
            Step(
                server="filesystem",
                tool="read_file",
                args={"path": "/repo/notes.txt"},
                capabilities=["read"],
            )
        ],
    )

    run_dir = await runner.run_benchmark(
        scenarios=[scenario],
        configs=["C0"],
        num_trials=1,
        dry_run=True,
    )

    assert run_dir.exists()
    assert (run_dir / "manifest.json").exists()
    assert (run_dir / "trials.csv").exists()
    assert (run_dir / "summary.csv").exists()

    manifest_data = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_data["settings"]["dry_run"] is True
    assert "C0" in manifest_data["configs"]

    trials_text = (run_dir / "trials.csv").read_text(encoding="utf-8")
    assert "TEST-01" in trials_text

    summary_text = (run_dir / "summary.csv").read_text(encoding="utf-8")
    assert "attacks" in summary_text
