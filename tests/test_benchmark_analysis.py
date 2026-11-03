"""Test automated benchmark analysis and byte-for-byte reproducibility."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmark.analysis import generate_report, load_manifest, load_trials, wilson_interval


def test_wilson_interval_properties() -> None:
    # Edge case: n == 0
    assert wilson_interval(0, 0) == (0.0, 0.0)

    # Edge case: k == 0
    low, high = wilson_interval(0, 10)
    assert low == 0.0
    assert 0.0 < high < 1.0

    # Edge case: k == n
    low, high = wilson_interval(10, 10)
    assert 0.0 < low < 1.0
    assert high == 1.0

    # Symmetry for 50%
    low_half, high_half = wilson_interval(50, 100)
    assert round(0.5 - low_half, 4) == round(high_half - 0.5, 4)


def test_byte_for_byte_reproducibility() -> None:
    trials_path = Path("benchmark/results/dev_20261011/trials.csv")
    manifest_path = Path("benchmark/attacks/dev/manifest.json")
    report_path = Path("benchmark/results/dev_analysis_20261011.md")

    if not trials_path.exists() or not report_path.exists():
        pytest.skip("Benchmark result files not present")

    trials = load_trials(trials_path)
    manifest = load_manifest(manifest_path)

    # First regeneration
    run1 = generate_report(trials, manifest, date_str="2026-10-11")
    # Second regeneration
    run2 = generate_report(trials, manifest, date_str="2026-10-11")

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed file (handling git checkout autocrlf)
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, "Regenerating analysis report failed byte-for-byte check"


def test_chunk_5_14_byte_for_byte_reproducibility() -> None:
    trials_path = Path("benchmark/results/dev_20261101/trials.csv")
    manifest_path = Path("benchmark/attacks/dev/manifest.json")
    benign_manifest_path = Path("benchmark/benign/manifest.json")
    report_path = Path("benchmark/results/dev_analysis_20261101.md")

    if not trials_path.exists() or not report_path.exists() or not benign_manifest_path.exists():
        pytest.skip("Benchmark result files not present")

    trials = load_trials(trials_path)
    manifest = load_manifest(manifest_path)
    benign_manifest = load_manifest(benign_manifest_path)

    # First regeneration
    run1 = generate_report(trials, manifest, date_str="2026-11-01", benign_manifest=benign_manifest)
    # Second regeneration
    run2 = generate_report(trials, manifest, date_str="2026-11-01", benign_manifest=benign_manifest)

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed file (handling git checkout autocrlf)
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.14 analysis report failed byte-for-byte check"
    )


def test_chunk_5_15_byte_for_byte_reproducibility() -> None:
    trials_path = Path("benchmark/results/dev_20261102/trials.csv")
    manifest_path = Path("benchmark/attacks/dev/manifest.json")
    benign_manifest_path = Path("benchmark/benign/manifest.json")
    benign_manifest_v2_path = Path("benchmark/benign/manifest_v2.json")
    report_path = Path("benchmark/results/dev_analysis_20261102.md")

    if (
        not trials_path.exists()
        or not report_path.exists()
        or not benign_manifest_path.exists()
        or not benign_manifest_v2_path.exists()
    ):
        pytest.skip("Benchmark result files not present")

    trials = load_trials(trials_path)
    manifest = load_manifest(manifest_path)
    benign_manifest = load_manifest(benign_manifest_path)
    benign_manifest_v2 = load_manifest(benign_manifest_v2_path)

    # First regeneration
    run1 = generate_report(
        trials,
        manifest,
        date_str="2026-11-02",
        benign_manifest=benign_manifest,
        benign_manifest_v2=benign_manifest_v2,
    )
    # Second regeneration
    run2 = generate_report(
        trials,
        manifest,
        date_str="2026-11-02",
        benign_manifest=benign_manifest,
        benign_manifest_v2=benign_manifest_v2,
    )

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed file (handling git checkout autocrlf)
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.15 analysis report failed byte-for-byte check"
    )


def test_chunk_5_16_byte_for_byte_reproducibility() -> None:
    trials_path = Path("benchmark/results/dev_20261103/trials.csv")
    manifest_path = Path("benchmark/attacks/dev/manifest.json")
    benign_manifest_path = Path("benchmark/benign/manifest.json")
    benign_manifest_v2_path = Path("benchmark/benign/manifest_v2.json")
    benign_manifest_v3_path = Path("benchmark/benign/manifest_v3.json")
    report_path = Path("benchmark/results/dev_analysis_20261103.md")

    if (
        not trials_path.exists()
        or not report_path.exists()
        or not benign_manifest_path.exists()
        or not benign_manifest_v2_path.exists()
        or not benign_manifest_v3_path.exists()
    ):
        pytest.skip("Benchmark result files not present")

    trials = load_trials(trials_path)
    manifest = load_manifest(manifest_path)
    benign_manifest = load_manifest(benign_manifest_path)
    benign_manifest_v2 = load_manifest(benign_manifest_v2_path)
    benign_manifest_v3 = load_manifest(benign_manifest_v3_path)

    # First regeneration
    run1 = generate_report(
        trials,
        manifest,
        date_str="2026-11-03",
        benign_manifest=benign_manifest,
        benign_manifest_v2=benign_manifest_v2,
        benign_manifest_v3=benign_manifest_v3,
    )
    # Second regeneration
    run2 = generate_report(
        trials,
        manifest,
        date_str="2026-11-03",
        benign_manifest=benign_manifest,
        benign_manifest_v2=benign_manifest_v2,
        benign_manifest_v3=benign_manifest_v3,
    )

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed file (handling git checkout autocrlf)
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.16 analysis report failed byte-for-byte check"
    )
