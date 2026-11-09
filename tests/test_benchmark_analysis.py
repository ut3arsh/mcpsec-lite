"""Test automated benchmark analysis and byte-for-byte reproducibility."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmark.analysis_legacy import (
    generate_report as generate_legacy_report,
)
from benchmark.analysis_legacy import (
    load_manifest,
    load_trials,
    wilson_interval,
)


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
    run1 = generate_legacy_report(trials, manifest, date_str="2026-10-11")
    # Second regeneration
    run2 = generate_legacy_report(trials, manifest, date_str="2026-10-11")

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
    run1 = generate_legacy_report(
        trials, manifest, date_str="2026-11-01", benign_manifest=benign_manifest
    )
    # Second regeneration
    run2 = generate_legacy_report(
        trials, manifest, date_str="2026-11-01", benign_manifest=benign_manifest
    )

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
    run1 = generate_legacy_report(
        trials,
        manifest,
        date_str="2026-11-02",
        benign_manifest=benign_manifest,
        benign_manifest_v2=benign_manifest_v2,
    )
    # Second regeneration
    run2 = generate_legacy_report(
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
    run1 = generate_legacy_report(
        trials,
        manifest,
        date_str="2026-11-03",
        benign_manifest=benign_manifest,
        benign_manifest_v2=benign_manifest_v2,
        benign_manifest_v3=benign_manifest_v3,
    )
    # Second regeneration
    run2 = generate_legacy_report(
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


def test_completeness_validation_detects_missing_row() -> None:
    from benchmark.analysis import TrialCompletenessError, validate_trial_completeness

    scenarios = ["BENIGN-01", "BENIGN-02"]
    configs = ["C1", "C2"]
    modes = ["deny_all", "approve_all"]

    full_trials = [
        {"id": sc, "config": cfg, "approval_mode": mode}
        for sc in scenarios
        for cfg in configs
        for mode in modes
    ]

    # Valid case passes without error
    validate_trial_completeness(full_trials, scenarios, configs, modes)

    # Missing row: drop (BENIGN-02, C2, approve_all)
    incomplete_trials = [
        t
        for t in full_trials
        if not (
            t["id"] == "BENIGN-02" and t["config"] == "C2" and t["approval_mode"] == "approve_all"
        )
    ]

    with pytest.raises(TrialCompletenessError) as exc_info:
        validate_trial_completeness(incomplete_trials, scenarios, configs, modes)

    err = str(exc_info.value)
    assert "BENIGN-02" in err
    assert "C2" in err
    assert "approve_all" in err
    assert "Missing 1 required trial(s)" in err


def test_completeness_validation_detects_duplicate_row() -> None:
    from benchmark.analysis import TrialCompletenessError, validate_trial_completeness

    scenarios = ["BENIGN-01", "BENIGN-02"]
    configs = ["C1", "C2"]
    modes = ["deny_all", "approve_all"]

    full_trials = [
        {"id": sc, "config": cfg, "approval_mode": mode}
        for sc in scenarios
        for cfg in configs
        for mode in modes
    ]

    # Duplicate row: add duplicate of (BENIGN-01, C1, deny_all)
    duplicated_trials = list(full_trials)
    duplicated_trials.append({"id": "BENIGN-01", "config": "C1", "approval_mode": "deny_all"})

    with pytest.raises(TrialCompletenessError) as exc_info:
        validate_trial_completeness(duplicated_trials, scenarios, configs, modes)

    err = str(exc_info.value)
    assert "BENIGN-01" in err
    assert "C1" in err
    assert "deny_all" in err
    assert "Duplicated 1 trial tuple(s)" in err


def test_chunk_5_17a_rerun_byte_for_byte_reproducibility() -> None:
    from benchmark.analysis import (
        generate_analysis_report,
        load_run_config,
    )
    from benchmark.analysis import (
        load_manifest as load_manifest_v2,
    )
    from benchmark.analysis import (
        load_trials as load_trials_v2,
    )

    trials_path = Path("benchmark/results/dev_20261103/trials.csv")
    run_json_path = Path("benchmark/results/dev_20261103/run.json")
    report_path = Path("benchmark/results/dev_analysis_20261104_rerun.md")

    if not trials_path.exists() or not report_path.exists() or not run_json_path.exists():
        pytest.skip("Benchmark result files not present")

    trials = load_trials_v2(trials_path)
    run_config = load_run_config(run_json_path, trials_path)
    attack_manifest = load_manifest_v2(Path("benchmark/attacks/dev/manifest.json"))
    benign_manifests = [
        load_manifest_v2(Path("benchmark/benign/manifest.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v2.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v3.json")),
    ]

    # First regeneration
    run1 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )
    # Second regeneration
    run2 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed / generated file
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.17a rerun analysis report failed byte-for-byte check"
    )


def test_chunk_5_17a_c5_byte_for_byte_reproducibility() -> None:
    from benchmark.analysis import (
        generate_analysis_report,
        load_run_config,
    )
    from benchmark.analysis import (
        load_manifest as load_manifest_v2,
    )
    from benchmark.analysis import (
        load_trials as load_trials_v2,
    )

    trials_path = Path("benchmark/results/dev_20261104_c5/trials.csv")
    run_json_path = Path("benchmark/results/dev_20261104_c5/run.json")
    report_path = Path("benchmark/results/dev_analysis_20261104_c5.md")

    if not trials_path.exists() or not report_path.exists() or not run_json_path.exists():
        pytest.skip("Benchmark result files not present")

    trials = load_trials_v2(trials_path)
    run_config = load_run_config(run_json_path, trials_path)
    attack_manifest = load_manifest_v2(Path("benchmark/attacks/dev/manifest.json"))
    benign_manifests = [
        load_manifest_v2(Path("benchmark/benign/manifest.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v2.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v3.json")),
    ]

    # First regeneration
    run1 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )
    # Second regeneration
    run2 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed / generated file
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.17a C5 analysis report failed byte-for-byte check"
    )


def test_chunk_5_17_e4_byte_for_byte_reproducibility() -> None:
    from benchmark.analysis import (
        generate_analysis_report,
        load_run_config,
    )
    from benchmark.analysis import (
        load_manifest as load_manifest_v2,
    )
    from benchmark.analysis import (
        load_trials as load_trials_v2,
    )

    trials_path = Path("benchmark/results/dev_20261106_e4/trials.csv")
    run_json_path = Path("benchmark/results/dev_20261106_e4/run.json")
    report_path = Path("benchmark/results/dev_analysis_20261106_e4.md")

    if not trials_path.exists() or not report_path.exists() or not run_json_path.exists():
        pytest.skip("Benchmark result files not present")

    trials = load_trials_v2(trials_path)
    run_config = load_run_config(run_json_path, trials_path)
    attack_manifest = load_manifest_v2(Path("benchmark/attacks/dev/manifest.json"))
    benign_manifests = [
        load_manifest_v2(Path("benchmark/benign/manifest.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v2.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v3.json")),
    ]

    # First regeneration
    run1 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )
    # Second regeneration
    run2 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed / generated file
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.17 E4 analysis report failed byte-for-byte check"
    )


def test_chunk_5_17b_e4b_byte_for_byte_reproducibility() -> None:
    from benchmark.analysis import (
        generate_analysis_report,
        load_run_config,
    )
    from benchmark.analysis import (
        load_manifest as load_manifest_v2,
    )
    from benchmark.analysis import (
        load_trials as load_trials_v2,
    )

    trials_path = Path("benchmark/results/dev_20261109_e4b/trials.csv")
    run_json_path = Path("benchmark/results/dev_20261109_e4b/run.json")
    report_path = Path("benchmark/results/dev_analysis_20261109_e4b.md")

    if not trials_path.exists() or not report_path.exists() or not run_json_path.exists():
        pytest.skip("Benchmark result files not present")

    trials = load_trials_v2(trials_path)
    run_config = load_run_config(run_json_path, trials_path)
    attack_manifest = load_manifest_v2(Path("benchmark/attacks/dev/manifest.json"))
    benign_manifests = [
        load_manifest_v2(Path("benchmark/benign/manifest.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v2.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v3.json")),
    ]

    # First regeneration
    run1 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )
    # Second regeneration
    run2 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed / generated file
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.17b E4b analysis report failed byte-for-byte check"
    )


def test_chunk_5_17c_byte_for_byte_reproducibility() -> None:
    from benchmark.analysis import (
        generate_analysis_report,
        load_run_config,
    )
    from benchmark.analysis import (
        load_manifest as load_manifest_v2,
    )
    from benchmark.analysis import (
        load_trials as load_trials_v2,
    )

    trials_path = Path("benchmark/results/dev_20261109_e5/trials.csv")
    run_json_path = Path("benchmark/results/dev_20261109_e5/run.json")
    report_path = Path("benchmark/results/dev_analysis_20261109_e5.md")

    if not trials_path.exists() or not report_path.exists() or not run_json_path.exists():
        pytest.skip("Benchmark result files not present")

    trials = load_trials_v2(trials_path)
    run_config = load_run_config(run_json_path, trials_path)
    attack_manifest = load_manifest_v2(Path("benchmark/attacks/dev/manifest.json"))
    benign_manifests = [
        load_manifest_v2(Path("benchmark/benign/manifest.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v2.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v3.json")),
        load_manifest_v2(Path("benchmark/benign/manifest_v4.json")),
    ]

    # First regeneration
    run1 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )
    # Second regeneration
    run2 = generate_analysis_report(
        trials=trials,
        run_config=run_config,
        attack_manifest=attack_manifest,
        benign_manifests=benign_manifests,
    )

    # Pure function determinism
    assert run1 == run2

    # Byte-for-byte identity against committed / generated file
    expected_bytes = report_path.read_bytes().replace(b"\r\n", b"\n")
    actual_bytes = run1.encode("utf-8")

    assert actual_bytes == expected_bytes, (
        "Regenerating Chunk 5.17c E5 analysis report failed byte-for-byte check"
    )
