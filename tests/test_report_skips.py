"""Tests for scripts/report_skips.py skip/xfail parser and test-ID validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.report_skips import (
    SkipValidationError,
    parse_collected_nodeids,
    parse_rsx_text,
)
from scripts.report_skips import (
    main as report_skips_main,
)

SAMPLE_COLLECT_OUTPUT = """tests/test_sample_contract.py::test_live_contract
tests/test_known_gaps.py::test_known_gap_http_redirect_ssrf_bypass
tests/test_known_gaps.py::test_known_gap_filesystem_symlink_toctou
tests/test_sample_matching.py::test_path_symlink_escape_resolution
265 tests collected in 1.2s
"""


def test_parse_valid_rsx_output_and_generate_table(tmp_path: Path) -> None:
    """Valid pytest -rsx -q entries resolve via AST and validate against collected nodeids."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (tests_dir / "test_sample_contract.py").write_text(
        "def test_live_contract():\n    pass\n", encoding="utf-8"
    )
    (tests_dir / "test_sample_matching.py").write_text(
        "def test_path_symlink_escape_resolution():\n    pass\n", encoding="utf-8"
    )

    valid_ids = parse_collected_nodeids(SAMPLE_COLLECT_OUTPUT)
    rsx_text = (
        "SKIPPED [1] tests\\test_sample_contract.py:2: Opt-in live contract test\n"
        "SKIPPED [1] tests\\test_sample_matching.py:2: Symlink creation not supported\n"
        "XFAIL tests/test_known_gaps.py::test_known_gap_http_redirect_ssrf_bypass - Known Gap: SSRF\n"
        "XFAIL tests/test_known_gaps.py::test_known_gap_filesystem_symlink_toctou - Known Gap: TOCTOU\n"
    )
    entries = parse_rsx_text(rsx_text, valid_ids, root_dir=tmp_path)
    assert len(entries) == 4
    assert entries[0].nodeid == "tests/test_sample_contract.py::test_live_contract"
    assert entries[1].nodeid == "tests/test_sample_matching.py::test_path_symlink_escape_resolution"
    assert entries[2].outcome == "XFAIL"
    assert entries[2].nodeid == "tests/test_known_gaps.py::test_known_gap_http_redirect_ssrf_bypass"


def test_fake_injected_test_name_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Injecting a fake or non-existent test ID MUST fail closed with non-zero exit code."""
    collect_file = tmp_path / "collect.txt"
    collect_file.write_text(SAMPLE_COLLECT_OUTPUT, encoding="utf-8")

    # 1. Inject hallucinated XFAIL test name
    fake_xfail = tmp_path / "fake_xfail.txt"
    fake_xfail.write_text(
        "XFAIL tests/test_known_gaps.py::test_attack_24_adversarial_timing_covert_channel_known_gap - fake\n",
        encoding="utf-8",
    )
    rc1 = report_skips_main([str(fake_xfail), "--collect-file", str(collect_file)])
    assert rc1 == 1
    assert "ABSENT from pytest --collect-only -q" in capsys.readouterr().err

    # 2. Inject hallucinated SKIPPED nodeid
    fake_skip = tmp_path / "fake_skip.txt"
    fake_skip.write_text(
        "SKIPPED tests/test_contract.py::test_tools_list_contract_against_node_fs - fake\n",
        encoding="utf-8",
    )
    rc2 = report_skips_main([str(fake_skip), "--collect-file", str(collect_file)])
    assert rc2 == 1
    assert "ABSENT from pytest --collect-only -q" in capsys.readouterr().err

    # 3. Inject fake line number pointing outside any test function
    bad_line = tmp_path / "bad_line.txt"
    bad_line.write_text(
        "SKIPPED [1] tests/test_contract.py:1: module docstring line\n", encoding="utf-8"
    )
    with pytest.raises(SkipValidationError, match="does not fall inside any test function"):
        parse_rsx_text(
            bad_line.read_text(encoding="utf-8"), parse_collected_nodeids(SAMPLE_COLLECT_OUTPUT)
        )

    # 4. Inject fake test name into CI step_summary.md table
    fake_ci_md = tmp_path / "step_summary_fake.md"
    fake_ci_md.write_text(
        "### Skipped Tests (`pytest -rs`)\n\n"
        "| Test Case | Class / File | Skip Reason |\n"
        "|---|---|---|\n"
        "| `test_phantom_nonexistent` | `tests.test_contract` | bogus |\n",
        encoding="utf-8",
    )
    rc4 = report_skips_main([str(fake_ci_md), "--collect-file", str(collect_file)])
    assert rc4 == 1
    assert "ABSENT from pytest --collect-only -q" in capsys.readouterr().err
