"""Tests for policy CLI tool (mcpsec-policy validate and explain)."""

from __future__ import annotations

import json
from pathlib import Path

from cli.policy_cli import validate_policy_file

VALID_YAML = """
version: 1
mode: enforce
capabilities:
  fs.read_file: [read]
policies:
  - agent: dev-agent
    tools:
      fs.read_file:
        path_allowlist: ["/safe/**"]
"""

INVALID_YAML = """
version: 99
mode: invalid_mode
"""


def test_cli_validate_success(tmp_path: Path, capsys: None) -> None:
    pol_file = tmp_path / "policy.yaml"
    pol_file.write_text(VALID_YAML, encoding="utf-8")

    code = validate_policy_file(pol_file)
    assert code == 0


def test_cli_validate_failure(tmp_path: Path, capsys: None) -> None:
    pol_file = tmp_path / "bad_policy.yaml"
    pol_file.write_text(INVALID_YAML, encoding="utf-8")

    code = validate_policy_file(pol_file)
    assert code == 1


def test_cli_validate_with_explain(tmp_path: Path, capsys: None) -> None:
    pol_file = tmp_path / "policy.yaml"
    pol_file.write_text(VALID_YAML, encoding="utf-8")

    # Allowed call
    code_allow = validate_policy_file(
        pol_file,
        explain=["dev-agent", "fs.read_file", json.dumps({"path": "/safe/data.txt"})],
    )
    assert code_allow == 0

    # Denied call
    code_deny = validate_policy_file(
        pol_file,
        explain=["dev-agent", "fs.read_file", json.dumps({"path": "/etc/shadow"})],
    )
    assert code_deny == 0
