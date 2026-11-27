# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.18e.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.13: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock`), cross-process locks, audit log rotation and hash-chain tampering verification, exact coverage gate, skips/xfails CI evidence correction, 6 mutation checks, 85% per-module floor.
- Chunk 5.14–5.17c: pre-registered benign workflows (v1..v4); automated `analysis.py` with Wilson 95% CIs and matrix completeness validation; ADR-018 (C5 adoption); flow-rule `unless.path_allowlist`; E4b / E5 ablations with file-origin untrusted taint and multi-session seeding.
- Chunk 5.18a–5.18c: ADR-019 (`C6` baseline in `273b22f`), `ConfigIntegrityError` in `analysis.py`, `approve_cli.py` ANSI/Bidi/URL-query redaction, full-history secret scan, official `github/github-mcp-server v2.3.0` snapshot (`46` default / `27` read-only tools) in `tests/fixtures/github.tools.official.json`, `scripts/report_skips.py`, `docs/claims.md`, `docs/freeze_checklist.md`, `scripts/freeze_manifest.py`.
- Chunk 5.18d: `ADR-020` (`OFFICIAL_GITHUB_TOOL_TABLE` 46 tools in `mcpsec_core/adapters.py`, offline contract test in `tests/test_contract.py`, `C7.yaml` + `benchmark/github_official_map.json` in `f962612`, `tests/fakes/fake_github_official.py`, `benchmark/check_equivalence.py`).
- Chunk 5.18e: accepted & implemented `ADR-021` (`BUILTIN_TOOL_TAINT_CLASSES` / `UNTRUSTED_CONTENT_BUILTIN_TOOLS` `21` `U` tools in `adapters.py`; Rule 11 `ERR_TAINT_SOURCE_MISSING` & `taint_exempt` `ERR_INVALID_TAINT_EXEMPT` in `mcpsec_core/policy.py`, `docs/policy_schema.md`, `docs/conformance.md`); 3/3 mutation spot-checks killed; `ADR-022` promotes `C7` as freeze-candidate default while keeping `C6` baseline unchanged (`benchmark/configs/pins.json` confirmed untracked/unused and stale copies removed); added `docs/operating_with_github_mcp.md`, updated `scripts/freeze_manifest.py`, `README.md`, `docs/claims.md`, `docs/freeze_checklist.md`.

## Verified Numbers (chunk 5.18e run)
- **Plain unit suite (`pytest -rsx`)**: 314 passed, 1 skipped, 8 deselected, 2 xfailed in 41.07s (< 60s).
- **Full suite (`pytest -rsx -m "integration or not integration"`)**: 320 passed, 3 skipped, 2 xfailed in 57.19s.
- **Static & Supply-Chain**: `mypy --strict` clean (87 source files), `ruff check` clean, `ruff format` clean (157 files), `pip-audit` clean (`No known vulnerabilities found`).
- **Dual-OS CI Gate (Run `46055135980`, `https://github.com/ut3arsh/mcpsec-lite/actions/runs/46055135980`)**: 9/9 jobs green (`ubuntu-24.04` & `windows-2022` Python 3.11–3.14 + `Combined Coverage Gate`), 0 annotations; combined `mcpsec_core` coverage: **97.19% statements** (1865/1919), **95.24% branches** (741/778), all modules `>= 90.38%`.
- **C6 vs C7 Equivalence (post-ADR-021, dev set, n=83 scenarios x 2 modes = 166 pairs)**: `166/166` (100.00%) match on `(status, blocking_layer, rule_id)` and `0/166` secondary diffs (`docs/evidence/5.18e/equivalence_c6_vs_c7.md`). C7 (`benchmark/results/dev_analysis_20261127_c7.md`, dev scenarios exercise `4` of `46` official tools): Hard-Block `0/50`, Attended `50/50` (`100.0%`), Unattended `32/50` (`64.0%`), `deny_all` In-Scope ASR `0/21` (`0.0%`), `approve_all` In-Scope ASR `9/21` (`42.9%`), Approvals/Task `0.40 (20/50)` (v1 `0.28`, v2 `0.75`, v3 `0.50`, v4 `0.25`).
- **Baseline Matrix C0–C6 (dev set, n=50 benign, n=32 valid attacks)**:
  - Hard-Block (`deny_all`): C0 0.00%, C1 0.00%, C2 20.00%, C5 0.00%, C6 0.00%.
  - In-Scope ASR (`deny_all` / `approve_all`): C0 100%/100%, C1 85.7%/85.7%, C2 9.5%/23.8%, C5 9.5%/47.6%, C6 0.0%/42.9%.
  - Approvals/Task (`approve_all`): C0 0.00, C1 0.00, C2 0.26, C5 0.56, C6 0.40 (`ATTACK-23`: `BLOCKED/BLOCKED`).
  - Total valid ASR under C7/C6: `deny_all`: 10/32 (31.2%); `approve_all`: 20/32 (62.5%); `0` in-scope succeed under `deny_all`.

## Open Items (to close in order)
1. Defenses NOT yet frozen/tagged (`v0.2-frozen` is owner-only action using printed command from `scripts/freeze_manifest.py`); held-out scenarios are not authored until owner freezes and tags defenses.
2. Pre-5.17b legacy configs (`C2`, `C2s`, `C3`, `C4`, `E0`–`E4`) and `examples/policies/dev-agent.yaml` fail ADR-021 load audit (`ERR_TAINT_SOURCE_MISSING`); kept unedited per immutable-config rule.
