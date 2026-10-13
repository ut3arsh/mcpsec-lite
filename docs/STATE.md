# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.9.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7: pinned `setup-node` to v7.0.0 SHA `820762786026740c76f36085b0efc47a31fe5020`. Appended `ATTACK-23` (tool mutation rug-pull). Raw per-trial records in `trials.csv`. `benchmark/analysis.py` generates all tables with byte-for-byte reproducibility tested.
- Chunk 5.8: Validated dev benchmark. Aligned C1 policy to match C2 allowlists (capabilities, path, and domain constraints); C1 blocks off-allowlist sinks (ATTACK-05, ATTACK-08, ATTACK-12). Added per-scenario `success_predicate` to manifest. ATTACK-22 marked `invalid` (no mutation) and excluded from evaluation denominators. ATTACK-19 reclassified `in-scope` (`[write, egress]`); ATTACK-24 added as genuine `known-gap` allowed-channel leak (`[write]`-only tool). Added harness approval modes (`deny_all` vs. `approve_all`) with 340 raw trials recorded. Fixed report prose (`ERR_TOOL_HASH_MISMATCH`, resolved 6.4 contradiction, aligned C1 verdict with spec).
- Chunk 5.9: Hardened CI security gate. `pip-audit` audits hashed lockfile (`requirements.lock`, `--require-hashes --strict`) with `|| echo` and `continue-on-error` removed; dated, justified ignores enforced via `audit-ignores.txt`. CI writes to `$GITHUB_STEP_SUMMARY`: `pytest -rs` skip list, `mcpsec_core` branch coverage with 2 decimals, and `pip-audit` result. Moved `benchmark/gh_cmd.py` to `scripts/gh_cmd.py` (credential-free). Reconciled C1 attribution and per-class totals (11/14 in-scope, 7/7 known-gap, 2/2 out-of-scope; 20/23 total).

## Verified Numbers (chunk 5.9 run)
- **CI Matrix**: Green across matrix (`ubuntu-24.04`, `windows-2022` on Python 3.11, 3.12, 3.13) with no masked failures.
- **Plain unit suite (`pytest`)**: 179 passed, 2 skipped, 8 deselected, 2 xfailed in ~41s (gate < 60s passed).
- **Static checks**: `mypy --strict` clean (66 source files including `scripts/`), `ruff check` clean, `ruff format` clean.
- **Dependency audit (`pip-audit`)**: Clean (0 unignored vulnerabilities on `requirements.lock`).
- **mcpsec_core Branch Coverage**: 91.08% overall branch-aware coverage (gate $\ge 90.00\%$), 87.68% pure branch coverage.
- **Summary Matrix Across Configurations (23 Valid Attacks, 10 Benign Tasks)**:
  - C0: ASR 23/23 (100.0%, 95% CI [0.8540, 1.0000]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C1: ASR 20/23 (87.0%, 95% CI [0.6786, 0.9546]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C2 (`deny_all`): ASR 10/23 (43.5%, 95% CI [0.2560, 0.6338]), FPR 2/10 (20.0%, 95% CI [0.0567, 0.5098])
  - C2 (`approve_all`): ASR 13/23 (56.5%, 95% CI [0.3662, 0.7440]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C3 (`deny_all`): ASR 10/23 (43.5%), FPR 2/10 (20.0%)
  - C4 (`deny_all`): ASR 9/23 (39.1%, 95% CI [0.2220, 0.5922]), FPR 2/10 (20.0%)
  - C4 (`approve_all`): ASR 12/23 (52.2%, 95% CI [0.3302, 0.7077]), FPR 0/10 (0.0%)
- **C1 Per-Class Breakdown**: In-Scope 11/14 (78.6%), Known-Gap 7/7 (100.0%), Out-of-Scope 2/2 (100.0%).

## Open Items (to close in order)
1. Raise remaining individual `mcpsec_core` module branch coverage to >= 90% (approvals 82%, detectors 78%, audit 88%).
2. Evidence carry-overs: perf metrics without cache, concurrency integrity under multi-process contention.
3. Defenses remain unfrozen; no `v0.2-frozen` tag until items 1–2 are resolved.