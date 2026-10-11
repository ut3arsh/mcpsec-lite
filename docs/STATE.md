# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.8.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7: pinned `setup-node` to v7.0.0 SHA `820762786026740c76f36085b0efc47a31fe5020` (>= 14 days old). Appended `ATTACK-23` (pure tool mutation rug-pull) to `manifest.json`. Raw per-trial records in `trials.csv`. `benchmark/analysis.py` generates all tables with byte-for-byte reproducibility tested and green.
- Chunk 5.8: Validated dev benchmark. Aligned C1 policy to match C2 allowlists (capabilities, path, and domain constraints); C1 blocks off-allowlist sinks (ATTACK-05, ATTACK-08, ATTACK-12). Added per-scenario `success_predicate` to manifest (evaluated from audit log + local sink log). ATTACK-22 marked `invalid` (no mutation) and excluded from evaluation denominators. ATTACK-19 reclassified `in-scope` (`[write, egress]`); ATTACK-24 added as genuine `known-gap` allowed-channel leak (`[write]`-only tool). Added harness approval modes (`deny_all` vs. `approve_all`) with 340 raw trials recorded. Fixed report prose (corrected `ERR_TOOL_HASH_MISMATCH`, resolved 6.4 contradiction, aligned C1 verdict with `benchmark_spec.md` §2).

## Verified Numbers (chunk 5.8 run)
- **CI Matrix**: 6/6 jobs green on main.
- **Plain unit suite (`pytest`)**: 179 passed, 2 skipped, 8 deselected, 2 xfailed in ~32s (gate < 60s passed).
- **Static checks**: `mypy --strict` clean (64 source files), `ruff check` clean, `ruff format` clean.
- **Byte-for-byte reproducibility**: `tests/test_benchmark_analysis.py` passes byte-for-byte check on regenerated report.
- **Summary Matrix Across Configurations (23 Valid Attacks, 10 Benign Tasks)**:
  - C0: ASR 23/23 (100.0%, 95% CI [0.8540, 1.0000]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C1: ASR 20/23 (87.0%, 95% CI [0.6786, 0.9546]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C2 (`deny_all`): ASR 10/23 (43.5%, 95% CI [0.2560, 0.6338]), FPR 2/10 (20.0%, 95% CI [0.0567, 0.5098])
  - C2 (`approve_all`): ASR 13/23 (56.5%, 95% CI [0.3662, 0.7440]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C3 (`deny_all`): ASR 10/23 (43.5%), FPR 2/10 (20.0%)
  - C4 (`deny_all`): ASR 9/23 (39.1%, 95% CI [0.2220, 0.5922]), FPR 2/10 (20.0%)
  - C4 (`approve_all`): ASR 12/23 (52.2%, 95% CI [0.3302, 0.7077]), FPR 0/10 (0.0%)
- **Approvals per Benign Task**: 2 across 10 tasks (BENIGN-08: 1, BENIGN-10: 1; mean = 0.2 approvals / benign task).
- **Partitioned Performance (C4 vs C2 under `deny_all`, 23 valid attacks)**:
  - In-Scope (n=14): C2 ASR 2/14 (14.3%, 95% CI [0.0401, 0.3994]); C4 ASR 1/14 (7.1%, 95% CI [0.0127, 0.3147], 92.9% prevented).
  - Known-Gap (n=7): C2/C3/C4 ASR 6/7 (85.7%, 95% CI [0.4869, 0.9743]).
  - Out-of-Scope (n=2): C0–C4 ASR 2/2 (100.0%, 95% CI [0.3424, 1.0000]).
  - Excluded (n=1): ATTACK-22 excluded from denominators (status: `invalid`).

## Open Items (to close in order)
1. Chunk 5.9: Fix `pip-audit` to audit hashed lock file (verify flags with `--help`, remove `|| echo` and `continue-on-error`).
2. Raise remaining individual `mcpsec_core` module branch coverage to >= 90% (approvals 78%, detectors 78%, audit 88%, pinning 88%, matching 88%).
3. Evidence carry-overs: perf metrics without cache, concurrency integrity under multi-process contention.
4. Defenses remain unfrozen; no `v0.2-frozen` tag until items 1–3 are resolved.