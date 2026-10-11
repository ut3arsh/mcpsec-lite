# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.7.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7: pinned `setup-node` to v7.0.0 SHA `820762786026740c76f36085b0efc47a31fe5020` (>= 14 days old, Node 24 runtime; v7.1.0 was published 2026-10-08, only 3 days old). Appended `ATTACK-23` (pure tool mutation rug-pull) to `manifest.json` (23 total scenarios: 14 in-scope, 7 known-gap, 2 out-of-scope). Dev harness outputs raw per-trial CSV to `benchmark/results/dev_20261011/trials.csv` (165 trials). `benchmark/analysis.py` generates all tables directly from `trials.csv` + `manifest.json` with zero hand-edited numbers. Byte-for-byte reproducibility tested and green.

## Verified Numbers (chunk 5.7 run)
- **CI Matrix (run 38139373561)**: 6/6 jobs green (`success`) on commit `1f778a0`.
- **Plain unit suite (`pytest`)**: 179 passed, 2 skipped, 8 deselected, 2 xfailed in 38.80s (gate < 60s passed).
- **Static checks**: `mypy --strict` clean (64 source files), `ruff check` clean, `ruff format` clean.
- **Byte-for-byte reproducibility**: `tests/test_benchmark_analysis.py` passes byte-for-byte check on regenerated report.
- **Local `pip-audit --strict`**: Exited with code 1 (`mcpsec-lite 0.1.0` unreleased local package not on PyPI).
- **Summary Matrix across configurations (23 attacks, 10 benign)**:
  - C0: ASR 23/23 (100.0%), FPR 0/10 (0.0%)
  - C1: ASR 23/23 (100.0%), FPR 0/10 (0.0%)
  - C2: ASR 10/23 (43.5%), FPR 2/10 (20.0%)
  - C3: ASR 10/23 (43.5%), FPR 2/10 (20.0%)
  - C4: ASR 9/23 (39.1%), FPR 2/10 (20.0%)
- **Partitioned Performance (C4 vs C2)**:
  - In-Scope (n=14): C2 ASR 2/14 (14.3%, 95% CI [0.0401, 0.3994]); C4 ASR 1/14 (7.1%, 95% CI [0.0127, 0.3147], 92.9% prevented). ATTACK-23 blocked in C4 by pinning.
  - Known-Gap (n=7): C2/C3/C4 ASR 6/7 (85.7%, 95% CI [0.4869, 0.9743]). ATTACK-19 blocked by `deny-private-egress`.
  - Out-of-Scope (n=2): C0–C4 ASR 2/2 (100.0%, 95% CI [0.3424, 1.0000]).
  - Benign (n=10): C2/C3/C4 FPR 2/10 (20.0%, 95% CI [0.0567, 0.5098], 80.0% allowed). BENIGN-08 and BENIGN-10 held by `appr-untrusted-write`.

## Open Items (to close in order)
1. Owner decision in Chunk 5.8 on local `pip-audit` package handling.
2. Raise remaining individual `mcpsec_core` module branch coverage to >= 90% (approvals 78%, detectors 78%, audit 88%, pinning 88%, matching 88%).
3. Evidence carry-overs: perf metrics without cache, concurrency integrity under multi-process contention.
4. Defenses remain unfrozen; no `v0.2-frozen` tag until items 1–3 are resolved.

## Decisions pending (owner)
- Decide fix in 5.8 for unreleased local package in `pip-audit --strict`.
- Determine defense freeze timeline following items 1–3 resolution.