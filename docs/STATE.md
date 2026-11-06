# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.17.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.13: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock`), cross-process locks, audit log rotation and hash-chain tampering verification, exact coverage gate, skips/xfails CI evidence correction, 6 mutation checks, 85% per-module floor.
- Chunk 5.14–5.16: pre-registered benign workflows (manifest v1..v3); benchmark harness for C0–C4, C2s, E0–E3; automated `analysis.py` with Wilson 95% CIs and matrix completeness validation; byte-for-byte reproducibility tested in CI.
- Chunk 5.17: ADR-018 adopting E3 as C5; defined attended vs unattended modes; implemented flow-rule path allowlist exemptions (`unless.path_allowlist`) in `mcpsec_core` with fail-closed normalization (NUL, UNC, device namespaces, ADS, realpath/junction resolution without caching); validation error codes (`ERR_INVALID_UNLESS_PATH`, `ERR_UNLESS_PATH_NON_WRITE`, `ERR_INVALID_PATH_PATTERN`, `ERR_INVALID_UNLESS`); truth table, Hypothesis monotonicity & idempotency tests, and 3 mutation spot-checks passed; pre-registered E4, scratch criterion, and ATTACK-31 committed before runs (`397af2f`); ran C1, C5, E4 matrix across all sets and both modes (456 trials).

## Verified Numbers (chunk 5.17 local run)
- **Plain unit suite (`pytest`)**: 246 passed, 2 skipped, 8 deselected, 2 xfailed in 44.93s (< 60s).
- **Static checks**: `mypy --strict` clean (75 source files), `ruff check` clean, `ruff format` clean.
- **Coverage (`mcpsec_core`)**: Statements 94.07% (1761/1872), Branches 92.72% (701/756) (both $\ge 90.00\%$).
- **Benchmark Matrix (n=46 benign, n=30 valid attacks, 456 trials)**:
  - Benign Hard-Block Rate (`deny_all`): C1 0.00%, C5 0.00%, E4 0.00% (all PASS bar $\le 5.0\%$).
  - Benign Completion Rate (`approve_all`): C1 100.00%, C5 100.00%, E4 100.00% (all PASS bar $\ge 90.0\%$).
  - In-Scope ASR (`deny_all`): C1 85.00% (17/20), C5 5.00% (1/20), E4 5.00% (1/20) (C5 and E4 PASS bar $\le 10.0\%$).
  - In-Scope ASR (`approve_all`): C1 85.00% (17/20), C5 45.00% (9/20), E4 45.00% (9/20) (report only).
  - Approvals / Task (`approve_all`): C1 0.00, C5 0.54 (25/46), E4 0.37 (17/46) (both PASS bar $\le 1.0$).
  - Tradeoff: E4 reduces approvals/task from 0.54 to 0.37 and increases unattended completion from 52.2% to 65.2%, at the cost of cross-session persistence (ATTACK-31 succeeds under `deny_all` in E4; blocked in C5).

## Open Items (to close in order)
1. Owner decision between C5 and E4 based on empirical fatigue vs persistence tradeoff.
2. Defenses remain unfrozen; held-out scenarios are not authored until owner freezes and tags defenses.
