# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.17b.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.13: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock`), cross-process locks, audit log rotation and hash-chain tampering verification, exact coverage gate, skips/xfails CI evidence correction, 6 mutation checks, 85% per-module floor.
- Chunk 5.14–5.17: pre-registered benign workflows (manifest v1..v3); automated `analysis.py` with Wilson 95% CIs and matrix completeness validation; ADR-018 (C5 adoption); flow-rule `unless.path_allowlist` with fail-closed normalization (NUL, UNC, devices, ADS, junction/symlink resolution).
- Chunk 5.17b: restored pre-registered C5 (`b558d65`) with audited taint sources; authored `E4b.yaml` (restored C5 + `unless.path_allowlist`) pre-registered in `ed6aa9a` before trials; executed C1, C5, E4b matrix across all sets and both modes (462 trials); data-driven byte-for-byte reproducibility test added; enhanced `scripts/check_coverage.py` and `.github/workflows/ci.yml` with fail-closed multi-OS coverage assertions ensuring both Windows and POSIX executions are present; corrected skip/xfail reporting discrepancies and explained approvals/pinning coverage deltas.

## Verified Numbers (chunk 5.17b run)
- **Plain unit suite (`pytest`)**: 247 passed, 2 skipped, 8 deselected, 2 xfailed in 40.48s (< 60s).
- **Full suite (`pytest -m "integration or not integration"`)**: 252 passed, 4 skipped, 2 xfailed in 61.36s.
- **Static checks**: `mypy --strict` clean (75 source files), `ruff check` clean, `ruff format` clean.
- **Combined Cross-Platform Coverage Gate (`mcpsec_core` from CI run 42266789877)**: Statements 97.01% (1816/1872), Branches 94.83% (715/754), Total 96.38% (2531/2626); `approvals.py` 235/241 (97.51%) stmts, 59/64 (92.19%) branches; `pinning.py` 317/331 (95.77%) stmts, 97/102 (95.10%) branches.
- **Benchmark Matrix (n=46 benign, n=30 valid attacks, 462 trials)**:
  - Benign Hard-Block Rate (`deny_all`): C1 0.00%, C5 0.00%, E4b 0.00% (all PASS $\le 5.0\%$).
  - Benign Completion Rate (`approve_all`): C1 100.00%, C5 100.00%, E4b 100.00% (all PASS $\ge 90.0\%$).
  - In-Scope ASR (`deny_all`): C1 85.00% (17/20), C5 5.00% (1/20), E4b 5.00% (1/20) (C5 and E4b PASS $\le 10.0\%$).
  - In-Scope ASR (`approve_all`): C1 85.00% (17/20), C5 45.00% (9/20), E4b 45.00% (9/20).
  - Approvals / Task (`approve_all`): C1 0.00, C5 0.59 (27/46), E4b 0.41 (19/46) (both PASS bar $\le 1.0$).
  - Bar (d) per benign set: V1: C5 0.28, E4b 0.28; V2: C5 1.25 (exceeds 1.0), E4b 0.75; V3: C5 1.50 (exceeds 1.0), E4b 0.50.
  - Unattended (`deny_all`) completion: Combined: C5 50.0% (23/46), E4b 63.0% (29/46); V1: 71.9% (23/32); V2: C5 0.0% (0/12), E4b 41.7% (5/12); V3: C5 0.0% (0/2), E4b 50.0% (1/2).

## Open Items (to close in order)
1. Owner decision between C5 and E4b based on empirical fatigue vs persistence tradeoff.
2. Defenses remain unfrozen; held-out scenarios are not authored until owner freezes and tags defenses.
