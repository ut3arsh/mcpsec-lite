# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.15.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.9: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock` with hashes and strict enforcement; dated ignore list).
- Chunk 5.10–5.13: cross-process `LockTimeout` with fault injection, audit log rotation and hash-chain tampering verification, event-driven approval wake, detector real-shape scanning, non-blocking lock offload, ReDoS scaling, exact coverage gate, skips/xfails CI evidence correction, 6 mutation checks, 85% per-module floor.
- Chunk 5.14: pre-registered 32 benign workflows (`manifest.json` committed before trials at `a889e89`); benchmark harness for C0–C4 + stress variant C2s across `deny_all` and `approve_all` (672 trials in `trials.csv`); automated `analysis.py` with Wilson 95% CIs.
- Chunk 5.15: 5.14 Task 0 evidence-backed report correction (`task0_imports.txt`, `task0_test_names.txt`); plain `pytest` optimized to 43.76s (< 60s target); owner-authored manifest v2 (BENIGN-33..44) committed before trials at `58edea2`; C1–C4 domain allowlists updated identically with 13 domains (omitted from `unless`); ATTACK-25..27 added (S2 untrusted content to egress with zero private reads); full 852-trial matrix run across C0–C4, C2s, and both approval modes; separate & combined analysis with contamination note (v1 100% in `unless` vs v2 0%), rule conflict matrix regenerated; byte-for-byte reproducibility tested in CI; defenses unchanged.

## Verified Numbers (chunk 5.15 local run)
- **Plain unit suite (`pytest`)**: 220 passed, 2 skipped, 8 deselected, 2 xfailed in 43.76s (< 60s).
- **Static checks**: `mypy --strict` clean (73 source files), `ruff check` clean, `ruff format` clean.
- **Benign evaluation (v2 alone, C2)**: Hard-block rate 6/12 (50.00% [25.38%, 74.62%]); approval-needed rate 5/12 (41.67% [19.33%, 68.05%]); approvals/task 0.42; completion rate 8.3% (`deny_all`) vs 50.0% (`approve_all`).
- **Benign evaluation (Combined, C2)**: Hard-block rate 9/44 (20.45% [11.15%, 34.50%]); approval-needed rate 11/44 (25.00% [14.57%, 39.44%]); approvals/task 0.25; completion rate 54.5% (`deny_all`) vs 79.5% (`approve_all`).
- **Attack ASR (C2)**: In-scope 1/17 (5.9% [1.1%, 27.0%]) under `deny_all` vs 4/17 (23.5% [9.6%, 47.3%]) under `approve_all`. In C4: In-scope 0/17 (0.0% [0.0%, 18.4%]) under `deny_all` vs 3/17 (17.6% [6.2%, 41.0%]) under `approve_all`.
- **Value of `deny-untrusted-egress`**: Proved measurable; stops ATTACK-25..27 at the flow layer (ASR drops from 82.4% in C1 to 5.9% in C2 deny_all).

## Open Items (to close in order)
1. Policy vs ergonomics tradeoff on `deny-untrusted-egress` for tools lacking URL domain arguments (`github.create_issue_comment`) and unexempted multi-step fetches.
2. Concurrency integrity under multi-process contention and real-server live integration tests.
3. Defenses remain unfrozen; no `v0.2-frozen` tag until items are resolved.