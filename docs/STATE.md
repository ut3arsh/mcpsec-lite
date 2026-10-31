# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.14.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.9: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock` with hashes and strict enforcement; dated ignore list).
- Chunk 5.10: cross-process `LockTimeout` with fault injection, audit log rotation and hash-chain tampering verification, event-driven approval wake, detector real-shape scanning.
- Chunk 5.11: cross-process approval wake with real CLI subprocess (latency < 150ms) and restart late-timeout rejection; non-blocking lock offload (`anyio.to_thread.run_sync`) with ticker task loop responsiveness (< 50ms delay under contention); proxy lock default <= 200ms vs CLI 5.0s; algorithmic ReDoS scaling test (4n vs n ratio < 8x, cap 500ms); CI per-job coverage and step summary artifact upload.
- Chunk 5.12: measured branch coverage diff for `proxy/session.py` (2291505: 78/114 = 68.42% covered, 36 missed vs HEAD: 110/118 = 93.22% covered, 8 missed); exact coverage gate configured (`precision = 2`, `relative_files = true`, `check_coverage.py` enforcing >= 90.00% stmts & branches); edge behavior suite `tests/test_coverage_completion.py`; Python 3.14 matrix expansion with verified `requirements.lock`; Node.js upgraded to active LTS v22; CI `coverage-gate` job green.
- Chunk 5.13: skips/xfails CI evidence correction and test count reconciliation; 6 mutation spot-checks passed; tool annotations hash-sensitivity assertion added; audit.py SHA-256 hash chain behavior suite (96.25% branches local); 85% per-module floor in `check_coverage.py`.
- Chunk 5.14: pre-registered 32 benign workflows (`manifest.json` committed before trials at `a889e89`); benchmark harness for C0–C4 + stress variant C2s across `deny_all` and `approve_all` (672 trials in `trials.csv`); automated `analysis.py` with Wilson 95% CIs, ASR across scopes, rule conflict matrix, pass bar reporting; byte-for-byte reproducibility tested in CI; defenses unchanged.

## Verified Numbers (chunk 5.14 local run)
- **Plain unit suite (`pytest`)**: 219 passed, 2 skipped, 8 deselected, 2 xfailed in 61.52s.
- **Static checks**: `mypy --strict` clean (73 source files), `ruff check` clean, `ruff format` clean.
- **Benign evaluation (C2)**: Hard-block rate 3/32 (9.38% [3.24%, 24.22%]), misses <= 5.0% pass bar due to `deny-untrusted-egress` on `github.create_issue_comment`; approval-needed rate 6/32 (18.75% [8.89%, 35.31%]); approvals/task 0.19; completion rate 71.88% (`deny_all`) vs 90.62% (`approve_all`).
- **Attack ASR (C4)**: In-scope 0.0% (`deny_all`) vs 21.4% (`approve_all`); Known-gap 100.0% (`deny_all`) vs 100.0% (`approve_all`); Out-of-scope 100.0%.

## Open Items (to close in order)
1. Policy vs ergonomics tradeoff on `deny-untrusted-egress` for tools lacking URL domain arguments (`github.create_issue_comment`).
2. Concurrency integrity under multi-process contention and real-server live integration tests.
3. Defenses remain unfrozen; no `v0.2-frozen` tag until items are resolved.