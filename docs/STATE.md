# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.12.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.9: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock` with hashes and strict enforcement; dated ignore list).
- Chunk 5.10: cross-process `LockTimeout` with fault injection, audit log rotation and hash-chain tampering verification, event-driven approval wake, detector real-shape scanning.
- Chunk 5.11: cross-process approval wake with real CLI subprocess (latency < 150ms) and restart late-timeout rejection; non-blocking lock offload (`anyio.to_thread.run_sync`) with ticker task loop responsiveness (< 50ms delay under contention); proxy lock default <= 200ms vs CLI 5.0s; algorithmic ReDoS scaling test (4n vs n ratio < 8x, cap 500ms); CI per-job coverage and step summary artifact upload.
- Chunk 5.12: measured branch coverage diff for `proxy/session.py` (2291505: 78/114 = 68.42% covered, 36 missed vs HEAD: 110/118 = 93.22% covered, 8 missed); exact coverage gate configured (`precision = 2`, `relative_files = true`, `check_coverage.py` enforcing >= 90.00% stmts & branches); edge behavior suite `tests/test_coverage_completion.py` raising core branches to 91.25% locally / > 92% combined; Python 3.14 matrix expansion with verified `requirements.lock`; Node.js upgraded to active LTS v22.

## Verified Numbers (chunk 5.12 local run)
- **Plain unit suite (`pytest`)**: 217 passed, 2 skipped, 8 deselected, 2 xfailed in 57.73s (gate < 60s passed).
- **Full suite (`pytest -m "integration or not integration"`)**: 217 passed, 4 skipped, 0 deselected, 2 xfailed in 77.29s.
- **Static checks**: `mypy --strict` clean (69 source files), `ruff check` clean, `ruff format` clean.
- **Dependency audit (`pip-audit`)**: Clean (0 unignored vulnerabilities on `requirements.lock`).
- **Proxy Session Coverage (`proxy/session.py`)**: 93.22% branch (110/118), 99.30% statement (283/285).
- **mcpsec_core Module Coverage (Windows local)**: Statements 93.31% (1689/1810), Branches 91.25% (657/720).
- **Benchmark Summary Across Configurations (23 Valid Attacks, 10 Benign Tasks)**:
  - C0: ASR 23/23 (100.0%, 95% CI [0.8540, 1.0000]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C1: ASR 20/23 (87.0%, 95% CI [0.6786, 0.9546]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C2 (`deny_all`): ASR 10/23 (43.5%, 95% CI [0.2560, 0.6338]), FPR 2/10 (20.0%, 95% CI [0.0567, 0.5098])
  - C2 (`approve_all`): ASR 13/23 (56.5%, 95% CI [0.3662, 0.7440]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C3 (`deny_all`): ASR 10/23 (43.5%), FPR 2/10 (20.0%)
  - C4 (`deny_all`): ASR 9/23 (39.1%, 95% CI [0.2220, 0.5922]), FPR 2/10 (20.0%)
  - C4 (`approve_all`): ASR 12/23 (52.2%, 95% CI [0.3302, 0.7077]), FPR 0/10 (0.0%)

## Open Items (to close in order)
1. Concurrency integrity under multi-process contention and real-server live integration tests.
2. Defenses remain unfrozen; no `v0.2-frozen` tag until items are resolved.