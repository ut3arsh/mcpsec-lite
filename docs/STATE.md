# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.13.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.9: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock` with hashes and strict enforcement; dated ignore list).
- Chunk 5.10: cross-process `LockTimeout` with fault injection, audit log rotation and hash-chain tampering verification, event-driven approval wake, detector real-shape scanning.
- Chunk 5.11: cross-process approval wake with real CLI subprocess (latency < 150ms) and restart late-timeout rejection; non-blocking lock offload (`anyio.to_thread.run_sync`) with ticker task loop responsiveness (< 50ms delay under contention); proxy lock default <= 200ms vs CLI 5.0s; algorithmic ReDoS scaling test (4n vs n ratio < 8x, cap 500ms); CI per-job coverage and step summary artifact upload.
- Chunk 5.12: measured branch coverage diff for `proxy/session.py` (2291505: 78/114 = 68.42% covered, 36 missed vs HEAD: 110/118 = 93.22% covered, 8 missed); exact coverage gate configured (`precision = 2`, `relative_files = true`, `check_coverage.py` enforcing >= 90.00% stmts & branches); edge behavior suite `tests/test_coverage_completion.py`; Python 3.14 matrix expansion with verified `requirements.lock`; Node.js upgraded to active LTS v22; CI `coverage-gate` job green.
- Chunk 5.13: skips/xfails CI evidence correction and test count reconciliation; 6 mutation spot-checks passed; tool annotations hash-sensitivity assertion added; audit.py HMAC myth dispelled (spec specifies SHA-256 hash chain only); audit.py behavior suite raising module branch coverage to 96.25% (Windows local) / >96% combined; 85% per-module floor enforced in `check_coverage.py`; `actions/download-artifact` pinned to v8.0.2 (Node 24 runtime, deprecation cleared); `allow-prereleases: true` removed.

## Verified Numbers (chunk 5.13 local run)
- **Plain unit suite (`pytest`)**: 218 passed, 2 skipped, 8 deselected, 2 xfailed in 51.85s (gate < 60s passed).
- **Full suite (`pytest -m "integration or not integration"`)**: 224 passed, 4 skipped, 0 deselected, 2 xfailed in 83.09s.
- **Static checks**: `mypy --strict` clean (73 source files), `ruff check` clean, `ruff format` clean.
- **Dependency audit (`pip-audit`)**: Clean (0 unignored vulnerabilities on `requirements.lock`).
- **mcpsec_core Module Coverage (Windows local)**: `audit.py` 99.55% stmts, 96.25% branches; `matching.py` 94.94% stmts, 96.51% branches; `policy.py` 95.03% stmts, 95.18% branches; `detectors.py` 98.18% stmts, 92.19% branches; `flow.py` 97.37% stmts, 90.00% branches; `taint.py` 100.00% stmts, 100.00% branches; overall 93.93% stmts, 92.62% branches (Windows alone).

## Open Items (to close in order)
1. Concurrency integrity under multi-process contention and real-server live integration tests.
2. Defenses remain unfrozen; no `v0.2-frozen` tag until items are resolved.