# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.11.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.9: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock` with hashes and strict enforcement; dated ignore list).
- Chunk 5.10: cross-process `LockTimeout` with fault injection, audit log rotation and hash-chain tampering verification, event-driven approval wake, detector real-shape scanning.
- Chunk 5.11: cross-process approval wake with real CLI subprocess (latency < 150ms) and restart late-timeout rejection; non-blocking lock offload (`anyio.to_thread.run_sync`) with ticker task loop responsiveness (< 50ms delay under contention); proxy lock default <= 200ms vs CLI 5.0s; algorithmic ReDoS scaling test (4n vs n ratio < 8x, cap 500ms); `proxy/session.py` branch coverage elevated to 92.50% (111/120) / 99.30% statement (282/284); CI per-job coverage and step summary artifact upload.

## Verified Numbers (chunk 5.11 run)
- **CI Matrix**: Green across matrix (`ubuntu-24.04`, `windows-2022` on Python 3.11, 3.12, 3.13) with no masked failures.
- **Plain unit suite (`pytest`)**: 211 passed, 2 skipped, 8 deselected, 2 xfailed in ~48s (gate < 60s passed).
- **Static checks**: `mypy --strict` clean (68 source files), `ruff check` clean, `ruff format` clean.
- **Dependency audit (`pip-audit`)**: Clean (0 unignored vulnerabilities on `requirements.lock`).
- **Proxy Session Coverage (`proxy/session.py`)**: 99.30% statement (282/284), 92.50% branch (111/120).
- **mcpsec_core Module Coverage (Windows local)**: `audit.py` 92% (84.15% branch), `detectors.py` 96% (92.19% branch), `matching.py` 91% (90.70% branch), `flow.py` 92%, `models.py` 96%, `policy.py` 95%, `taint.py` 100%, `approvals.py` 84% (87.93% branch), `pinning.py` 88% (95.10% branch).
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