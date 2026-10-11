# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.6c.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning` function, programmatic meta-test verifying 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, immutable `manifest.json` (22 attacks), spec citation verification script, ADR-016 & ADR-017, GitHub Actions pinned to full SHAs on Node 24 majors (`checkout@v7.0.1`, `setup-python@v7.0.0`, `setup-node@v7.1.0`), POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision with grandchild cleanup), `load_policy` split into `load_policy_text` and `load_policy_file` with cross-type rejection, green CI matrix across 6 jobs (`ubuntu-24.04`, `windows-2022` × Python 3.11, 3.12, 3.13).

## Verified Numbers (chunk 5.6c run)
- **CI Matrix (run 38130890989)**: 6/6 jobs green (`success`).
  - Ubuntu 24.04 (Py 3.11, 3.12, 3.13): 183 passed, 4 skipped, 2 xfailed; `mcpsec_core` branch coverage = 90% (89.82%).
  - Windows 2022 (Py 3.11, 3.12, 3.13): 184 passed, 3 skipped, 2 xfailed; `mcpsec_core` branch coverage = 91% (91.30%).
- **Plain unit suite (`pytest`)**: 177 passed, 2 skipped, 8 deselected, 2 xfailed in 37.68s (gate < 60s passed).
- **Static checks**: `mypy --strict` clean (62 source files), `ruff check` clean, `ruff format` clean.
- **Node 20 deprecation**: Zero warnings or annotations on latest run (all 3 actions pinned to Node 24 runtime).
- **Dev-Set Attack Partitioning (C4)**:
  - In-Scope (n=13): 0/13 ASR (0.0%, 95% CI [0.0000, 0.2281], 100% prevented).
  - Known-Gap (n=7): 7/7 ASR (100.0%, 95% CI [0.6457, 1.0000]).
  - Out-of-Scope (n=2): 2/2 ASR (100.0%, 95% CI [0.3424, 1.0000]).
- **Benign Workflows (FPR)**:
  - C0: 0/10 (0.0%), C1: 0/10 (0.0%), C2: 2/10 (20.0%), C3: 2/10 (20.0%), C4: 2/10 (20.0%).

## Open Items (to close in order)
1. Raise remaining individual `mcpsec_core` module branch coverage to >= 90% (approvals 78%, detectors 78%, audit 88%, pinning 88%, matching 88%).
2. Evidence carry-overs: perf metrics without cache, concurrency integrity under multi-process contention.
3. Defenses remain unfrozen; no `v0.2-frozen` tag until items 1–2 are resolved.

## Decisions pending (owner)
- Review partitioned in-scope attack breakdown and benign FPR reduction candidates.
- Determine defense freeze timeline following items 1–2 resolution.