# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.17a.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.13: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock`), cross-process locks, audit log rotation and hash-chain tampering verification, exact coverage gate, skips/xfails CI evidence correction, 6 mutation checks, 85% per-module floor.
- Chunk 5.14–5.15: pre-registered benign workflows (manifest v1 and v2); benchmark harness for C0–C4 + stress variant C2s across `deny_all` and `approve_all`; automated `analysis.py` with Wilson 95% CIs; proved measurable value of `deny-untrusted-egress` on ATTACK-25..27; byte-for-byte reproducibility tested in CI.
- Chunk 5.16: trusted egress criterion authored and committed before runs in `docs/trusted_destinations.md` (`71681f0`); `*.s3.amazonaws.com` allowlisted identically in C1-C4/C2s; owner-authored benign v3 (BENIGN-45..46) and in-scope attacks ATTACK-28..30 committed before trials; experiment configs E0..E3, C2s evaluated across 912 trials; defenses in `mcpsec_core/` and `proxy/` strictly untouched.
- Chunk 5.17a: audited tool fixtures in `docs/taint_sources_audit.md` and authored `benchmark/configs/C5.yaml` committed before trials (`b558d65`); refactored `benchmark/analysis.py` into a data-driven generator with matrix completeness validation (`TrialCompletenessError`) and zero typed numbers in prose; archived legacy generators in `benchmark/analysis_legacy.py`; recomputed approvals/task metric from `approve_all` trials and partitioned by acquired taint; ran E3 vs C5 benchmark matrix (304 trials) isolating deltas to `BENIGN-42` (exercises audited `github.list_issues` taint source); defenses in `mcpsec_core/` and `proxy/` strictly untouched.

## Verified Numbers (chunk 5.17a local run)
- **Plain unit suite (`pytest`)**: 225 passed, 2 skipped, 8 deselected, 2 xfailed in 33.28s (< 60s).
- **Static checks**: `mypy --strict` clean (74 source files), `ruff check` clean, `ruff format` clean.
- **Combined Benign Approvals / Task (`approve_all`, n=46)**: C1 0.00; E0 0.26; E1 0.59 (27/46); E2 0.35; E3 0.54 (25/46); C2s 0.26; C5 0.59 (27/46).
- **E3 vs C5 Comparative Evaluation (n=46 benign, n=20 in-scope attacks, 304 trials)**:
  - Hard-Block Rate (benign): E3 0.00% [0.00%, 7.71%]; C5 0.00% [0.00%, 7.71%].
  - Approve-All Completion Rate: E3 100.00% [92.29%, 100.00%]; C5 100.00% [92.29%, 100.00%].
  - In-Scope Attack ASR under `deny_all`: E3 5.00% (1/20); C5 5.00% (1/20).
  - Approvals / Task (`approve_all`): E3 0.54 (25/46); C5 0.59 (27/46).
  - Pre-Registered Selection Bars: both E3 and C5 meet all 4 bars (4/4 ALL PASS).
  - Delta isolation: 75/76 scenarios identical; single delta is `BENIGN-42` (exercises `github.list_issues` audited taint source, requesting 2 approvals in C5).

## Open Items (to close in order)
1. Owner selection of preferred defense configuration based on Pareto tradeoff and taint-source audit evidence.
2. Concurrency integrity under multi-process contention and real-server live integration tests.
3. Defenses remain unfrozen; held-out scenarios are not authored until the owner freezes and tags the defenses.
