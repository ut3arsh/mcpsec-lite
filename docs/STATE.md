# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.16.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.13: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock`), cross-process locks, audit log rotation and hash-chain tampering verification, exact coverage gate, skips/xfails CI evidence correction, 6 mutation checks, 85% per-module floor.
- Chunk 5.14–5.15: pre-registered benign workflows (manifest v1 and v2); benchmark harness for C0–C4 + stress variant C2s across `deny_all` and `approve_all`; automated `analysis.py` with Wilson 95% CIs; proved measurable value of `deny-untrusted-egress` on ATTACK-25..27; byte-for-byte reproducibility tested in CI.
- Chunk 5.16: trusted egress criterion authored and committed before runs in `docs/trusted_destinations.md` (`71681f0`); `*.s3.amazonaws.com` allowlisted identically in C1-C4/C2s; owner-authored benign v3 (BENIGN-45..46) and in-scope attacks ATTACK-28..30 (with `realism: mechanism-only` on 25..26) committed before trials at `59b9602`; experiment configs E0 (C2 unchanged), E1 (untrusted egress approval), E2 (curated unless on both rules), E3 (hybrid E1+E2); full 912-trial matrix run across C1, E0..E3, C2s x both approval modes; byte-for-byte reproducibility tested; defenses in `mcpsec_core/` and `proxy/` strictly untouched.

## Verified Numbers (chunk 5.16 local run)
- **Plain unit suite (`pytest`)**: 221 passed, 2 skipped, 8 deselected, 2 xfailed in 35.31s (< 60s).
- **Static checks**: `mypy --strict` clean (73 source files), `ruff check` clean, `ruff format` clean.
- **Combined Benign Hard-Block Rate (n=46)**: C1 0.00% [0.00%, 7.71%]; E0 21.74% [12.26%, 35.57%]; E1 2.17% [0.38%, 11.34%]; E2 13.04% [6.12%, 25.67%]; E3 0.00% [0.00%, 7.71%]; C2s 23.91% [13.91%, 37.94%].
- **Combined Approve-All Completion Rate (n=46)**: C1 100.00%; E0 78.26%; E1 97.83%; E2 86.96%; E3 100.00%; C2s 76.09%.
- **In-Scope Attack ASR under `deny_all` (n=20)**: C1 85.00% (17/20); E0 5.00% (1/20); E1 5.00% (1/20); E2 5.00% (1/20); E3 5.00% (1/20); C2s 5.00% (1/20).
- **Approvals / Task (Combined Benign, n=46)**: C1 0.00; E0 0.26; E1 0.46; E2 0.35; E3 0.48; C2s 0.26.
- **Pre-Registered Selection Bars (a: HB<=5%, b: Comp>=90%, c: InScopeASR<=10%, d: Appr/Task<=1.0)**: E1 and E3 meet all 4 bars (4/4); C1 meets 3/4 (fails c); E0, E2, C2s meet 2/4 (fail a and b). Config selection deferred to owner.

## Open Items (to close in order)
1. Owner selection of preferred defense configuration (E0, E1, E2, or E3) based on Pareto tradeoff evidence.
2. Concurrency integrity under multi-process contention and real-server live integration tests.
3. Defenses remain unfrozen; held-out scenarios are not authored until the owner freezes and tags the defenses.
