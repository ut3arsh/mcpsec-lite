# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.18b.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7–5.13: benchmark validation (C1 aligned with C2 allowlists; ATTACK-22 invalid; ATTACK-24 known-gap; approval modes `deny_all` vs `approve_all`), reproducible reporting tables, CI security gate (`pip-audit` on `requirements.lock`), cross-process locks, audit log rotation and hash-chain tampering verification, exact coverage gate, skips/xfails CI evidence correction, 6 mutation checks, 85% per-module floor.
- Chunk 5.14–5.17c: pre-registered benign workflows (v1..v4); automated `analysis.py` with Wilson 95% CIs and matrix completeness validation; ADR-018 (C5 adoption); flow-rule `unless.path_allowlist`; E4b / E5 ablations with file-origin untrusted taint and multi-session seeding.
- Chunk 5.18a: pre-registered ADR-019 (C6 default profile adoption, two-mode deployment model) and pre-registered `benchmark/configs/C6.yaml` committed in `273b22f`; executed benchmark matrix C0, C1, C2, C5, C6 (830 trials); verified byte-for-byte analysis report reproducibility.
- Chunk 5.18b: pre-freeze verification: verified C6 byte-for-byte integrity against commit `273b22f`; implemented `ConfigIntegrityError` in `benchmark/analysis.py` and SHA-256 recording in runner; hardened `cli/approve_cli.py` against ANSI ESC, Bidi overrides, NUL, and overlong payloads; captured real GitHub MCP server schema (26 tools) to `tests/fixtures/github.tools.real.json` and authored `docs/github_snapshot_diff.md`; full history secret scan across 128 commits triaged (0 real secrets) and wired into CI workflow; created `SECURITY.md` and synced `README.md`.

## Verified Numbers (chunk 5.18b run)
- **Plain unit suite (`pytest`)**: 253 passed, 2 skipped, 8 deselected, 2 xfailed in 52.11s (< 60s).
- **Static checks**: `mypy --strict` clean (77 source files), `ruff check` clean, `ruff format` clean (125 source files).
- **Benchmark Matrix (n=50 benign, n=32 valid attacks, 830 trials)**:
  - Benign Hard-Block Rate (`deny_all`): C0 0.00%, C1 0.00%, C2 20.00%, C5 0.00%, C6 0.00% (C6 PASS $\le 5.0\%$).
  - Benign Completion Rate (`approve_all`): C0 100.0%, C1 100.0%, C2 80.0%, C5 100.0%, C6 100.0% (C6 PASS $\ge 90.0\%$).
  - In-Scope ASR (`deny_all`): C0 100.0% (21/21), C1 85.7% (18/21), C2 9.5% (2/21), C5 9.5% (2/21), C6 0.0% (0/21) (C6 PASS $\le 10.0\%$).
  - In-Scope ASR (`approve_all`): C0 100.0% (21/21), C1 85.7% (18/21), C2 23.8% (5/21), C5 47.6% (10/21), C6 42.9% (9/21).
  - Approvals / Task (`approve_all`): C0 0.00, C1 0.00, C2 0.26, C5 0.56, C6 0.40 (C6 PASS $\le 1.0$).
  - Bar (d) per benign set for C6: v1: 0.28 (9/32), v2: 0.75 (9/12), v3: 0.50 (1/2), v4: 0.25 (1/4), Combined: 0.40 (20/50) (ALL $\le 1.0$).
  - Unattended (`deny_all`) completion for C6: Combined: 64.0% (32/50); v1: 71.9% (23/32); v2: 41.7% (5/12); v3: 50.0% (1/2); v4: 75.0% (3/4).
  - ATTACK-23 (mid-session tool description rug-pull): C0 PASS, C1 PASS, C2 PASS, C5 PASS, C6 BLOCKED/BLOCKED.
  - Total valid ASR under C6: `deny_all`: 10/32 (31.2%); `approve_all`: 20/32 (62.5%). Under `deny_all`, all 10 succeeding attacks are known-gap or out-of-scope; 0 in-scope attacks succeed.

## Open Items (to close in order)
1. Defenses frozen at C6 default profile (`benchmark/configs/C6.yaml`); held-out scenarios are not authored until owner freezes and tags defenses.
