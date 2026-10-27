# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.10.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6c): tool-description pinning, generic agent-facing denials, `tools/list_changed` re-fetching, pure `check_pinning`, meta-test on 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, POSIX process tree hygiene (`/proc` descendant-walk kill, child PID tracking, crash-restart supervision), GitHub Actions pinned to Node 24 majors.
- Chunk 5.7: pinned `setup-node` to v7.0.0 SHA `820762786026740c76f36085b0efc47a31fe5020`. Appended `ATTACK-23` (tool mutation rug-pull). Raw per-trial records in `trials.csv`. `benchmark/analysis.py` generates all tables with byte-for-byte reproducibility tested.
- Chunk 5.8: Validated dev benchmark. Aligned C1 policy to match C2 allowlists; C1 blocks off-allowlist sinks (ATTACK-05, ATTACK-08, ATTACK-12). Added per-scenario `success_predicate` to manifest. ATTACK-22 marked `invalid` and excluded from denominators. ATTACK-19 reclassified `in-scope`; ATTACK-24 added as `known-gap`. Added harness approval modes (`deny_all` vs. `approve_all`) with 340 raw trials recorded. Fixed report prose.
- Chunk 5.9: Hardened CI security gate. `pip-audit` audits hashed lockfile (`requirements.lock`, `--require-hashes --strict`); dated, justified ignores enforced via `audit-ignores.txt`. CI writes skip list, branch coverage, and pip-audit result to `$GITHUB_STEP_SUMMARY`. Moved `scripts/gh_cmd.py`. Reconciled C1 attribution (11/14 in-scope, 7/7 known-gap, 2/2 out-of-scope; 20/23 total).
- Chunk 5.10: Integrity and fail-closed locks. Cross-process `LockTimeout` (5.0s default) for `PinStore` and `ApprovalManager` with fault injection proving zero writes under contention. Audit integrity verified: size-triggered rotation (seq restart, `prev_hash` continuity), chain resume after restart, failure matrix on tampered chains (edited, deleted, inserted, reordered, truncated, broken rotation continuity), fsync-in-strict mode. Approvals: event-driven held-call wake on approve, deny, timeout (< 50ms latency); atomic single-outcome race resolution; multi-session hold isolation. Detectors: real MCP content shapes (TextContent, ImageContent, EmbeddedResource, structured dicts, oversized with `scan_truncated`), high-entropy base64/hex secret detection, zero raw data logged privacy invariant, and linear-time ReDoS timing benchmark.

## Verified Numbers (chunk 5.10 run)
- **CI Matrix**: Green across matrix (`ubuntu-24.04`, `windows-2022` on Python 3.11, 3.12, 3.13) with no masked failures.
- **Plain unit suite (`pytest`)**: 197 passed, 2 skipped, 8 deselected, 2 xfailed in ~39s (gate < 60s passed).
- **Static checks**: `mypy --strict` clean (70 source files including `tests/test_locks.py`, `tests/test_audit_integrity.py`, `tests/test_approvals_integration.py`, `tests/test_detectors_mcp.py`), `ruff check` clean, `ruff format` clean.
- **Dependency audit (`pip-audit`)**: Clean (0 unignored vulnerabilities on `requirements.lock`).
- **mcpsec_core Module Coverage (Windows local)**: `audit.py` 92% (84.15% branch), `detectors.py` 96% (92.19% branch), `matching.py` 91% (90.70% branch), `flow.py` 92%, `models.py` 96%, `policy.py` 95%, `taint.py` 100%. `approvals.py` 84% (87.93% branch), `pinning.py` 88% (95.10% branch) — remaining misses on Windows are POSIX `fcntl` locking branches tested on Ubuntu.
- **Summary Matrix Across Configurations (23 Valid Attacks, 10 Benign Tasks)**:
  - C0: ASR 23/23 (100.0%, 95% CI [0.8540, 1.0000]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C1: ASR 20/23 (87.0%, 95% CI [0.6786, 0.9546]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C2 (`deny_all`): ASR 10/23 (43.5%, 95% CI [0.2560, 0.6338]), FPR 2/10 (20.0%, 95% CI [0.0567, 0.5098])
  - C2 (`approve_all`): ASR 13/23 (56.5%, 95% CI [0.3662, 0.7440]), FPR 0/10 (0.0%, 95% CI [0.0000, 0.2831])
  - C3 (`deny_all`): ASR 10/23 (43.5%), FPR 2/10 (20.0%)
  - C4 (`deny_all`): ASR 9/23 (39.1%, 95% CI [0.2220, 0.5922]), FPR 2/10 (20.0%)
  - C4 (`approve_all`): ASR 12/23 (52.2%, 95% CI [0.3302, 0.7077]), FPR 0/10 (0.0%)
- **C1 Per-Class Breakdown**: In-Scope 11/14 (78.6%), Known-Gap 7/7 (100.0%), Out-of-Scope 2/2 (100.0%).

## Open Items (to close in order)
1. Evidence carry-overs: perf metrics without cache, concurrency integrity under multi-process contention.
2. Defenses remain unfrozen; no `v0.2-frozen` tag until items are resolved.