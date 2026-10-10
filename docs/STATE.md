# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.6.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.6): tool-description pinning with "all model-visible fields except `_meta`" hashing, generic agent-facing denials (`Denied by mcpsec policy`), `tools/list_changed` re-fetching, multi-process/thread concurrency safety, pure `check_pinning` lifecycle function, programmatic meta-test verifying 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, immutable `benchmark/attacks/dev/manifest.json` (22 attacks, SHA256 hashed), ATTACK-19 reclassified to KNOWN-GAP (per `benchmark_spec.md` §3.2), spec citation verification script, ADR-016 (pinning) & ADR-017 (cache removal), glob directory root semantics note (`policy_schema.md` §3.1), and dev benchmark C0–C4 execution.

## Verified Numbers (chunk 5.6 run)
- **Plain unit suite (`pytest`)**: 171 passed, 2 skipped, 6 deselected, 2 xfailed in 38.61s (gate < 60s passed).
- **Static checks**: `mypy --strict` clean (60 source files), `ruff check` clean, `ruff format` clean.
- **Dev-Set Attack Partitioning (C4)**:
  - In-Scope (n=13): 0/13 ASR (0.0%, 95% CI [0.0000, 0.2281], 100% prevented).
  - Known-Gap (n=7): 7/7 ASR (100.0%, 95% CI [0.6457, 1.0000]).
  - Out-of-Scope (n=2): 2/2 ASR (100.0%, 95% CI [0.3424, 1.0000]).
- **Benign Workflows (FPR)**:
  - C0: 0/10 (0.0%).
  - C1: 0/10 (0.0%) [BENIGN-01 fixed via sandbox root allowlist].
  - C2: 2/10 (20.0%) [BENIGN-08, BENIGN-10 legitimate over-blocks from coarse session taint].
  - C3: 2/10 (20.0%) [Identical decisions to C2, ADR-003].
  - C4: 2/10 (20.0%).

## Open Items (to close in order)
1. Raise remaining `mcpsec_core` module branch coverage to >= 90% (audit 88%, approvals 81%, detectors 78%, taint 59%).
2. Evidence carry-overs: perf metrics without cache, concurrency integrity, GitHub snapshot verification, CI run on Ubuntu + Windows.
3. Defenses remain unfrozen; no `v0.2-frozen` tag until items 1–2 are resolved.

## Decisions pending (owner)
- Review partitioned in-scope attack breakdown and benign FPR reduction candidates.
- Determine defense freeze timeline following items 1–2 resolution.