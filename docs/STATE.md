# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.5.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunks 5.2–5.5): tool-description pinning with "all model-visible fields except `_meta`" hashing, generic agent-facing denials (`Denied by mcpsec policy`), `tools/list_changed` re-fetching, multi-process/thread concurrency safety for PinStore and ApprovalManager, bi-directional audit enum contract test, pure `check_pinning` lifecycle function, programmatic meta-test verifying all 11 protections, CI `--cov-fail-under=90` scoped to `mcpsec_core`, and full dev-set attack partitioning (in-scope vs known-gap vs out-of-scope) with benign FPR root cause analysis (`dev_analysis_20261010.md`).

## Verified Numbers (chunk 5.5 run)
- **Full suite (`pytest -m "integration or not integration"`)**: 174 passed, 4 skipped, 2 xfailed in 37.20s.
- **Plain unit suite (`pytest`)**: 170 passed, 2 skipped, 6 deselected, 2 xfailed in 30.04s (gate < 60s passed).
- **Hypothesis CI Profile (`HYPOTHESIS_PROFILE=ci`, >=500 examples)**: 36 passed, 1 skipped in 17.84s.
- **Static checks**: `mypy --strict` clean (59 files), `ruff check` clean, `ruff format` clean.
- **CI Gate**: `--cov-fail-under=90` scoped to `mcpsec_core` (standard gate); `proxy`/`cli` coverage report-only.
- **`mcpsec_core` AGGREGATE branch coverage**: **90.5%** (1672 stmts, 666 branches, 2115/2338 elements).
- **Dev-Set Attack Partitioning (C4)**: In-Scope 0/14 ASR (0.0%, 95% CI [0.0000, 0.2153]); Known-Gap 6/6 ASR (100.0%); Out-of-Scope 2/2 ASR (100.0%). Benign FPR: 3/10 (1 policy glob boundary misconfig, 2 coarse session taint over-blocks).

## Open Items (to close in order)
1. [x Closed in 5.2] Pinning tested end-to-end: `tools/list_changed`, rug-pull audit vs strict, corrupt store fail-closed, concurrent approvers, first-use approval in strict, invisible/bidi diff flags.
2. [x Closed in 5.2] Pin hashing uses all model-visible fields except `_meta`; `hashed_fields` recorded in `pins.json`.
3. [x Closed in 5.2] Agent-facing denial text is generic; `ERR_UNPINNED_TOOL` / `ERR_TOOL_HASH_MISMATCH` in audit log only.
4. Raise remaining `mcpsec_core` module branch coverage to >= 90% (audit 88%, approvals 81%, detectors 78%, taint 59%).
5. [x Closed in 5.5] Partition dev benchmark results: in-scope (14/14 blocked in C4) vs out-of-scope (2) / known-gap (6); diagnosed benign FPR.
6. Align benchmark configs with `benchmark_spec.md` (or propose ADR + spec patch).
7. Resolve ADR-015 duplication (renumber caching removal ADR and update references).
8. Evidence carry-overs: perf metrics without cache, concurrency integrity, GitHub snapshot verification, CI run on Ubuntu + Windows.
9. Defenses remain unfrozen; no `v0.2-frozen` tag until items 4, 6–8 are resolved.

## Decisions pending (owner)
- Review partitioned in-scope attack breakdown and benign FPR reduction candidates.
- Determine defense freeze timeline following item 4, 6–8 resolution.