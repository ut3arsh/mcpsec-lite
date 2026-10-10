# STATE.md — current project state (update at the end of every chunk; verified facts only)

**As of:** end of week 5, chunk 5.2.

## Built (verified)
- Weeks 1–4: pass-through proxy, JSONL audit log, policy engine (default deny, path/domain matching), multi-upstream aggregation, taint + flow rules (with `unless` exemption), approval queue + CLI, CI workflow, conformance matrix.
- Week 5 (chunk 5.2): tool-description pinning with "all model-visible fields except `_meta`" hashing, `hashed_fields` recorded in `pins.json`, generic agent-facing denials (`Denied by mcpsec policy`) with `ERR_*` codes restricted to audit logs, `tools/list_changed` re-fetching and downstream notification, atomic concurrency-safe approvers, serverInfo informational changes, and meta-test for protection completeness.

## Verified Numbers (chunk 5.2 run)
- **176 tests collected**: 170 passed, 4 skipped, 2 xfailed in 74.1s. `mypy --strict`: 0 issues in 59 files. `ruff`: clean.
- **`mcpsec_core/pinning.py` branch coverage**: **93%** (285 stmts, 86 branches; gate >= 90% passed).
- **Core module branch coverage**: policy 96%, models 96%, adapters 93%, flow 92%, matching 91%, audit 88%, approvals 81%, detectors 78%, pinning 93%.

## Open Items (to close in order)
1. [x Closed in 5.2] Pinning tested end-to-end: `tools/list_changed`, rug-pull audit vs strict, corrupt store fail-closed, concurrent approvers, first-use approval in strict, invisible/bidi diff flags.
2. [x Closed in 5.2] Pin hashing uses all model-visible fields except `_meta`; `hashed_fields` recorded in `pins.json`.
3. [x Closed in 5.2] Agent-facing denial text is generic; `ERR_UNPINNED_TOOL` / `ERR_TOOL_HASH_MISMATCH` in audit log only.
4. Raise remaining `mcpsec_core` module branch coverage to >= 90% (audit 88%, approvals 81%, detectors 78%).
5. Partition dev benchmark results: in-scope vs out-of-scope/known-gap attacks; diagnose and address benign FPR on C2/C4.
6. Align benchmark configs with `benchmark_spec.md` (or propose ADR + spec patch).
7. Resolve ADR-015 duplication (renumber caching removal ADR and update references).
8. Evidence carry-overs: perf metrics without cache, concurrency integrity, GitHub snapshot verification, CI run on Ubuntu + Windows.
9. Defenses remain unfrozen; no `v0.2-frozen` tag until items 4–8 are resolved.

## Decisions pending (owner)
- Review partitioned in-scope attack breakdown and benign FPR reduction candidates.
- Determine defense freeze timeline following item 4–8 resolution.