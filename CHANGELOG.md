# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/). Versions follow [SemVer](https://semver.org/) once code is released.

Weekly progress notes live under **Weekly log** at the bottom. They feed the final write-up, so record hours and blockers honestly.

## [Unreleased]

### Added
- `DESIGN.md` v0: scope, threat model, architecture, taint/flow semantics, pinning, kill criteria.
- `docs/policy_schema.md` v1: YAML policy specification and validation rules.
- `docs/audit_log_schema.md` v1: JSONL audit log specification.
- `docs/benchmark_spec.md` v0: benchmark methodology, held-out rule, metrics, budget.
- `docs/decisions.md`: ADR-001 to ADR-011.
- `README.md`, `LICENSE` (Apache-2.0), `CHANGELOG.md`.

---

## Weekly log

Template (copy per week):

```
## Week N (YYYY-MM-DD to YYYY-MM-DD) — hours: __
- Done:
- Blocked:
- Decisions (link ADR):
- Next:
- Kill-criteria check (from week 5 on): flow-rule block rate __%, false positives __%
```

## Week 1 (2026-10-07 to 2026-10-14) — hours: 14
- Done:
  - Repository skeleton with `pyproject.toml` (pinned `mcp==2.3.0`, `pydantic>=2.0`, `pytest`, `ruff`, `mypy`).
  - `mcpsec_core/models.py`: typed models for Decision, SessionState, ToolCall, and all audit event types per schema v1.
  - `mcpsec_core/audit.py`: single-writer append-only JSONL logger with monotonic `seq`, RFC 3339 UTC ms timestamps, and `full`/`redacted`/`hash_only` redaction modes.
  - Stubbed pure lifecycle functions in `mcpsec_core` (`check_pinning`, `check_policy`, `check_flow`, `update_taint`).
  - `proxy/`: stdio MCP proxy mediating between agent client and upstream MCP server, forwarding `tools/list` and `tools/call`, recording `latency_ms.proxy` and `latency_ms.upstream`.
  - `cli/replay.py`: `mcpsec-replay` CLI with filtering by session, tool, decision, agent, layer, and timeline output.
  - Test suite (13 passing tests) and benchmark measuring proxy overhead: p50 = 0.041 ms, p95 = 0.072 ms (< 10 ms target).
  - `NOTES.md` documenting ambiguities, assumptions, measurements, and Week 2 risks.
- Blocked: none.
- Decisions: ADR-001 through ADR-011 reaffirmed; pure library separation for `mcpsec_core` validated.
- Next: Week 2 policy engine, YAML schema validation, per-agent allowlists, path normalization, domain matching, and default-deny enforcement.

## Week 0 (2026-09-30 to 2026-10-06) — hours: 12
- Done: design docs drafted (DESIGN, policy schema, audit schema, benchmark spec, ADRs).
- Blocked:
- Decisions: ADR-001 to ADR-011.
- Next: resolve DESIGN.md §13 open questions (capability taxonomy first); create the repo skeleton; freeze the policy schema for the proxy skeleton.