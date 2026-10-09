# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/). Versions follow [SemVer](https://semver.org/) once code is released.

Weekly progress notes live under **Weekly log** at the bottom. They feed the final write-up, so record hours and blockers honestly.

## [Unreleased]

### Added
- `mcpsec_core/policy.py`: Frozen Pydantic models for Policy (`extra="forbid"`, `frozen=True`), loading with `yaml.safe_load`, computing `policy_hash` (SHA-256), and enforcing all 9 validation rules with unique error codes.
- `mcpsec_core/adapters.py`: Registry for tool argument extraction with built-in adapters for filesystem (`read_file`, `write_file`, `list_directory`, etc.) and fetch tools, enforcing fail-closed checks on suspicious argument keys.
- `mcpsec_core/matching.py`: Cross-platform path matching (Unicode NFC normalization, symlink resolution, parent resolution for write targets, Win32 device namespace / ADS / DOS reserved name rejection) and strict domain matching (userinfo rejection, punycode IDN, exact subdomain wildcard matching).
- `cli/policy_cli.py`: `mcpsec-policy` CLI command (`validate` and `--explain`).
- `cli/replay.py`: Constant-memory streaming reader and atomic sidecar index (`audit.jsonl.idx`) for high-throughput replay.
- `tests/test_real_server.py`: Integration test running proxy over stdio against real `@modelcontextprotocol/server-filesystem` via `npx`.
- `tests/test_matching.py`: Property-based testing with `hypothesis` (500+ examples) and traversal/bypass corpus suite.
- `demo_week2.py`: End-to-end demonstration script showing allowlist passes, path traversal block, symlink block, unlisted tool block, and audit logs.
- `docs/decisions.md`: ADR-012, ADR-013, ADR-014.

### Changed
- `proxy/session.py`: Wired real `check_policy` enforcement, returning generic `"Denied by mcpsec policy"` to agents while writing full forensic context to audit logs, and failing closed on injected faults.
- `proxy/main.py`: Upstream process environment isolation via `sanitize_upstream_env`.
- `mcpsec_core/models.py`: Added `UNCHECKED = "unchecked"` to `PinStatus` enum and defaulted `pin_status` to `"unchecked"` while pinning is stubbed.
- `docs/audit_log_schema.md`: Documented `pin_status: "unchecked"` and default `decision_reason: "pass-through (no policy)"`.

### Removed
- Deleted duplicate root `DECISIONS.md`; consolidated in `docs/decisions.md`.

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

## Week 2 (2026-10-10) — hours: 16
- Done:
  - Week 1 fixes: Added `pin_status: "unchecked"`, fixed `decision_reason` to `"pass-through (no policy)"` when unconfigured, removed duplicate `DECISIONS.md`.
  - Added real-server integration test against `@modelcontextprotocol/server-filesystem` via `npx` over stdio.
  - Implemented immutable `Policy` loader with full 9-rule validation, error paths, and O(1) compiled lookup tables.
  - Implemented argument adapter registry with built-in adapters and fail-closed checks on unmapped path/domain arguments.
  - Implemented Unicode NFC path normalization, symlink resolution, parent resolution for write targets, and Windows security filters (rejection of UNC, device paths, ADS, DOS reserved names).
  - Implemented strict URL and domain parsing (rejection of userinfo, schemes, empty hosts, raw IPs; exact subdomain wildcard matching).
  - Property testing with Hypothesis (500+ examples) and comprehensive traversal/bypass corpus tests.
  - Wired policy enforcement in `proxy/session.py`, returning generic error message `"Denied by mcpsec policy"` to agent while logging complete forensics in audit log.
  - Upstream child process environment isolation (`sanitize_upstream_env`).
  - Added `mcpsec-policy validate` and `--explain` CLI.
  - Updated `mcpsec-replay` to stream audit logs with constant memory and build incremental atomic sidecar index (`audit.jsonl.idx`).
  - Created `demo_week2.py` demonstrating allowlisted reads, path traversal block, symlink block, unlisted tool block, and audit logging.
- Blocked: none.
- Decisions: ADR-012 (O(1) compiled policy lookup), ADR-013 (fail-closed generic error responses), ADR-014 (canonical path resolution with cross-platform filtering).
- Next: Week 3 - Taint tracking, flow control rules, approval CLI groundwork, and GitHub MCP server integration.

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