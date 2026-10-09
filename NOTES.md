# NOTES.md — Decisions, Ambiguities, Assumptions & Spec Notes

This document tracks assumptions, ambiguities, design decisions, and measurements encountered during development, per project requirements.

## Week 1: Proxy Skeleton & Audit Logging

### Ambiguities & Assumptions
1. **Upstream MCP Server in `proxy.yaml`**:
   - *Assumption*: `proxy.yaml` specifies upstream configuration with `name`, `command`, `args`, and optional `env` / `cwd`, alongside `redaction` settings (`log_args: full | redacted | hash_only`).
   - *Detail*: This allows launching any stdio MCP server (such as filesystem or custom test servers) transparently.

2. **`session_id` Assignment**:
   - *Assumption*: Assigned as UUIDv4 at the start of an agent connection and carried across all events for that session.

3. **`latency_ms` Breakdown**:
   - *Assumption*: `latency_ms.upstream` measures the round-trip time spent calling the upstream MCP server. `latency_ms.proxy` measures the remaining time spent in proxy preprocessing (pinning/policy/flow checks) and postprocessing (taint updates, audit formatting).

4. **Redaction Modes (`full`, `redacted`, `hash_only`)**:
   - *Assumption*:
     - `full`: logs arguments unchanged.
     - `redacted` (default): walks string and dictionary values in arguments, redacting fields named in `never_log_fields` (e.g. `password`, `token`, `authorization`) or regex-matching patterns (e.g., AWS/GitHub tokens) to `"[REDACTED]"`.
     - `hash_only`: produces `{"sha256": "<hex>"}` computed over canonical JSON (`json.dumps(args, sort_keys=True, separators=(',', ':'))`).

5. **`response_summary`**:
   - *Assumption*: The response content is never logged verbatim. `response_summary` records `{"status": "ok" | "error", "bytes": int}` where `bytes` is the UTF-8 byte length of all returned content items.

6. **MCP SDK Integration (v2.3.0)**:
   - Used official `mcp` Python SDK (`mcp.server.lowlevel.Server`, `mcp.client.session.ClientSession`, `mcp.server.stdio.stdio_server`, `mcp.client.stdio.stdio_client`).
   - `mcpsec_core` remains pure and has zero dependencies on `mcp` SDK or transports.

### Measured Proxy Latency Overhead
Run via `python benchmark/measure_overhead.py` over 100 tool calls:
- **Proxy Overhead (p50):** 0.041 ms
- **Proxy Overhead (p95):** 0.072 ms
- **Proxy Overhead (mean):** 0.046 ms
- **Proxy Overhead (max):** 0.191 ms
- **Target (< 10 ms):** PASSED (sub-millisecond overhead, ~0.04-0.07 ms)

### Top 3 Risks for Week 2 (Policy Engine & Allowlists)
1. **Path Normalization & Symlink Resolution across OSes**:
   - Glob matching (`**`, `*`) against paths must safely normalize symlinks, relative segments (`..`), and home paths (`~`) without bypasses on Windows vs POSIX paths.
2. **Strict Default-Deny & Tool-to-Argument Mapping**:
   - Validation rules in `policy_schema.md` require fail-closed behavior when tool arguments do not match expected schemas or when unknown capabilities are encountered.
3. **Domain Matching & URL Parsing**:
   - Correctly handling apex domains vs subdomains (`*.github.com` vs `github.com`), non-standard URL schemes, and redirect blind spots without introducing false positives in benign runs.
