# NOTES.md — Decisions, Ambiguities, Assumptions & Spec Notes

This document tracks assumptions, ambiguities, and design decisions encountered during development, per project requirements.

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
