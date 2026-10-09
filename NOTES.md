# NOTES.md — Decisions, Ambiguities, Assumptions & Spec Notes

This document tracks assumptions, ambiguities, design decisions, spec patches, and measurements encountered during development, per project requirements.

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

---

## Week 2: Policy Engine & Default-Deny Enforcement

### Week 2 Decisions & Applied Spec Patches

1. **[x Applied] Unicode NFC Normalization & URL Encoding in Path Matching**:
   - *Decision*: Paths are normalized using Unicode NFC before comparison. Paths containing NUL bytes, over-length strings (>4096 chars), or non-string values are rejected. Path strings are **not** URL-decoded (prevents double-decoding and evasion attacks).
   - *Applied Spec Patch (`docs/policy_schema.md` §3.1)*:
     ```markdown
     Path arguments MUST undergo Unicode NFC normalization before canonicalization.
     Implementations MUST NOT URL-decode file path arguments before evaluating allowlists.
     ```

2. **[x Applied] Strict Domain & URL Parsing (Userinfo, Schemes, Wildcard Scoping)**:
   - *Decision*: URLs and domains are strictly parsed. Reject userinfo (`https://user:pass@evil.com/` or `https://github.com@evil.com/`), reject non-HTTP/HTTPS schemes, reject empty hosts, and reject raw IP literals unless explicitly allowlisted. `*.example.com` matches only subdomains (e.g., `api.example.com`), never the apex domain (`example.com`) or look-alikes (`evil-example.com`, `example.com.attacker.com`). Single trailing dots are stripped before matching.
   - *Applied Spec Patch (`docs/policy_schema.md` §3.1)*:
     ```markdown
     Domain matching MUST reject userinfo components in URLs, reject non-HTTP(S) schemes,
     and wildcard '*.domain' MUST match only true subdomains of domain, not the apex or
     suffix-colliding domains.
     ```

3. **[x Applied] Strict Argument Schemas (Replacing Heuristic Denial)**:
   - *Decision*: Rather than guessing parameter names, tool adapters declare the complete set of valid argument names (`all_args`). When evaluating tool calls for constrained tools, any argument key not declared in the tool adapter's schema is denied immediately (`ERR_UNEXPECTED_ARGUMENT`).
   - *Applied Spec Patch (`docs/policy_schema.md` §3.1 & §10 Rule 8)*:
     ```markdown
     When evaluating tool calls for constrained tools, if unrecognized arguments or arguments
     not declared in the tool adapter schema are supplied, the proxy MUST deny the call (ERR_UNEXPECTED_ARGUMENT).
     ```

4. **[x Applied] Generic Denial Message to Agent (Information Leak Prevention)**:
   - *Decision*: In `enforce` mode, when a tool call is denied by policy, the proxy returns a generic error text `"Denied by mcpsec policy"` to the agent. Full forensic details (e.g. `path not in allowlist: ...` or `tool 'fs.write_file' is not in allowlist`) are recorded exclusively in the audit log.
   - *Applied Spec Patch (`docs/policy_schema.md` §3.2)*:
     ```markdown
     Agent-facing denial error responses in enforce mode MUST return a generic message ("Denied by mcpsec policy")
     and MUST NOT leak allowlists, filesystem paths, or internal policy details.
     ```

5. **[x Applied] Non-Existent Target Path Canonicalization**:
   - *Decision*: For tool operations on files that do not yet exist (e.g., creating a new file via `write_file`), the engine resolves the real path of the nearest existing ancestor directory and joins the remaining relative segments before matching against allowlist globs.
   - *Applied Spec Patch (`docs/policy_schema.md` §3.1)*:
     ```markdown
     For write targets where the target path does not exist on disk, canonicalization MUST
     resolve the parent directory's real path and append the leaf component.
     ```

6. **[x Applied] Windows Security Boundaries**:
   - *Decision*: On Windows, paths are checked to reject UNC paths (`\\server\share`), Win32 device namespace paths (`\\?\`, `\\.\`), Alternate Data Streams (`:`), and legacy DOS reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`). Trailing dots and spaces are stripped per Win32 conventions.
   - *Applied Spec Patch (`docs/policy_schema.md` §3.1)*:
     ```markdown
     On Windows, implementations MUST reject UNC paths, Win32 device namespace paths
     (\\?\\, \\.\\), Alternate Data Streams, and legacy reserved device names (CON, NUL, etc.).
     ```

7. **[x Applied] Audit Log `pin_status` Enum Agreement**:
   - *Decision*: `pin_status` enum across `models.py`, `docs/audit_log_schema.md`, and test assertions is strictly `pinned | unpinned | changed | unchecked` (default: `unchecked` when pinning layer is disabled). `drifted` and `new` were errant drafts and are removed.
   - *Spec Agreement (`docs/audit_log_schema.md` §3)*:
     ```markdown
     pin_status: "pinned" | "unpinned" | "changed" | "unchecked" (default: "unchecked")
     ```

8. **TOCTOU Defense in Depth (Config, Not Code)**:
   - *Decision*: To mitigate Time-of-Check to Time-of-Use (TOCTOU) symlink swapping attacks between proxy evaluation and upstream tool execution, the upstream MCP filesystem server should be configured with its own native directory restrictions equal to the policy roots (e.g. `args: ["-y", "@modelcontextprotocol/server-filesystem", "/allowed/root"]`). This provides defense-in-depth where even if a symlink is swapped after the proxy's check, the upstream server itself enforces directory confinement.

---

## Week 3: Multi-Upstream Aggregation & Architecture Keystone

### Week 3 Decisions (Fail-Closed Choices & Exact Proposed Spec Patches)

1. **Multi-Upstream Configuration & Server Namespacing (`proxy.yaml`)**:
   - *Decision*: `proxy.yaml` defines a list of upstream servers under `servers: [...]`. Each server specifies `name`, `command`, `args`, optional `env` and `cwd`, and `required: bool`.
   - *Validation*: Server names must strictly match `^[a-z][a-z0-9-]*$`, be unique, and must not contain `.` or `__`.
   - *Fail-Closed*: If configuration has invalid or duplicate server names, the proxy refuses to start.

2. **Unified Session State Spanning Upstreams**:
   - *Decision*: A single `SessionState` instance is created per agent connection and shared across all upstream servers under a per-session lock (`anyio.Lock`). This is the architectural keystone allowing session-level taint (Weeks 5-7) to track cross-server flows (e.g., untrusted GitHub read followed by HTTP fetch/post).

3. **Tool Name Translation & Startup Validation (`<server>__<tool>`)**:
   - *Decision*: Tools exposed to the agent are namespaced as `<server>__<tool>`. Policy identifiers remain `<server>.<tool>`.
   - *Validation*: At startup, all exposed tool names are validated to ensure length `<= 64` characters and charset `^[a-zA-Z0-9_-]+$`. Any tool exceeding 64 chars or containing invalid characters fails startup closed.
   - *Routing*: On `tools/call`, the proxy decodes `<server>__<tool>`. If the name has an unknown prefix, invalid format, or resolves to an unknown server, the call is denied with `ERR_UNKNOWN_TOOL` and audited.

4. **Upstream Process Supervision & Degraded Operation**:
   - *Decision*: Each upstream process is supervised with start timeouts, call timeouts, crash detection, bounded restarts with exponential backoff and jitter, and complete process tree termination on shutdown (preventing orphan processes on Windows and Linux).
   - *Degraded Behavior*: If a non-`required` upstream fails or crashes repeatedly, it is marked degraded; its tools are omitted from `tools/list`, and an audit warning is emitted. If a `required` upstream fails, the proxy shuts down cleanly.

5. **Upstream Environment Isolation**:
   - *Decision*: Upstream subprocesses receive an isolated environment containing only safe base system variables plus explicitly allowlisted variables configured for that specific server (e.g., `GITHUB_TOKEN` is passed exclusively to the GitHub server).

6. **Unsupported MCP Surfaces & Server-Initiated Requests**:
   - *Decision*: In v1, the proxy advertises **only** the `tools` capability (`listChanged=True`). Requests for unsupported surfaces (prompts, resources) and server-initiated requests (sampling, elicitation, roots) are rejected and audited as `ERR_UNSUPPORTED_SURFACE`. Notifications other than `tools/list_changed` are logged and ignored.

7. **No False Assurance for Unenforced Policy Features (`ERR_NOT_YET_ENFORCED`)**:
   - *Decision*: In `mode: enforce`, if a policy contains non-empty `flow_rules`, `taint_sources`, or `pinning.mode: strict` (features scheduled for weeks 4-6), the policy loader **refuses to start** with `ERR_NOT_YET_ENFORCED`. In `mode: audit`, loud startup warnings and `policy_loaded` audit events are emitted without blocking.

### Measured Latencies & Performance

Measured via `tests/test_perf.py` on a policy containing **1,000 rules across 100 agents**:
- **Pure In-Memory Policy Lookup & Domain Matching (enforced < 1.0 ms gate):**
  - **p50:** 0.0302 ms
  - **p95:** 0.0610 ms (well within < 1.0 ms budget)
  - **p99:** 0.1407 ms
- **End-to-End Filesystem Canonicalization & Path Matching (target < 10.0 ms):**
  - **p50:** 1.8621 ms
  - **p95:** 2.5590 ms (well within < 10.0 ms target)
  - **p99:** 3.0366 ms

### Top 3 Risks for Week 4 (Benchmark Adapter & Injection Detectors)

1. **Benchmark Tool Schema Drift Across Upstream Server Versions**:
   - Mitigated by committing tool snapshot fixtures (`tests/fixtures/*.tools.json`) and running contract tests against live servers.
2. **Coarse Session Taint Over-Blocking on Benign Multi-Step Workflows**:
   - Benchmarking false positives on benign multi-upstream sessions and calibrating allowlists/flow rules.
3. **Subprocess Pipe Buffer Deadlocks under Heavy Concurrent Streaming**:
   - Ensuring bounded stdio streaming, explicit per-call timeouts, and asynchronous non-blocking drains.
