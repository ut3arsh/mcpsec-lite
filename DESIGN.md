# DESIGN.md — mcpsec-lite (working name)

**Status:** v0 draft · **Owner:** Utkarsh Anand · **Last updated:** 2026-09-30

> Reference implementation + open benchmark for deterministic runtime policy and session-level flow control on MCP tool calls.

---

## 1. Overview & goals

AI agents now hold real capabilities (filesystem, HTTP, GitHub, shell, cloud). Tool *outputs* are attacker-influenced (issues, web pages, emails), so a single poisoned response can steer an agent into exfiltrating secrets. Model-level guardrails are probabilistic; nothing widely adopted enforces least privilege at the tool-call boundary.

**Goals**
1. A transparent MCP proxy that enforces deterministic policy on every tool call.
2. **Session taint + flow rules** (headline contribution): block egress/exec once a session has seen untrusted content or touched private data.
3. **Tool-description pinning**: detect rug-pull / tool-poisoning changes.
4. Structured audit log + replay.
5. Public benchmark with honest numbers (attack success, false positives, latency), using external suites plus a held-out set.

**Success metrics (v1)**
- Flow rules block ≥90% of the attack set with <5% false positives on benign workflows (kill criterion, see §11).
- Proxy overhead <10 ms per call for non-LLM checks.
- ≥100 GitHub stars, ≥3 external users, ≥1 external blog/paper mention.

## 2. Scope & non-goals

**In scope:** MCP traffic between an agent's MCP client and MCP servers (stdio and HTTP transports).

**Explicit non-goals**
- Agent-native tools that bypass MCP (built-in shell, browser, file access). **The proxy cannot see or stop these.**
- Model-level defenses, jailbreak detection, or "catching all injections."
- Enterprise IAM/SIEM integration, multi-tenant SaaS, compliance claims.
- Per-argument data provenance (future work).

## 3. Threat model

**Assets:** local secrets (`~/.ssh`, `.env`, tokens), private repo contents, the agent's ability to act (exec, write, send).

**Attackers**
- A1: Content author (poisoned GitHub issue, web page, file) — controls tool *output*, not the agent.
- A2: Malicious or compromised MCP server — controls tool *descriptions and behavior*.
- A3: Out of scope: compromised agent host, compromised model provider.

**Trust boundaries**
```
User/Policy author (trusted)
        │
Agent + LLM  ──(untrusted: follows injected text)──┐
        │                                          │
   MCP client                                      │
        │                                          │
   [ PROXY ]  ← trust anchor, enforces policy      │
        │                                          │
MCP servers (semi-trusted) ── tool outputs (untrusted content)
```
The LLM is treated as **confusable, not trustworthy**. Security must hold even if the model fully obeys injected instructions.

**Attack scenarios in scope**
| ID | Scenario | Mitigation |
|----|----------|------------|
| S1 | Poisoned GitHub issue → agent reads `~/.ssh/id_rsa` → posts it via HTTP | Path allowlist; flow rule (private_data ⇒ no egress) |
| S2 | Poisoned web page → agent calls egress tool with data | Flow rule (untrusted_content ⇒ deny egress/exec) |
| S3 | Tool description changes mid-session (rug pull) | Pinning |
| S4 | Malicious tool description embeds instructions (tool poisoning) | Pinning on first-seen + policy allowlist of servers/tools |
| S5 | Secret in tool args | Basic secret detector (weak, labeled as such) |

**Known blind spots (stated up front)**
- Non-MCP tools bypass the proxy.
- Session-level taint is coarse: it over-blocks after any untrusted read.
- Injection detectors are heuristic and bypassable; they are not the security claim.
- Data can leak via allowed channels (e.g., writing secrets into an allowed file/PR body) unless egress-capable tools are flow-controlled.
- Concurrent calls can race the taint state (see §4.4).

## 4. Architecture

### 4.1 Components
```
mcpsec-lite/
  mcpsec_core/   # policy, taint, flow, pinning, audit (pure library, no I/O to MCP)
  proxy/         # MCP proxy (Python, official MCP SDK): client side to servers, server side to agent
  cli/           # mcpsec-replay, mcpsec-approve, mcpsec-pin
  benchmark/     # attacks, adapters (AgentDojo/InjecAgent), runner, results
  tests/
```
`mcpsec_core` is deliberately a standalone library so benchmark adapters can call it directly when an external suite isn't MCP-native.

### 4.2 Tool-call lifecycle
```
agent call
  → resolve server/tool + capabilities
  → pinning check        (changed/unpinned tool?)
  → policy check         (tool/args allowlists; default deny)
  → flow check           (session taint × capability)
  → decision: allow | deny | require_approval
  → [if allow] forward to MCP server
  → classify response → update taint (taint_sources)
  → detectors (secrets/heuristics) → flags
  → audit log entry
  → return response (or error) to agent
```
Precedence: `deny` > `require_approval` > `allow`. Unlisted tools are denied by default.

### 4.3 Core interfaces (high level)
```
check_pinning(server_id, tools_snapshot) -> Decision
check_policy(call, policy)              -> Decision
check_flow(session_state, call, policy) -> Decision
update_taint(call, response, session_state, policy) -> SessionState
```
All four are pure functions over explicit state, so they are unit-testable and formally reasonable (a finite state machine over a small label set).

### 4.4 Sessions & concurrency
- One session per agent connection; `session_id` assigned by the proxy.
- Session state: `{taint: set[label], approvals: [...]}`, guarded by a per-session lock.
- Taint updates commit when a response is processed. A call issued concurrently with a tainting call is evaluated against the pre-update state. Mitigation: `serialize_calls: true` (default in strict mode) serializes calls per session. Document as a limitation otherwise.
- Audit log: append-only JSONL, single writer task, fsync per entry in strict mode.

## 5. Policy & taint design

### 5.1 Capabilities
Each tool is tagged with capabilities so rules target behavior, not names:
```yaml
capabilities:
  http.post:      [egress]
  http.fetch:     [network_read]
  email.send:     [egress]
  shell.exec:     [exec]
  fs.write_file:  [write]
  fs.read_file:   [read]
```
Unlisted tools have no capabilities and are default-denied by policy.

### 5.2 Taint sources (who labels what)
Labels are assigned **by source, declared in policy** — never inferred by a model:
```yaml
taint_sources:
  untrusted_content:
    - tool: github.get_issue
    - tool: github.get_pull_request
    - tool: http.fetch
  private_data:
    - tool: fs.read_file
      args: { path: ["~/.ssh/**", "**/.env", "**/*secret*"] }
```
A label is added to the session **after** a matching call returns.

### 5.3 Flow rules
```yaml
flow_rules:
  - if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
  - if_session_has: [private_data]
    deny_capabilities: [egress]
  - if_session_has: [untrusted_content, private_data]
    deny_capabilities: [egress, exec, write]
mode: enforce          # audit | enforce
approval:
  allow_clear: [untrusted_content]   # private_data cannot be cleared in-session
```
Semantics: labels are monotonic within a session and cleared only by an explicit, logged human approval (`mcpsec-approve --clear-taint untrusted_content`). Approval is CLI-based in v1 (web UI is optional/stretch).

### 5.4 Per-agent allowlists (baseline layer)
```yaml
policies:
  - agent: dev-agent
    tools:
      fs.read_file:
        path_allowlist: ["/home/user/project/**"]
      http.fetch:
        domain_allowlist: ["api.github.com", "raw.githubusercontent.com"]
```

### 5.5 Known cost: over-blocking
Session-wide taint blocks legitimate egress after any untrusted read. v1 ships coarse taint and **reports the false-positive rate honestly**. Per-argument provenance is deferred.

### 5.6 Detectors (secondary, weak by design)
- Secret patterns in args (e.g., `AKIA…`, `ghp_…`).
- Coarse injection markers and encoding anomalies in responses, labeled "basic, easily bypassed."
- Emit `flags` / `risk_score` in the audit log only; **the security guarantee comes from policy + flow, not detectors.** Detector logic is frozen before the held-out benchmark set is written.

## 6. Tool-description pinning
- On first use of a server, snapshot each tool `{name, description, inputSchema}`.
- Hash: SHA-256 over canonical JSON (sorted keys, normalized whitespace) per tool, plus a per-server hash.
- Store in a local `pins.json`.
- On mismatch:
  - `pinning.mode: audit` → log a warning.
  - `pinning.mode: strict` → deny calls to changed tools until re-pinned.
- `tools/list_changed` notifications trigger a re-fetch and diff. A legitimate change surfaces as an approval event, not a silent block or silent accept.
- `mcpsec-pin` CLI: list, diff, approve.

## 7. Audit logging
JSONL, one entry per call and per approval/pin event. Full spec in `docs/audit_log_schema.md`. Key fields: `timestamp, session_id, agent_id, server, tool, args (redactable), decision, decision_reason, rule_id, flags, risk_score, taint_before, taint_after, pin_status, latency_ms`. Replay CLI filters by agent/tool/decision/session.

## 8. CLI
- `mcpsec-replay --file audit.jsonl [--session ID --tool T --decision D]`
- `mcpsec-approve --file pending_approvals.jsonl [--clear-taint LABEL]`
- `mcpsec-pin {list|diff|approve}`

## 9. Benchmark plan (summary; full spec in `docs/benchmark_spec.md`)
- **External:** AgentDojo (primary), InjecAgent (cut first if time slips). These use their own harnesses; budget ~2 weeks of adapter work via `mcpsec_core`.
- **MCP-native, held-out:** GitHub-issue and web-page injection scenarios written **after** detector logic is frozen; never used for tuning.
- **Configs:** baseline · policy only · policy + flow · policy + flow + detectors.
- **Models:** 2–3 (one open-weight), multiple trials each, report variance. Cost budget ≈ $100–200.
- **Metrics:** attack success rate, false-positive rate on benign runs, latency overhead.

## 10. Limitations
See §3 blind spots. Additionally: results depend on model behavior; benchmark attack sets are not exhaustive; the proxy is not a substitute for OS-level sandboxing.

## 11. Kill / pivot criteria
- By week 7: if flow rules block <90% of the initial attack set or FP ≥5% on benign runs → narrow the claim; do not add detectors to compensate.
- If external benchmarks show no clear gain from flow rules → reframe as reference implementation + schema + pinning.
- Responsible disclosure of a real MCP finding is a **stretch goal**, not a committed deliverable.

## 12. Future work
Per-argument provenance/taint; richer detectors; web approval UI; org-level policies; additional MCP servers; standard-track policy/audit schema proposal.

## 13. Open questions
1. Exact capability taxonomy — is `{egress, exec, write, read, network_read}` sufficient?
2. Should `private_data` ever be clearable in-session?
3. How to treat multi-agent sessions sharing one proxy?
4. Which AgentDojo suites map cleanly to MCP tool semantics?