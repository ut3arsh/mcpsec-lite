# AgentDojo Reconnaissance Note (Week 8 Preparation)

**Document Version:** 1.0.0  
**Date:** 2026-10-10  
**Status:** Approved for Week 8 Implementation  
**Audience:** `mcpsec-lite` Architecture & Benchmark Engineers

---

## 1. Suite Structure & Licensing

[AgentDojo](https://github.com/dedis/agent-dojo) (Debenedetti et al., NeurIPS 2024) is a benchmark framework designed to evaluate prompt injection attacks and defenses on tool-augmented LLM agents.

- **License:** MIT License.
- **Suite Organization:**
  - **Environments:** Pre-packaged simulated environments with local Python-state backends:
    - `workspace` (Email, Calendar, Cloud Drive / Files)
    - `banking` (Account balance, transactions, recipient management)
    - `slack` (Channels, user direct messages, bot posting)
    - `travel` / `flight` (Flight booking, car rental, hotel reservation)
  - **Tasks:** Pairs of benign user tasks and injected prompts (indirect prompt injection via simulated emails, web pages, tool outputs).
  - **Defense Hook Points:** AgentDojo provides pipeline filters (`prompt_filter`, `tool_filter`), but does not natively ship with an external protocol proxy.

---

## 2. Integration Architecture: MCP Adapter vs. Agent Harness

### Current AgentDojo Boundary
In upstream AgentDojo:
1. Environments define tools as Python functions decorated with `@tool` schema annotations.
2. The agent loop invokes tools directly via Python in-process dispatch (`env.run_tool(tool_name, **kwargs)`).
3. Tool schemas are converted to OpenAI Function Calling or Anthropic Tool formats.

### `mcpsec-lite` Proxy Placement
To benchmark `mcpsec-lite` against AgentDojo with zero defense cheating:
- The proxy must sit between the agent harness and the environment tools via the JSON-RPC 2.0 MCP protocol over STDIO or local loopback HTTP/SSE.
- **Adapter Architecture:**
  - `agentdojo_mcp_server.py`: A lightweight MCP server adapter running over stdio that discovers AgentDojo's registered tools in the target environment (`workspace`, `banking`, `slack`, `travel`) and exposes them via standard `tools/list` and `tools/call`.
  - `ProxySession` intercepts all client-to-adapter JSON-RPC communication, enforcing taint propagation, flow rules, tool pinning, secret detection, and human approval.
  - The evaluation harness drives the agent with standard LLM clients (or scripted benchmark agents) connected to `ProxySession` stdin/stdout.

```
+----------------+      JSON-RPC / stdio      +------------------------+      JSON-RPC / stdio      +--------------------------+
| Agent Harness  | -------------------------> |  mcpsec-lite Proxy     | -------------------------> |  AgentDojo MCP Server    |
| (LLM / Script) | <------------------------- | (Taint, Flow, Pinning) | <------------------------- | (Workspace / Slack / ..) |
+----------------+                            +------------------------+                            +--------------------------+
```

---

## 3. Tool Boundary Mapping to `mcpsec-lite` Policy

| Environment | Tool Name | Classification | Taint Source / Sink Role | Required Rule / Approval |
| :--- | :--- | :--- | :--- | :--- |
| **Workspace** | `search_emails`, `read_email` | **Taint Source** | Emits `tainted:external_content` | Standard read |
| **Workspace** | `search_drive`, `read_file` | **Taint Source / Internal** | Emits `untrusted_data` or `internal` | Standard read |
| **Workspace** | `send_email` | **Sink (Exfiltration)** | Rejects tainted payloads to untrusted domains | Flow Rule: block if tainted unless internal domain |
| **Workspace** | `share_file`, `delete_file` | **High-Impact Action** | Mutates permissions / data | Mandatory human approval |
| **Slack** | `read_channel_messages` | **Taint Source** | Emits `tainted:slack_message` | Standard read |
| **Slack** | `post_message` | **Sink (Public/External)** | Rejects tainted exfiltration | Flow Rule: block tainted exfiltration |
| **Banking** | `get_balance`, `get_transactions` | **Sensitive Source** | Emits `sensitive:financial` | Restricted read |
| **Banking** | `transfer_money`, `add_recipient` | **High-Impact Sink** | Exfiltration / fund diversion | Mandatory human approval |
| **Travel** | `search_flights`, `search_hotels` | **Clean Utility** | Public catalog data | Standard read |
| **Travel** | `book_flight`, `charge_card` | **High-Impact Sink** | Financial commitment | Mandatory human approval |

---

## 4. Feasibility & Effort Estimate (Week 8)

### Effort Breakdown (Total: ~3–4 Engineer Days)
1. **Day 1: Adapter Construction (`agentdojo_mcp_server.py`)**
   - Wrap AgentDojo tool schemas into MCP JSON-RPC `tools/list` and `tools/call` handlers.
   - Handle environment state reset per trial (`env.reset()`).
2. **Day 2: Policy & Pin Store Authoring**
   - Formulate `agentdojo_policy.yaml` with sources, sinks, and flow rules covering the 4 suites.
   - Generate golden tool hashes in `agentdojo_pins.json`.
3. **Day 3: Benchmark Runner Integration**
   - Connect `benchmark/runner.py` to AgentDojo suite execution harness.
   - Run C0 (Baseline), C1 (Static Policy), C2 (Full Firewall), C3 (Flow-only), and C4 (Strict Pinning).
4. **Day 4: Statistical Evaluation & Reporting**
   - Wilson score intervals for ASR and FPR on standard AgentDojo attack/benign tasks.
   - Produce `benchmark/results/agentdojo_2026_w8.md`.

### Anticipated Blockers & Mitigations
- **Async Proxy vs. Synchronous Environment:** AgentDojo tools run synchronously; the MCP server adapter wraps tool execution in `asyncio.to_thread` or standard async dispatch to prevent loop blockage.
- **State Reset Isolation:** State leaks across trials could corrupt taint tracking or balance state. The runner will invoke `env.reset()` and initialize a fresh `ProxySession` per scenario run.
- **Model Determinism:** For benchmark repeatability, use fixed seeds and deterministic temperature ($T=0$) when invoking LLM backends (or deterministic replay traces).

---

## 5. Architectural Decision

**Decision:** **Wrap AgentDojo environments as an MCP server library adapter using AgentDojo as an upstream Python dependency.**

- **Rationale:**
  - Avoids maintaining an out-of-sync fork of AgentDojo.
  - Avoids the overhead of multi-process OS daemon management by running the adapter via subprocess stdio within the benchmark runner.
  - Guarantees strict conformance: the proxy operates on real JSON-RPC wire messages identically to production MCP servers.
