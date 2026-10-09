# Human-in-the-Loop Approval Queue Design Note (Week 5 Prep)

## 1. Executive Summary & Goals

In autonomous agent workflows, certain actions represent irreversible or high-risk operations (e.g. initiating external HTTP POST egress after reading untrusted user issues, deleting repositories, or executing arbitrary shell commands). 

While deterministic static policies (`allow` / `deny`) handle black-and-white boundaries, real-world development workflows frequently require **conditional human-in-the-loop (HITL) elevation**: allowing an operator to inspect the exact context, arguments, and accumulated session taint, and explicitly approve or deny the tool execution.

This document outlines the architectural blueprint, data structures, concurrency guarantees, and channel abstractions for the Week 5 Approval Queue engine in `mcpsec-lite`.

---

## 2. Policy Configuration Schema

HITL approval is configured in [`docs/policy_schema.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/policy_schema.md) via two complementary mechanisms:

```yaml
version: 1
mode: enforce

flow_rules:
  - id: require-approval-untrusted-egress
    if_session_has: [untrusted_content]
    require_approval_capabilities: [egress]

approval:
  channel: cli                  # cli | webhook | socket
  timeout_seconds: 120          # Fail-closed timeout
  default_action: deny          # Fail-closed default on timeout / channel drop
  allow_clear: [untrusted_content] # Taint labels operator is permitted to clear
```

---

## 3. Data Model

### 3.1 Approval Request

When an incoming tool call matches a `require_approval` rule:

```json
{
  "request_id": "appr_9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "session_id": "sess_a81f8f3c-5764-4bf8-b80c-7b9c9f0b12e1",
  "call_id": "call_f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "agent_id": "dev-agent",
  "server": "fetch",
  "tool": "fetch",
  "capabilities": ["egress"],
  "arguments": {
    "url": "https://api.external-service.com/deploy"
  },
  "taint_state": ["untrusted_content"],
  "rule_id": "require-approval-untrusted-egress",
  "created_at": "2026-10-10T03:00:00.000Z",
  "expires_at": "2026-10-10T03:02:00.000Z"
}
```

### 3.2 Operator Decision

```json
{
  "request_id": "appr_9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "decision": "approve",       // "approve" | "deny" | "approve_and_clear_taint"
  "operator_id": "alice@corp.internal",
  "clear_taint": ["untrusted_content"],
  "reason": "Verified deploy endpoint is benign destination",
  "decided_at": "2026-10-10T03:00:15.120Z"
}
```

---

## 4. Architectural Pipeline & Execution Flow

```
Agent Client
     │  (MCP call_tool)
     ▼
ProxySession
     │
     ├── 1. Decode Name (<server>__<tool>)
     ├── 2. Evaluate Policy & Flow Rules
     │       └── Flow Rule matches `require_approval_capabilities`
     │
     ▼
ApprovalQueue (Pending State)
     │
     ├── 3. Emit Audit Event: `approval_requested` (effective_decision: held)
     ├── 4. Dispatch Request to Channel (CLI prompt / Webhook / Unix Socket)
     ├── 5. Await Operator Decision with bounded `anyio.fail_after(timeout_seconds)`
     │
     ├── [Timeout / Operator Deny]
     │       ├── Log Audit Event: `approval_resolved` (decision: deny, effective: blocked)
     │       └── Return Generic Error to Agent: "Denied by mcpsec policy"
     │
     └── [Operator Approve / Approve & Clear]
             ├── If approve_and_clear: `SessionState.taint.difference_update(cleared)`
             ├── Log Audit Event: `approval_resolved` (decision: allow, effective: forwarded)
             ├── Forward tool call to upstream server
             └── Return upstream result to agent
```

---

## 5. Channel Abstractions

To support diverse runtime environments (local CLI development vs. team orchestration servers):

1. **`CliApprovalChannel` (Default for Dev Agent):**
   - Renders formatted terminal prompt with tool name, arguments, and current taint state.
   - Interactive prompt options: `[a]pprove once`, `[c]lear taint & approve`, `[d]eny`.
2. **`WebhookApprovalChannel` (CI / Cloud Deployment):**
   - Issues signed HMAC-SHA256 HTTP POST to security operations webhook endpoint.
   - Awaits asynchronous REST callback at `/api/v1/approvals/{request_id}/decision`.
3. **`SocketApprovalChannel` (Local IPC / Desktop App):**
   - Communicates over local domain socket / named pipe to native UI notification helper.

---

## 6. Concurrency & Security Invariants

1. **Fail-Closed by Construction:** Any error during approval dispatch (channel drop, deserialization error, timeout) immediately falls back to `decision: deny`.
2. **Cancellation Hygiene:** If the agent disconnects or cancels the pending MCP request while approval is pending, the proxy cleans up the approval task without leaking orphaned threads or holding memory.
3. **Audit Immutability:** Every transition (`approval_requested`, `approval_resolved`, `approval_expired`) generates a structured audit log event with operator ID, reason, and latency metrics.
4. **Taint Clearance Enforcement:** Operators can only clear taint labels explicitly declared in `approval.allow_clear`. Requests to clear undeclared labels are rejected.
