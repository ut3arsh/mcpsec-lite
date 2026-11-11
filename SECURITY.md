# Security Policy

## Supported Versions

`mcpsec-lite` is currently in active development. Security updates and patches are provided exclusively on the `main` branch.

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main`           | :white_check_mark: |
| Pre-release tags | :white_check_mark: |
| Historical / archived branches | :x: |

---

## Reporting a Vulnerability

We take the security of `mcpsec-lite` seriously. If you identify a potential security vulnerability or architectural flaw:

1. **Do NOT open a public GitHub issue or pull request.**
2. **Submit a private report** via GitHub Security Advisories:
   - Navigate to [GitHub Security Advisories](https://github.com/ut3arsh/ai-agent-firewall/security/advisories/new).
   - Alternatively, contact the project maintainer directly at `utkarshanand0506@gmail.com` with the subject line `[SECURITY] mcpsec-lite Vulnerability Report`.
3. Provide a clear description of the issue, reproducible steps or scripted proof-of-concept (PoC), and the relevant policy/configuration used.

### Response Expectations & Triage SLA
- **Initial Acknowledgment:** Within **48 hours** of report receipt.
- **Triage & Reproducibility Assessment:** Within **7 business days**.
- **Coordinated Disclosure:** We will work with the reporter to establish a reasonable fix and release timeline before any public disclosure.

---

## Architectural Scope & Threat Model Boundaries

`mcpsec-lite` is a **deterministic runtime proxy and session flow firewall for the Model Context Protocol (MCP)**. It treats the agent's underlying LLM as *confusable, not trustworthy*.

### In Scope
- **Policy Enforcement:** Default-deny allowlisting of MCP tools, arguments, filesystem paths, and network domains.
- **Session Taint & Flow Rules:** Tracking taint labels (`untrusted_content`, `private_data`) across multi-step conversations and holding/blocking unapproved egress or write actions.
- **Tool-Description Pinning:** Cryptographic detection and rejection of mid-session tool mutations (rug pulls) and server tampering.
- **Audit Log Integrity:** Tamper-evident hash-chain verification and secret redaction in logs and human approval prompts.
- **Fail-Closed Guarantees:** Unrecognized schemas, parsing errors, or unknown parameters fail closed to denial.

### Explicitly Out of Scope (Known Blind Spots)
- **Native Agent Tools:** Tools, shell interpreters, browsers, or file APIs built natively into the AI agent that bypass the MCP stdio/SSE proxy are invisible to `mcpsec-lite`.
- **OS Sandbox Boundary:** `mcpsec-lite` is an **MCP protocol firewall, not an operating system sandbox**. It does not constrain kernel syscalls, memory, CPU, or network sockets outside the proxy process tree. Deployments requiring OS isolation must pair `mcpsec-lite` with containerization or hypervisor sandboxes (e.g. Docker, Firecracker, gVisor).
- **Allowed-Channel Data Leakage:** If a policy explicitly permits an egress destination or scratch directory without flow restrictions, data sent along that permitted path is allowed by design.
- **Probabilistic Heuristics:** Advisory detectors (`DetectorEngine`) provide informational audit signals only and never alter firewall decisions (ADR-003). Heuristic bypasses without an associated flow/policy bypass are not considered security vulnerabilities.
