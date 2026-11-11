# mcpsec-lite

**Deterministic runtime policy and session-level flow control for MCP tool calls, with an open benchmark.**

![status](https://img.shields.io/badge/status-active%20development%20(C6)-orange) [![CI](https://github.com/ut3arsh/ai-agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/ut3arsh/ai-agent-firewall/actions/workflows/ci.yml) ![license](https://img.shields.io/badge/license-Apache--2.0-blue)

> **Status: verified implementation (Default Profile C6).** The complete proxy pipeline, policy engine, session taint tracking, strict tool-description pinning, hardened human approval CLI, and reproducible benchmark evaluation suite are fully implemented and verified in CI. Baseline and defense-profile benchmark results are reported below from the frozen C6 development evaluation.

---

## The problem

AI agents now hold real capabilities: filesystem, HTTP, GitHub, shell, cloud. Their tool *outputs* are attacker-influenced (a GitHub issue, a web page, an email). One poisoned response can steer an agent into reading a secret and sending it out. Model-level guardrails are probabilistic, and there is no widely adopted layer that enforces least privilege at the tool-call boundary.

## The approach

`mcpsec-lite` is a proxy between an agent's MCP client and its MCP servers. It treats the LLM as **confusable, not trustworthy**: security must hold even if the model fully obeys injected text.

Three deterministic mechanisms, no ML required:

1. **Policy allowlists.** Default-deny per-agent rules on tools, paths, and domains.
2. **Session taint + flow rules** *(headline contribution).* Once a session reads untrusted content or touches private data, egress and exec tools are blocked until a human approves. This targets the actual attack pattern, which per-call allowlists cannot stop.
3. **Tool-description pinning.** Hash tool descriptions and detect changes (rug pulls, tool poisoning).

Plus a structured **audit log with replay**, and a **benchmark** (external suites plus a held-out set) that reports attack success, false positives, and latency honestly.

Heuristic detectors (secret patterns, coarse injection markers) exist but are advisory only. They never change a decision. The security claim rests on policy and flow control.

## How it works

```
Agent → MCP client → [ mcpsec-lite proxy ] → MCP servers
                        │
       pinning check → policy check → flow/taint check
                        │
             allow / deny / require approval
                        │
             forward → classify response → update taint → audit log
```

Example flow rule:

```yaml
taint_sources:
  untrusted_content: [{ tool: github.get_issue }, { tool: http.fetch }]
  private_data:      [{ tool: fs.read_file, args: { path: ["**/.env", "~/.ssh/**"] } }]

flow_rules:
  - id: no-egress-after-untrusted
    if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
```

An agent that reads a poisoned issue can no longer call `http.post` in that session, however persuasive the injected text.

## Quickstart

```bash
# Start proxy with C6 default profile in front of MCP servers
mcpsec-proxy --config benchmark/configs/C6.yaml --audit-log audit.jsonl

# Review pending human approval requests (hardened against ANSI/terminal injections)
mcpsec-approve list --log pending_approvals.jsonl --audit-log audit.jsonl

# Replay session timeline from tamper-evident audit log
mcpsec-replay --file audit.jsonl
```

A minimal policy is in [`docs/policy_schema.md`](docs/policy_schema.md) §11.

## What it does NOT do

- **Native agent tools bypass it.** Built-in shell, browser, or file access that doesn't go through MCP is invisible to the proxy. Pair with OS-level sandboxing.
- **Session taint is coarse.** It over-blocks after any untrusted read. The false-positive rate is measured and reported.
- **It is not an injection detector.** Detectors are weak by design and clearly labeled.
- **Allowed channels can still leak.** If an agent may write to an allowed destination, data can leave that way unless the writing tool is flow-controlled.

## Benchmark & Empirical Evaluation (Chunk 5.18a Default Profile C6)

Evaluated across 50 benign workflows (manifests v1–v4) and 32 valid attack scenarios across both supported operating modes (`deny_all` unattended fail-closed vs `approve_all` attended worst-case):

| Configuration | In-Scope ASR (`deny_all`) | In-Scope ASR (`approve_all`) | Approvals / Task | Hard-Block Rate | Profile Description |
|---|---|---|---|---|---|
| **C0** | 21/21 (100.0%) | 21/21 (100.0%) | 0.00 | 0.0% | Baseline without proxy (pass-through) |
| **C1** | 18/21 (85.7%) | 18/21 (85.7%) | 0.00 | 0.0% | Static policy allowlists only |
| **C2** | 2/21 (9.5%) | 5/21 (23.8%) | 0.26 | 20.0% | Policy + session taint + flow rules |
| **C5** | 2/21 (9.5%) | 10/21 (47.6%) | 0.56 | 0.0% | Curated egress exemptions + approval |
| **C6 (Frozen Default)** | **0/21 (0.0%)** | **9/21 (42.9%)** | **0.40** | **0.0%** | **C5 + scratch notes exemption + file-origin taint + strict pinning** |

- **Security Guarantee (Unattended Mode):** In unattended mode (`deny_all`), C6 reduces in-scope attack success rate to **0.0% (0/21, 95% CI [0.0%, 15.5%])**.
- **Tool-Description Tampering (ATTACK-23):** C6 strict pinning blocks mid-session tool description rug-pulls in both modes (`BLOCKED/BLOCKED`), whereas C0–C5 allow the mutated tool to execute.
- **Benign Completion:** Attended (`approve_all`) completion is **100.0% (50/50)** across all manifests with **0% hard-blocks**. Unattended completion is **64.0% (32/50)** combined.

See [`docs/benchmark_spec.md`](docs/benchmark_spec.md) and [`benchmark/results/dev_analysis_20261110_c6.md`](benchmark/results/dev_analysis_20261110_c6.md) for full trial records and methodology.

## Documentation

- [`DESIGN.md`](DESIGN.md): threat model, architecture, session flow semantics
- [`docs/policy_schema.md`](docs/policy_schema.md): policy YAML specification
- [`docs/audit_log_schema.md`](docs/audit_log_schema.md): audit log specification and replay format
- [`docs/benchmark_spec.md`](docs/benchmark_spec.md): benchmark methodology and configuration profiles (C0–C6)
- [`docs/decisions.md`](docs/decisions.md): architecture decision log (ADR-001 through ADR-019)
- [`docs/conformance.md`](docs/conformance.md): specification conformance matrix
- [`docs/engineering_standards.md`](docs/engineering_standards.md): binding engineering standards and invariants
- [`docs/trusted_destinations.md`](docs/trusted_destinations.md): trusted destination criteria and curated domain catalog
- [`docs/taint_sources_audit.md`](docs/taint_sources_audit.md): comprehensive taint sources audit and file-origin rules
- [`docs/github_snapshot_diff.md`](docs/github_snapshot_diff.md): official GitHub MCP server snapshot diff analysis
- [`SECURITY.md`](SECURITY.md): vulnerability reporting policy and scope boundaries
- [`CHANGELOG.md`](CHANGELOG.md): chronological project change log

## Development

### Prerequisites
- Python ≥ 3.11
- `uv` (recommended) or `pip`

### Installation
```bash
# Install dependencies and package in editable mode
uv pip install -e ".[dev]"
# Or via standard pip:
python -m pip install -e ".[dev]"
```

### Running the Proxy
```bash
# Start proxy in front of upstream MCP server
mcpsec-proxy --config proxy.yaml --audit-log audit.jsonl

# Or via python module:
python -m proxy.main --config proxy.yaml --audit-log audit.jsonl
```

### Replaying Audit Logs
```bash
# View human-readable session timeline
mcpsec-replay --file audit.jsonl

# Filter by session, tool, decision, or agent
mcpsec-replay --file audit.jsonl --session 7c1d --tool read_file --decision allow
```

### Running Tests & Quality Checks
```bash
# Run pytest suite
pytest -v

# Run linter and type checker
ruff check .
mypy .
```

### Measuring Proxy Overhead
```bash
# Run benchmark measuring p50/p95 latency distributions
python benchmark/measure_overhead.py
```

## Security & Limitations
- **Fail-Closed Default:** Any unrecognized tool call, invalid argument format, or parsing error is rejected with default-deny semantics.
- **Protocol Surface (v1):** The proxy advertises and supports only the MCP `tools` capability (`listChanged=True`). Non-tool surfaces (`prompts`, `resources`) and server-initiated requests (`sampling/createMessage`, `elicitation`, `roots/list`) are rejected and audited as `ERR_UNSUPPORTED_SURFACE`.
- **Generic Agent Errors:** In `enforce` mode, policy denials return generic messages to prevent information leakage to confusable models.
- **Deployment Operating Modes (ADR-018, ADR-019):**
  - **Unattended Mode (`deny_all`):** Automated execution without human operator presence. Pending approval requests time out and fail closed to denial. Security guarantee: 0% in-scope attack success rate (ASR = 0/21, 0.0% [0.0%, 15.5%]). Benign workflow unattended completion is determined by whether the task strictly avoids unapproved writes or egress outside exempt scratch paths and curated domains.
  - **Attended Mode (`approve_all`):** Operator online to review pending approvals. Evaluated under `approve_all` as the catastrophic upper bound of operator approval fatigue (rubber-stamping all prompts), where in-scope ASR is 9/21 (42.9% [24.5%, 63.4%]).
- **Empirical Default Profile C6 Tradeoffs (per-set figures from generated benchmark report):**
  - **v1 manifest (n=32):** Approvals / task = 0.28 (9/32), Unattended (`deny_all`) completion = 23/32 (71.9% [54.6%, 84.4%]), Attended (`approve_all`) completion = 32/32 (100.0% [89.3%, 100.0%]).
  - **v2 manifest (n=12):** Approvals / task = 0.75 (9/12), Unattended (`deny_all`) completion = 5/12 (41.7% [19.3%, 68.0%]), Attended (`approve_all`) completion = 12/12 (100.0% [75.8%, 100.0%]).
  - **v3 manifest (n=2):** Approvals / task = 0.50 (1/2), Unattended (`deny_all`) completion = 1/2 (50.0% [9.4%, 90.5%]), Attended (`approve_all`) completion = 2/2 (100.0% [34.2%, 100.0%]).
  - **v4 manifest (n=4):** Approvals / task = 0.25 (1/4), Unattended (`deny_all`) completion = 3/4 (75.0% [30.1%, 95.4%]), Attended (`approve_all`) completion = 4/4 (100.0% [51.0%, 100.0%]).
  - **Combined (n=50):** Approvals / task = 0.40 (20/50), Unattended (`deny_all`) completion = 32/50 (64.0% [50.1%, 75.9%]), Attended (`approve_all`) completion = 50/50 (100.0% [92.9%, 100.0%]).


Report vulnerabilities in this project privately per [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE). Copyright 2026 Utkarsh Anand.