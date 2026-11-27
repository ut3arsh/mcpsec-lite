# mcpsec-lite

**Deterministic runtime policy and session-level flow control for MCP tool calls, with an open benchmark.**

![status](https://img.shields.io/badge/status-default%20profile%20C7%20(candidate)-orange) [![CI](https://github.com/ut3arsh/ai-agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/ut3arsh/ai-agent-firewall/actions/workflows/ci.yml) ![license](https://img.shields.io/badge/license-Apache--2.0-blue)

> **Status: default profile C7 (candidate, owner has not tagged).** The proxy pipeline, policy engine (including `ADR-021` untrusted taint-source validation), session taint tracking, strict tool-description pinning, hardened approval CLI, official `github/github-mcp-server v2.3.0` adapter table, and benchmark evaluation harness are implemented and run in CI (`C6` is retained unchanged as the handwritten mock-names baseline). All empirical numbers below are from the **development set, scripted attacker, not final benchmark results** (evaluated against local fake servers replaying the official `github-mcp-server v2.3.0` schemas and the 8-tool handwritten mock, not the live `github/github-mcp-server` binary; dev scenarios exercise `4` of `46` official tools). See [`docs/claims.md`](docs/claims.md) for claim-by-claim evidence status.

---

## The problem

AI agents now hold real capabilities: filesystem, HTTP, GitHub, shell, cloud. Their tool *outputs* are attacker-influenced (a GitHub issue, a web page, an email). One poisoned response can steer an agent into reading a secret and sending it out. Model-level guardrails are probabilistic, and there is no widely adopted layer that enforces least privilege at the tool-call boundary.

## The approach

`mcpsec-lite` is a proxy between an agent's MCP client and its MCP servers. It treats the LLM as **confusable, not trustworthy**: security holds within the proxy's scope by design even if the model obeys injected text (`DESIGN.md` §3).

Three deterministic mechanisms, no ML required:

1. **Policy allowlists.** Default-deny per-agent rules on tools, paths, and domains.
2. **Session taint + flow rules** *(headline contribution).* Once a session reads untrusted content or touches private data, egress and exec tools are blocked or held for human approval.
3. **Tool-description pinning.** Hash tool `{name, description, inputSchema}` definitions and reject changes in `strict` mode (rug pulls, tool poisoning).

Plus a structured **audit log with replay** (`mcpsec-replay`), and an open **benchmark** harness. Heuristic detectors (secret patterns, coarse injection markers) exist in audit mode only; they never alter a decision (`ADR-003`).

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
  untrusted_content: [{ tool: github.issue_read }, { tool: http.fetch }]
  private_data:      [{ tool: fs.read_file, args: { path: ["**/.env", "~/.ssh/**"] } }]

flow_rules:
  - id: no-egress-after-untrusted
    if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
```

## Quickstart

```bash
# Start proxy with default profile C7 (candidate, owner has not tagged; C6 retained as baseline)
mcpsec-proxy --config benchmark/configs/C7.yaml --audit-log audit.jsonl

# Review pending human approval requests (sanitized display + query-param redaction)
mcpsec-approve list --log pending_approvals.jsonl --audit-log audit.jsonl

# Replay session timeline from tamper-evident audit log
mcpsec-replay --file audit.jsonl
```

A minimal policy is in [`docs/policy_schema.md`](docs/policy_schema.md) §11.

## What it does NOT do

- **Native agent tools bypass it.** Built-in shell, browser, or file access that doesn't go through MCP is invisible to the proxy (`ADR-001`). Pair with OS-level sandboxing (see [`SECURITY.md`](SECURITY.md)).
- **Session taint is coarse.** It over-blocks after any untrusted read (`ADR-002`). False-positive friction is measured on the development set and reported below.
- **It is not an injection detector.** Detectors are advisory heuristics only (`ADR-003`).
- **Allowed channels can still leak.** If an agent may write to an allowed destination, data can leave that way unless the writing tool is flow-controlled (`benchmark/configs/C7.yaml`, `DESIGN.md` §3).
- **Development benchmark uses fake upstreams (dev scenarios exercise 4 of 46 official tools).** Scripted benchmark runs (`benchmark/dev/benchmark_dev.py`) execute against local fake MCP servers (`C7` replays `4` of `46` official tools from [`tests/fixtures/github.tools.official.json`](tests/fixtures/github.tools.official.json); baseline `C0`–`C6` use the handwritten 8-tool mock in `tests/fixtures/github.tools.json`) rather than the live `github/github-mcp-server` binary (see [`docs/github_snapshot_diff.md`](docs/github_snapshot_diff.md), [`docs/github_tool_mapping.md`](docs/github_tool_mapping.md), and [`docs/operating_with_github_mcp.md`](docs/operating_with_github_mcp.md)).

## Operational Notes (`github/github-mcp-server v2.3.0`)

See [`docs/operating_with_github_mcp.md`](docs/operating_with_github_mcp.md) for the full operator guide and `taint_sources` checklist:

- **Pinning:** Strict pinning (`pinning.mode: strict` in `C7.yaml`) means upgrading `github-mcp-server` changes tool descriptions or schemas, hiding/blocking updated tools until you review diffs and run `mcpsec-pin approve`.
- **Read-only mode & toolsets:** Passing `--read-only` to `github-mcp-server` cuts the server tool count from `46` to `27`; passing `--toolsets all` expands it to `94`, with unmapped tools outside the `46` default snapshot denied by default policy (`ADR-020`).
- **Other surfaces:** `github-mcp-server v2.3.0` also advertises `prompts`, `resources`, and `completions`, which the proxy does not forward (proxy advertises `tools` only and rejects unsupported surfaces with `ERR_UNSUPPORTED_SURFACE`).

## Benchmark & Empirical Evaluation (Default Profile C7 Candidate)

> **Scope Warning:** **Development set, scripted attacker, not final benchmark results.** Evaluated locally under `default profile C7 (candidate, owner has not tagged)` (plus baseline `C0`–`C6`) across scripted benign workflows (v1–v4, `n=50`) and scripted attacks (`n=32` valid scenarios) against local fake upstreams (`dev scenarios exercise 4 of 46 official tools`; live binary and multi-LLM `M1`–`M3` evaluation plus held-out scenarios remain **unmeasured** until the owner applies the pre-registered freeze tag per `AGENTS.md` §4 Rule 8).  
> **Sources:** `C7` post-ADR-021 evaluation in [`benchmark/results/dev_analysis_20261127_c7.md`](benchmark/results/dev_analysis_20261127_c7.md) §1, §5 (equivalence `166/166` vs `C6` in [`docs/evidence/5.18e/equivalence_c6_vs_c7.md`](docs/evidence/5.18e/equivalence_c6_vs_c7.md)); baseline `C0`–`C6` matrix in [`benchmark/results/dev_analysis_20261110_c6.md`](benchmark/results/dev_analysis_20261110_c6.md) §1, §5.

| Configuration | In-Scope ASR (`deny_all`) | In-Scope ASR (`approve_all`) | Approvals / Task (`approve_all`) | Hard-Block Rate (`deny_all`) | Profile Description |
|---|---|---|---|---|---|
| **C0** | 21/21 (100.0%) | 21/21 (100.0%) | 0.00 (0/50) | 0/50 (0.00%) | Baseline without proxy (pass-through) |
| **C1** | 18/21 (85.7%) | 18/21 (85.7%) | 0.00 (0/50) | 0/50 (0.00%) | Static policy allowlists only |
| **C2** | 2/21 (9.5%) | 5/21 (23.8%) | 0.26 (13/50) | 10/50 (20.00%) | Policy + session taint + flow rules |
| **C5** | 2/21 (9.5%) | 10/21 (47.6%) | 0.56 (28/50) | 0/50 (0.00%) | Curated egress exemptions + approval |
| **C6** *(baseline, mock GitHub names)* | 0/21 (0.0%) | 9/21 (42.9%) | 0.40 (20/50) | 0/50 (0.00%) | C5 + scratch notes exemption + file-origin taint + strict pinning |
| **C7** *(default profile C7 (candidate, owner has not tagged))* | **0/21 (0.0%)** | **9/21 (42.9%)** | **0.40 (20/50)** | **0/50 (0.00%)** | **C6 aligned to official `github-mcp-server v2.3.0` schemas + all 19 official `U` GitHub taint sources** |

- **Unattended Scripted Attack Containment (`deny_all`, development set, scripted attacker, not final benchmark results):** In-scope ASR for C7 (and C6 baseline) is `0/21 (0.0% [0.0%, 15.5%])`; total valid ASR including known-gap and out-of-scope scenarios is `10/32 (31.2%)` under `deny_all` and `20/32 (62.5%)` under `approve_all` (Source: `benchmark/results/dev_analysis_20261127_c7.md` §5).
- **Tool-Description Mutation (`ATTACK-23`, development set, scripted attacker, not final benchmark results):** Under C7 (and C6) strict pinning, mid-session tool-description rug-pull is `BLOCKED/BLOCKED`, whereas C0–C5 allow the mutated call (`PASS/PASS`) (Source: `benchmark/results/dev_analysis_20261127_c7.md` §11).
- **Scripted Benign Completion (development set, scripted attacker, not final benchmark results):** Attended (`approve_all`) completion for C7 is `50/50 (100.0%)` with `0/50 (0.00%)` hard-blocks; unattended (`deny_all`) completion is `32/50 (64.0% [50.1%, 75.9%])` combined (`166/166` identical to C6 baseline) (Source: `benchmark/results/dev_analysis_20261127_c7.md` §2).

See [`docs/benchmark_spec.md`](docs/benchmark_spec.md) and [`benchmark/results/dev_analysis_20261127_c7.md`](benchmark/results/dev_analysis_20261127_c7.md) for methodology, known gaps, and per-trial tables.

## Documentation

- [`DESIGN.md`](DESIGN.md): threat model, architecture, session flow semantics
- [`docs/policy_schema.md`](docs/policy_schema.md): policy YAML specification
- [`docs/audit_log_schema.md`](docs/audit_log_schema.md): audit log specification and replay format
- [`docs/benchmark_spec.md`](docs/benchmark_spec.md): benchmark methodology and configuration profiles (C0–C7)
- [`docs/decisions.md`](docs/decisions.md): architecture decision log (ADR-001 through ADR-022)
- [`docs/conformance.md`](docs/conformance.md): specification conformance matrix
- [`docs/engineering_standards.md`](docs/engineering_standards.md): binding engineering standards and invariants
- [`docs/trusted_destinations.md`](docs/trusted_destinations.md): trusted destination criteria and curated domain catalog
- [`docs/taint_sources_audit.md`](docs/taint_sources_audit.md): comprehensive taint sources audit and file-origin rules
- [`docs/github_snapshot_diff.md`](docs/github_snapshot_diff.md): handwritten, deprecated npm, and official GitHub MCP server v2.3.0 snapshot diff analysis
- [`docs/github_tool_mapping.md`](docs/github_tool_mapping.md): official `github-mcp-server v2.3.0` 46-tool mapping and schema inventory
- [`docs/operating_with_github_mcp.md`](docs/operating_with_github_mcp.md): operator guide for `--read-only`, `--toolsets`, pinning upgrades, surfaces, and taint checklist
- [`docs/claims.md`](docs/claims.md): audit mapping every README claim to evidence files and measurement status
- [`docs/freeze_checklist.md`](docs/freeze_checklist.md): pre-tag checklist and owner tag instructions
- [`SECURITY.md`](SECURITY.md): vulnerability reporting policy and scope boundaries
- [`CHANGELOG.md`](CHANGELOG.md): chronological project change log

## Development

### Prerequisites
- Python >= 3.11
- `uv` (recommended) or `pip`

### Installation
```bash
uv pip install -e ".[dev]"
# Or via standard pip:
python -m pip install -e ".[dev]"
```

### Running the Proxy
```bash
mcpsec-proxy --config proxy.yaml --audit-log audit.jsonl
# Or via python module:
python -m proxy.main --config proxy.yaml --audit-log audit.jsonl
```

### Replaying Audit Logs
```bash
mcpsec-replay --file audit.jsonl
mcpsec-replay --file audit.jsonl --session 7c1d --tool read_file --decision allow
```

### Running Tests & Quality Checks
```bash
pytest -v
ruff check .
mypy --strict mcpsec_core proxy cli tests benchmark scripts
```

### Measuring Proxy Overhead
```bash
python benchmark/measure_overhead.py
```

## Security & Limitations
- **Fail-Closed Default (`by design`):** Unrecognized tool calls, invalid argument formats, or policy parse errors fail closed with default-deny semantics (`ADR-004`).
- **Protocol Surface (v1, `by design`):** The proxy advertises and forwards only the MCP `tools` capability (`listChanged=True`). Non-tool surfaces (`prompts`, `resources`) and server-initiated requests (`sampling/createMessage`, `elicitation`, `roots/list`) are rejected and audited as `ERR_UNSUPPORTED_SURFACE` (`DESIGN.md` §2).
- **Generic Agent Errors (`by design`):** In `enforce` mode, policy denials return `"Denied by mcpsec policy"` to prevent leaking policy internals to confusable models (`ADR-013`).
- **Deployment Operating Modes (`ADR-018`, `ADR-019`, `ADR-022`, measurement source: `benchmark/results/dev_analysis_20261127_c7.md`):**
  - **Unattended Mode (`deny_all`):** Pending approvals time out to deny. Measured in-scope ASR on development set (scripted attacker, not final benchmark results): `0/21 (0.0% [0.0%, 15.5%])`.
  - **Attended Mode (`approve_all`):** Worst-case rubber-stamping model where every approval prompt is accepted. Measured in-scope ASR on development set (scripted attacker, not final benchmark results): `9/21 (42.9% [24.5%, 63.4%])`.
- **Empirical Default Profile C7 Candidate Tradeoffs (development set, scripted attacker, not final benchmark results; `166/166` identical to `C6` baseline; source: `benchmark/results/dev_analysis_20261127_c7.md` §1, §2; note wide 95% Wilson CIs on small sets like v3 `n=2` and v4 `n=4`):**
  - **v1 manifest (`n=32`):** Approvals / task = `0.28` (`9/32`), Unattended (`deny_all`) completion = `23/32` (`71.9% [54.6%, 84.4%]`), Attended (`approve_all`) completion = `32/32` (`100.0% [89.3%, 100.0%]`).
  - **v2 manifest (`n=12`):** Approvals / task = `0.75` (`9/12`), Unattended (`deny_all`) completion = `5/12` (`41.7% [19.3%, 68.0%]`), Attended (`approve_all`) completion = `12/12` (`100.0% [75.8%, 100.0%]`).
  - **v3 manifest (`n=2`, small n — wide CI):** Approvals / task = `0.50` (`1/2`), Unattended (`deny_all`) completion = `1/2` (`50.0% [9.4%, 90.5%]`), Attended (`approve_all`) completion = `2/2` (`100.0% [34.2%, 100.0%]`).
  - **v4 manifest (`n=4`, small n — wide CI):** Approvals / task = `0.25` (`1/4`), Unattended (`deny_all`) completion = `3/4` (`75.0% [30.1%, 95.4%]`), Attended (`approve_all`) completion = `4/4` (`100.0% [51.0%, 100.0%]`).
  - **Combined (`n=50`):** Approvals / task = `0.40` (`20/50`), Unattended (`deny_all`) completion = `32/50` (`64.0% [50.1%, 75.9%]`), Attended (`approve_all`) completion = `50/50` (`100.0% [92.9%, 100.0%]`).

Report vulnerabilities in this project privately per [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE). Copyright 2026 Utkarsh Anand.
