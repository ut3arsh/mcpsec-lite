# Operating `mcpsec-lite` with Official `github/github-mcp-server` (`v2.3.0`)

This guide documents operational flags, tool-pinning lifecycle, unsupported MCP protocol surfaces, and `ADR-021` taint configuration when running `mcpsec-lite` in front of [`github/github-mcp-server`](https://github.com/github/github-mcp-server) (`v2.3.0`).

---

## 1. Snapshot Coverage & Dev Scenario Scope

- Verified official snapshot: [`tests/fixtures/github.tools.official.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.official.json) captured from `github-mcp-server v2.3.0` (`stdio`, default toolsets), containing **`46`** tools (`19` `U`, `27` `T`, `0` `P`).
- Reviewed pure-data adapter definitions for all `46` tools live in `OFFICIAL_GITHUB_TOOL_TABLE` inside [`mcpsec_core/adapters.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/mcpsec_core/adapters.py) and are mapped against [`docs/github_tool_mapping.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/github_tool_mapping.md).
- Default freeze-candidate config [`benchmark/configs/C7.yaml`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/benchmark/configs/C7.yaml) default-denies unused GitHub tools and allowlists only the **`4` of `46` official tools** exercised by the development scenarios (`github.issue_read`, `github.list_issues`, `github.search_repositories`, `github.add_issue_comment`). All remaining `42` default official tools have reviewed schemas in `OFFICIAL_GITHUB_TOOL_TABLE` and may be explicitly enabled in policy files as needed (note all `U`-classified tools require ADR-021 `taint_sources.untrusted_content` entries; see §5).

---

## 2. Read-Only Mode (`--read-only`: `46` -> `27` Tools)

Run `github-mcp-server` with `--read-only` whenever the agent only needs read/search access:

- **Default flags (`stdio`):** exposes **`46`** tools (`27` read-only + `19` write/mutation tools).
- **With `--read-only`:** server exposes **`27`** tools and drops all `19` write/egress mutation tools (such as `add_issue_comment`, `create_or_update_file`, `merge_pull_request`).
- **Defense-in-depth:** Even without `--read-only`, `mcpsec-lite` enforces default-deny per [`docs/policy_schema.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/policy_schema.md) §3 (`C7.yaml` allows only `github.add_issue_comment` among mutations, gated by `flow_rules` after `untrusted_content` or `private_data` taint). Enabling `--read-only` removes mutation tools upstream before `tools/list` pinning.

---

## 3. Toolsets (`--toolsets`: default `46` vs `--toolsets all` `94`)

- Default `github-mcp-server v2.3.0` (`stdio`) registers the **`46`** standard tools captured in [`tests/fixtures/github.tools.official.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.official.json).
- Passing `--toolsets all` expands the server's tool count to **`94`** tools (including GitHub Actions, security advisories, Dependabot, discussions, projects, etc.).
- **Fail-closed behavior (`ADR-020`):** Tools outside the reviewed `46`-tool `OFFICIAL_GITHUB_TOOL_TABLE` are absent from `mcpsec_core/adapters.py` and from `C7.yaml`'s allowlists, so enabling `--toolsets all` leaves those extra tools **denied by default** until reviewed adapters, capability tags, taint classifications, and policy entries are authored.

---

## 4. Strict Pinning & Server Upgrades (`mcpsec-pin approve`)

Default config [`benchmark/configs/C7.yaml`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/benchmark/configs/C7.yaml) sets `pinning.mode: strict`:

- At `tools/list` and `tools/call`, [`mcpsec_core/pinning.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/mcpsec_core/pinning.py) hashes canonical model-visible fields (`name`, `description`, `inputSchema`, excluding `_meta`).
- **Upgrading `github-mcp-server`** (or toggling `--read-only` / `--toolsets`) changes tool descriptions, parameter schemas, or tool sets. In `strict` mode, unpinned or modified tools are **hidden from `tools/list` and blocked on `tools/call`** (`pin_status: unpinned | changed`).
- **Operator workflow after an intentional upgrade:**
  1. Start or inspect the server, then review pending/changed definitions with `mcpsec-pin list` or `mcpsec-pin diff`.
  2. Approve reviewed tool hashes into the local store using `mcpsec-pin approve` (`./pins.json` or configured store path).
  3. Keep `pins.json` and `*.lock` local (both are gitignored and never tracked in git per `ADR-022`).

---

## 5. Non-Forwarded Protocol Surfaces (`ERR_UNSUPPORTED_SURFACE`)

- `github-mcp-server v2.3.0` advertises four MCP server capability groups: `tools`, `prompts`, `resources`, and `completions` ([`tests/fixtures/github.tools.official.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.official.json)).
- Per [`DESIGN.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/DESIGN.md) §2 and [`proxy/main.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/proxy/main.py), `mcpsec-lite` **advertises and forwards only `tools` (`listChanged=True`)** in v1.
- The proxy does **not** forward `prompts`, `resources`, or `completions`, and rejects unsupported protocol/server-initiated requests (`resources/list`, `resources/read`, `prompts/list`, `prompts/get`, `sampling/createMessage`, `roots/list`) with **`ERR_UNSUPPORTED_SURFACE`** logged to the audit stream; `elicitation` is likewise unsupported.

---

## 6. `taint_sources` Checklist & `ADR-021` Validation (`Rule 11`)

Under [`ADR-021`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/decisions.md) and [`docs/policy_schema.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/policy_schema.md) §10 Rule 11:

- Whenever **any** rule in `flow_rules` includes `untrusted_content` in `if_session_has`, **every** tool allowlisted under `policies` (for any agent, not only `"*"`) whose built-in classification in [`mcpsec_core/adapters.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/mcpsec_core/adapters.py) is `U` MUST appear in `taint_sources.untrusted_content` — or fail policy load with **`ERR_TAINT_SOURCE_MISSING`**.
- If an operator intentionally allows a `U` tool without tainting `untrusted_content`, an explicit `taint_exempt` entry with a non-empty `reason` is required (logged into `policy_loaded.warnings`; empty/whitespace reasons fail closed with **`ERR_INVALID_TAINT_EXEMPT`**):
  ```yaml
  taint_exempt:
    - tool: github.get_tag
      reason: "Repository releases tags restricted to signed internal org mirror"
  ```
- When no `flow_rules` entry references `untrusted_content`, untagged `U` tools still load but emit a loud `WARNING:` into `policy_loaded.warnings`.

### All `21` Built-In `U` (`untrusted_content`) Tools

1. **HTTP / Fetch (`2`):** `fetch.fetch`, `http.fetch`
2. **Official `github-mcp-server v2.3.0` (`19`):**
   - `github.get_commit`
   - `github.get_file_contents`
   - `github.get_label`
   - `github.get_latest_release`
   - `github.get_release_by_tag`
   - `github.get_tag`
   - `github.issue_read`
   - `github.list_commits`
   - `github.list_issues`
   - `github.list_pull_requests`
   - `github.list_releases`
   - `github.pull_request_read`
   - `github.search_code`
   - `github.search_commits`
   - `github.search_issues`
   - `github.search_pull_requests`
   - `github.search_repositories`
   - `github.search_users`
   - `github.ui_get`
