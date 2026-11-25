# GitHub MCP Server Snapshot Diff Analysis

This document compares three GitHub MCP tool schemas:

1. **Handwritten Benchmark Fixture (Baseline Mock):** [`tests/fixtures/github.tools.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.json) (`UNVERIFIED-handwritten`, **8 tools**) — used by the scripted fake GitHub server in the dev benchmark.
2. **Archived / Deprecated npm Package:** [`tests/fixtures/github.tools.npm_deprecated.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.npm_deprecated.json) (`@modelcontextprotocol/server-github@2025.4.8`, server `0.6.2`, **26 tools**, `VERIFIED` schema from deprecated npm package; **NOT** GitHub's official server).
3. **Official Go GitHub MCP Server:** [`tests/fixtures/github.tools.official.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.official.json) (`github/github-mcp-server` **`v2.3.0`**, commit `c6b62954c062b3ad779f4e208716e09cb4a723e0`, asset `github-mcp-server_Windows_x86_64.zip`, flags `["stdio"]`, **46 tools** in default toolsets; **27 tools** with `--read-only`).

> **Scope Note (No Code/Config Edits):** Per Chunk 5.18c rules, this document and [`docs/github_tool_mapping.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/github_tool_mapping.md) are **documentation only**. Neither `benchmark/configs/*.yaml`, `mcpsec_core/adapters.py`, nor `mcpsec_core/` taint logic were modified. The dev/frozen C6 benchmark continues to target the fake/mock GitHub server matching the handwritten schema.

---

## 1. Implementation & Verification Comparison

| Dimension | Handwritten (`github.tools.json`) | Deprecated npm (`@modelcontextprotocol/server-github`) | Official Go (`github/github-mcp-server` `v2.3.0`) |
|---|---|---|---|
| Provenance / Status | `UNVERIFIED-handwritten` | `CAPTURED-npm-deprecated-package` (archived `servers-archived`; NOT GitHub's official server) | `VERIFIED-official-github-mcp-server` (`github-mcp-server_Windows_x86_64.zip`, SHA-256 verified) |
| Capture Flags | N/A | None supported (stdio default) | `stdio` (`--read-only` supported; `--toolsets` supported, default `context,copilot,issues,pull_requests,repos,users`) |
| `--read-only` Mode | N/A | **Not supported** | **Supported** (filters 46 default tools down to **27** read-only tools) |
| Write Tools Present | 0 | **Yes (12 write tools always exposed)** | **Yes by default (19 write tools)**; **0 when `--read-only` passed**; **94 total with `--toolsets all`** |
| MCP Capabilities Advertised | `tools` (benchmark mock) | `tools` | `completions`, `prompts`, `resources`, `tools` (`mcpsec-lite` blocks non-`tools` surfaces with `ERR_UNSUPPORTED_SURFACE`) |
| Total Tools Exposed | 8 | 26 | **46** (default toolsets) / **27** (`--read-only`) / **94** (`--toolsets all`) |
| Auth Behavior on `tools/list` (Dummy Token) | N/A | Served statically without token check | Attempted token scope check (`stderr`: `failed to fetch token scopes, continuing without scope filtering`), then served full `tools/list` without live results |

---

## 2. Official Server (`v2.3.0`, `stdio`) vs. Handwritten Fixture (`github.tools.json`)

### A. Tools Present, Missing, and Consolidated/Renamed

Of the **8** tools in the handwritten fixture (which C6 relies on alongside `github.create_issue_comment`):

| Handwritten / C6 Tool Name | Status in Official `github-mcp-server v2.3.0` | Breaking Delta |
|---|---|---|
| `get_issue` | **MISSING (Consolidated)** | Replaced by `issue_read` (requires `method` in `{get, get_comments, get_sub_issues, get_labels}`). |
| `get_pull_request` | **MISSING (Consolidated)** | Replaced by `pull_request_read` (requires `method` in `{get, get_diff, get_status, get_files, get_review_comments, get_reviews, get_comments}`; param `pull_number` $\rightarrow$ `pullNumber`). |
| `create_issue_comment` (used in C6 & benchmarks) | **MISSING (Renamed)** | Named `add_issue_comment` in official server (also missing in handwritten fixture). |
| `get_file_contents` | **Present** (Schema changed) | `path` no longer required (directory listings); added `fields`, `sha` alongside `ref`. |
| `list_issues` | **Present** (Schema changed) | `per_page` $\rightarrow$ `perPage`, `page` $\rightarrow$ `after` (cursor), `sort` $\rightarrow$ `orderBy`; added `fields`, `field_filters`. |
| `list_pull_requests` | **Present** (Schema changed) | `per_page` $\rightarrow$ `perPage`; added `fields`. |
| `search_repositories` | **Present** (Schema changed) | `per_page` $\rightarrow$ `perPage`; added `minimal_output`, `order`, `sort`. |
| `search_code` | **Present (Breaking)** | Required `q` renamed to **`query`**; `per_page` $\rightarrow$ `perPage`; added `fields`. |
| `search_issues` | **Present (Breaking)** | Required `q` renamed to **`query`**; `per_page` $\rightarrow$ `perPage`; added `fields`, `owner`, `repo`. |

### B. Extra Tools Present in Official Server (`v2.3.0` Default Toolsets)

All **40 additional tools** (`46 - 6 shared names = 40`) absent from `tests/fixtures/github.tools.json` fall into:
- **21 Read-Only Tools (present under `--read-only`):** `get_commit`, `get_label`, `get_latest_release`, `get_me`, `get_release_by_tag`, `get_tag`, `get_team_members`, `get_teams`, `issue_read`, `list_branches`, `list_commits`, `list_issue_fields`, `list_issue_types`, `list_releases`, `list_repository_collaborators`, `list_tags`, `pull_request_read`, `search_commits`, `search_pull_requests`, `search_users`, `ui_get`.
- **19 Write / Mutation Tools (stripped if `--read-only` is set):** `add_comment_to_pending_review`, `add_issue_comment`, `add_reply_to_pull_request_comment`, `assign_copilot_to_issue`, `create_branch`, `create_or_update_file`, `create_pull_request`, `create_repository`, `delete_file`, `fork_repository`, `issue_write`, `merge_pull_request`, `pull_request_review_write`, `push_files`, `request_copilot_review`, `sub_issue_write`, `update_issue_comment`, `update_pull_request`, `update_pull_request_branch`.

### C. Official Go `v2.3.0` (`46`) vs. Deprecated npm `@modelcontextprotocol/server-github` (`26`)

- **9 tools in deprecated npm absent from official default `v2.3.0`:**
  `create_issue`, `create_pull_request_review`, `get_issue`, `get_pull_request`, `get_pull_request_comments`, `get_pull_request_files`, `get_pull_request_reviews`, `get_pull_request_status`, `update_issue` (replaced by consolidated `issue_read`, `issue_write`, `pull_request_read`, `pull_request_review_write`).
- **29 tools in official default `v2.3.0` absent from deprecated npm:**
  Consolidated read/write/review/sub-issue/branch/tag/release/commit/team/Copilot tools listed in [`tests/fixtures/github.tools.official.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.official.json).

---

## 3. Shared Tool Parameter Schema Divergences (Official vs. Handwritten)

| Tool | Handwritten (`github.tools.json`) Properties & Required | Official `v2.3.0` Properties & Required | Impact on Strict Adapter (`all_args` / `path_args`) |
|---|---|---|---|
| `get_file_contents` | props: `owner, path, ref, repo`; req: `owner, path, repo` | props: `fields, owner, path, ref, repo, sha`; req: `owner, repo` | `ERR_UNEXPECTED_ARGUMENT` on `fields`/`sha`; `path` omitted on directory lookup fails `extract_path_arguments` (`path_args=("path",)`). |
| `list_issues` | props: `direction, labels, owner, page, per_page, repo, since, sort, state`; req: `owner, repo` | props: `after, direction, field_filters, fields, labels, orderBy, owner, perPage, repo, since, state`; req: `owner, repo` | `ERR_UNEXPECTED_ARGUMENT` on `after`, `field_filters`, `fields`, `orderBy`, `perPage`. |
| `list_pull_requests` | props: `base, direction, head, owner, page, per_page, repo, sort, state`; req: `owner, repo` | props: `base, direction, fields, head, owner, page, perPage, repo, sort, state`; req: `owner, repo` | `ERR_UNEXPECTED_ARGUMENT` on `fields`, `perPage`. |
| `search_repositories` | props: `page, per_page, query`; req: `query` | props: `minimal_output, order, page, perPage, query, sort`; req: `query` | `ERR_UNEXPECTED_ARGUMENT` on `minimal_output`, `order`, `perPage`, `sort`. |
| `search_code` | props: `order, page, per_page, q, sort`; req: **`q`** | props: `fields, order, page, perPage, query, sort`; req: **`query`** | **Call-breaking:** required parameter `q` renamed to `query`; `ERR_UNEXPECTED_ARGUMENT` on `query`, `fields`, `perPage`. |
| `search_issues` | props: `order, page, per_page, q, sort`; req: **`q`** | props: `fields, order, owner, page, perPage, query, repo, sort`; req: **`query`** | **Call-breaking:** required parameter `q` renamed to `query`; `ERR_UNEXPECTED_ARGUMENT` on `query`, `fields`, `owner`, `repo`, `perPage`. |

---

## 4. Concrete Breaking Impact on `C6.yaml` and `mcpsec_core/adapters.py`

1. **Policy Allowlists (`benchmark/configs/C6.yaml`):**
   - `github.get_issue`, `github.get_pull_request`, and `github.create_issue_comment` are listed in `C6.yaml` (`capabilities` and `policies`), but **none of these three tool names exist** in official `github/github-mcp-server v2.3.0` (replaced by `issue_read`, `pull_request_read`, `add_issue_comment`).
   - Meanwhile, all 40 newly exposed official tools are omitted from `C6.yaml` and therefore **default-denied** by policy.
2. **Capabilities (`C6.yaml`):**
   - Running the official server without `--read-only` introduces **19 mutating/egress tools** (including `issue_write`, `add_issue_comment`, `create_pull_request`, `create_or_update_file`, `push_files`, `delete_file`, `merge_pull_request`, `assign_copilot_to_issue`, `sub_issue_write`). Only `add_issue_comment` (under the deprecated alias `create_issue_comment`) has `[write, egress]` declared in `C6.yaml`.
3. **Taint Sources (`C6.yaml`):**
   - C6 declares `github.get_issue` and `github.get_pull_request` as `untrusted_content` sources, **NOT** `github.issue_read`, `github.pull_request_read`, `github.search_pull_requests`, `github.list_commits`, `github.get_commit`, `github.search_commits`, etc. Reading a poisoned issue or PR via official `issue_read` / `pull_request_read` would fail to acquire `untrusted_content` if allowed in policy without updating `taint_sources`.
4. **Strict Argument Adapters (`mcpsec_core/adapters.py`):**
   - All 6 shared tools suffer schema drift (`perPage`, `query` vs `q`, `after`, `orderBy`, `fields`, `sha`, optional `path`), triggering `ERR_UNEXPECTED_ARGUMENT` fail-closed denials when any new official argument key is supplied.
   - `github.add_issue_comment`, `github.issue_read`, `github.issue_write`, and `github.pull_request_read` have no adapters at all.
5. **See [`docs/github_tool_mapping.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/github_tool_mapping.md)** for the complete 46-tool policy, capability, taint-class (`U`/`P`/`T`), and C6 breakage table.
