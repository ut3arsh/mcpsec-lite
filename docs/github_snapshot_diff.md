# GitHub MCP Server: Real vs Handwritten Snapshot Diff Analysis

**Captured at:** 2026-11-11T10:09:08.932476+00:00  
**Real Server Fixture:** [`tests/fixtures/github.tools.real.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.real.json)  
**Handwritten Fixture:** [`tests/fixtures/github.tools.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.json)  
**Server Implementation:** `github-mcp-server` v0.6.2 (npm `@modelcontextprotocol/server-github` v2025.4.8)  
**Protocol Version:** `2024-11-05` (Transport: stdio, offline capture with dummy authentication token)  
**Verification Status:** `VERIFIED-real-server`  

---

## 1. Overview & Tool Inventory

| Metric | Handwritten Fixture | Real GitHub Server | Delta |
|---|---|---|---|
| Total Tools | 8 | 26 | +18 tools |
| Mutating / Write Tools | 0 | 12 | +12 tools |
| Read / Inspection Tools | 8 | 14 | +6 tools |
| Missing from Real Server | 0 | 0 | 0 (100% of handwritten tool names exist in real server) |

All 8 tools defined in the handwritten fixture exist in the official `@modelcontextprotocol/server-github` implementation with identical tool names. However, the real server exports an additional 18 tools covering write operations, pull request lifecycle management, branch creation, repository forks, and git commit history.

---

## 2. Tools Present in Real Server but Absent from Handwritten Fixture

The 18 tools present in the real server but absent from [`tests/fixtures/github.tools.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.json) fall into two categories:

### A. Mutating / Write Tools (12 tools)
These tools perform mutating state changes on GitHub repositories and issues:
1. `create_or_update_file`: Create or update a single file in a GitHub repository.
2. `push_files`: Push multiple files to a GitHub repository in a single commit.
3. `create_repository`: Create a new GitHub repository in the authenticated account.
4. `fork_repository`: Fork a GitHub repository to account or specified organization.
5. `create_branch`: Create a new branch in a GitHub repository.
6. `create_issue`: Create a new issue in a GitHub repository.
7. `update_issue`: Update an existing issue in a GitHub repository.
8. `add_issue_comment`: Add a comment to an existing issue.
9. `create_pull_request`: Create a new pull request in a GitHub repository.
10. `update_pull_request_branch`: Update a pull request branch with latest base branch changes.
11. `merge_pull_request`: Merge a pull request into its base branch.
12. `create_pull_request_review`: Create a review comment or verdict on a pull request.

### B. Read-Only / Inspection Tools (6 tools)
These tools provide additional read-only inspection surfaces:
1. `list_commits`: Get list of commits of a branch in a GitHub repository.
2. `search_users`: Search for users across GitHub.
3. `get_pull_request_files`: Get the list of files changed in a pull request.
4. `get_pull_request_status`: Get the combined status of all status checks for a pull request.
5. `get_pull_request_comments`: Get review comments on a pull request.
6. `get_pull_request_reviews`: Get reviews on a pull request.

---

## 3. Renamed and Equivalent Tools

| Operation | Benchmark / Handwritten Name | Real Server Tool Name | Status & Resolution |
|---|---|---|---|
| Post issue comment | `create_issue_comment` | `add_issue_comment` | **Renamed.** Benchmark scenarios (e.g. `ATTACK-02`) use `create_issue_comment`. Connecting to real server requires adapter translation or policy alias. |
| Read issue | `get_issue` | `get_issue` | Exact match. |
| Read file | `get_file_contents` | `get_file_contents` | Exact match (parameter nuance below). |
| List issues | `list_issues` | `list_issues` | Exact match. |
| Search code | `search_code` | `search_code` | Exact match. |
| Search repos | `search_repositories` | `search_repositories` | Exact match (parameter nuance below). |

---

## 4. Parameter Schema Comparison on Shared Tools

For the 8 shared tools, parameter schemas were compared field-by-field:

### Identical Schemas (5 tools)
- **`get_issue`**:
  - Properties: `['issue_number', 'owner', 'repo']`
  - Required: `['issue_number', 'owner', 'repo']` (Identical)
- **`get_pull_request`**:
  - Properties: `['owner', 'pull_number', 'repo']`
  - Required: `['owner', 'pull_number', 'repo']` (Identical)
- **`list_issues`**:
  - Properties: `['direction', 'labels', 'owner', 'page', 'per_page', 'repo', 'since', 'sort', 'state']`
  - Required: `['owner', 'repo']` (Identical)
- **`list_pull_requests`**:
  - Properties: `['base', 'direction', 'head', 'owner', 'page', 'per_page', 'repo', 'sort', 'state']`
  - Required: `['owner', 'repo']` (Identical)
- **`search_issues`**:
  - Properties: `['order', 'page', 'per_page', 'q', 'sort']`
  - Required: `['q']` (Identical)

### Schema Divergences (3 tools)
1. **`get_file_contents`**:
   - Handwritten properties: `['owner', 'path', 'ref', 'repo']` (Required: `['owner', 'path', 'repo']`)
   - Real properties: `['branch', 'owner', 'path', 'repo']` (Required: `['owner', 'path', 'repo']`)
   - *Difference:* Handwritten used standard GitHub REST parameter `ref` (which allows branches, tags, or commit SHAs). Real server uses `branch` parameter.
2. **`search_code`**:
   - Handwritten properties: `['order', 'page', 'per_page', 'q', 'sort']` (Required: `['q']`)
   - Real properties: `['order', 'page', 'per_page', 'q']` (Required: `['q']`)
   - *Difference:* Handwritten included optional `sort`. Real server omits `sort` property in its exposed schema.
3. **`search_repositories`**:
   - Handwritten properties: `['page', 'per_page', 'query']` (Required: `['query']`)
   - Real properties: `['page', 'perPage', 'query']` (Required: `['query']`)
   - *Difference:* Handwritten used snake_case `per_page`. Real server schema uses camelCase `perPage`.

---

## 5. Breaking Impact Assessment

Per standing rule AGENTS.md §4 and the Chunk 5.18b prompt, **benchmark configs (`benchmark/configs/*.yaml`) are not modified in this verification step**. This section evaluates the operational impact if a live deployment connects `mcpsec-lite` directly to `@modelcontextprotocol/server-github`:

### A. Policy Allowlists (`C1`–`C6`)
- **Current Config:** Allowlists in `C1`, `C2`, `C5`, and `C6` grant access to `github.get_issue`, `github.list_issues`, and `github.create_issue_comment`.
- **Impact:**
  - Read tools (`get_issue`, `list_issues`) resolve cleanly without breakage.
  - Calls to `github.create_issue_comment` fail closed under default-deny policy because the upstream tool is named `github.add_issue_comment`.
  - **Remediation for live deployment:** Upstream adapter in `proxy/` should alias `create_issue_comment` $\leftrightarrow$ `add_issue_comment`, or policy should add `github.add_issue_comment` to allowed tools.

### B. Capabilities Mapping
- **Current Mapping:** Upstream tool capabilities for github are classified as `network_read` for queries and `egress` for issue comments.
- **Impact:**
  - The 12 real mutating tools (`create_or_update_file`, `push_files`, `create_repository`, `fork_repository`, `create_branch`, `create_issue`, `update_issue`, `add_issue_comment`, `create_pull_request`, `update_pull_request_branch`, `merge_pull_request`, `create_pull_request_review`) must be mapped to capability `["write", "egress"]`.
  - Under `C6` flow rules, any of these calls following an untrusted read will properly trigger `appr-untrusted-egress` or `appr-untrusted-write` approval requirements.

### C. Taint Sources
- **Current Config:** In `benchmark/configs/C6.yaml`, `taint_sources.untrusted_content` includes:
  `github.get_issue`, `github.list_issues`, `github.get_pull_request`, `github.list_pull_requests`, `github.search_issues`, `github.search_code`, `github.search_repositories`.
- **Impact:**
  - All 7 declared taint sources match exact tool names on the real server.
  - **Gap to close on server expansion:** The real server exposes 4 additional user-content read tools: `get_pull_request_comments`, `get_pull_request_reviews`, `list_commits`, and `get_file_contents`.
  - In a full production profile, `get_pull_request_comments` and `get_pull_request_reviews` contain attacker-controllable text and must be designated as `untrusted_content` sources.

### D. Upstream Adapters & Benchmark Harness
- In the dev benchmark harness (`benchmark/dev/benchmark_dev.py`), mocked tools currently match handwritten names.
- When transitioning to live integration tests against the real server binary, the harness adapter must forward `create_issue_comment` to `add_issue_comment` and map `per_page` $\rightarrow$ `perPage` for `search_repositories`.
