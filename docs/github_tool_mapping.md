# Official GitHub MCP Server (`v2.3.0`) Tool Mapping & C6 Breakage Audit

**Source Snapshot:** [`tests/fixtures/github.tools.official.json`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/fixtures/github.tools.official.json)  
**Server Release:** `github/github-mcp-server` `v2.3.0` (commit `c6b62954c062b3ad779f4e208716e09cb4a723e0`, flags `["stdio"]`, 46 default tools; 27 under `--read-only`)  
**C6 Policy Baseline:** [`benchmark/configs/C6.yaml`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/benchmark/configs/C6.yaml) + [`mcpsec_core/adapters.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/mcpsec_core/adapters.py)  

> **Scope Statement (Documentation Only):** Zero changes were made to `C6.yaml`, `mcpsec_core/adapters.py`, taint rules, or benchmark scenarios. In the dev benchmark, fake/scripted GitHub calls target the 8-tool handwritten schema (`tests/fixtures/github.tools.json`) plus `create_issue_comment`. This document specifies the exact mapping and identifies every C6 rule that breaks against the official Go server binary.

---

## 1. Taxonomy & Policy Legend

- **Taint Class (per [`docs/taint_sources_audit.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/taint_sources_audit.md)):**
  - **`U` (Untrusted Content):** Returns text, markdown, titles, bodies, commit messages, diff content, code excerpts, comments, labels, or user-authored metadata from external repositories/issues/PRs/discussions.
  - **`P` (Private Data):** Reads confidential local files, keys, credentials, or sensitive private operational identity/data (note: none of the GitHub remote tools read local files, though `get_me` / `get_teams` / `get_team_members` read authenticated account/org membership if targeting private orgs; classified `T` as structural metadata unless scoped `P` by private-org deployment policy).
  - **`T` (Neither / Clean / Structural / Write Sink):** Structural branch/type/field enumeration or mutating write/egress sinks that alter remote GitHub state without ingesting arbitrary third-party prompt text (note: write sinks require `[write, egress]` capabilities so C6 flow rules gate them after taint).
- **Capabilities (closed v1 set in `docs/policy_schema.md`):** `{read, write, network_read, egress, exec}`. All remote GitHub reads carry `network_read`; remote mutations/comments/Copilot assignments/PR merges carry `[write, egress]` because they transmit caller-controlled payloads to external GitHub infrastructure.

---

## 2. Complete Mapping for All 46 Official Default Tools

| Official Tool Name | `--read-only` | Target Policy ID | Recommended Capabilities | Taint Class | C6 Status & Exact Breakage (`C6.yaml` & `adapters.py`) |
|---|---|---|---|---|---|
| `add_comment_to_pending_review` | No (Write) | `github.add_comment_to_pending_review` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, and `adapters.py`; default-denied. |
| `add_issue_comment` | No (Write) | `github.add_issue_comment` | `[write, egress]` | `T` | **BREAKS (Renamed):** C6 & benchmarks declare `github.create_issue_comment`; official server uses `add_issue_comment` (with extra `comment_id`, `reaction` args). Denied by policy. |
| `add_reply_to_pull_request_comment` | No (Write) | `github.add_reply_to_pull_request_comment` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, and `adapters.py`; default-denied. |
| `assign_copilot_to_issue` | No (Write) | `github.assign_copilot_to_issue` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6; triggers external Copilot agent execution (`custom_instructions`); default-denied. |
| `create_branch` | No (Write) | `github.create_branch` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, and `adapters.py`; default-denied. |
| `create_or_update_file` | No (Write) | `github.create_or_update_file` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6; writes remote repo file (`path`, `content`); default-denied. |
| `create_pull_request` | No (Write) | `github.create_pull_request` | `[write, egress]` | `T` | **BREAKS (Policy Missing / Schema Drift):** `adapters.py` has `github.create_pull_request` (missing `reviewers` arg), but C6 omits it from `capabilities` and `policies`; default-denied. |
| `create_repository` | No (Write) | `github.create_repository` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6; creates public/private repo; default-denied. |
| `delete_file` | No (Write) | `github.delete_file` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, and `adapters.py`; default-denied. |
| `fork_repository` | No (Write) | `github.fork_repository` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, and `adapters.py`; default-denied. |
| `get_commit` | Yes (RO) | `github.get_commit` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, `taint_sources`, and `adapters.py` (commit message/diff is untrusted content). |
| `get_file_contents` | Yes (RO) | `github.get_file_contents` | `[network_read]` | **`U`** | **PARTIAL BREAK (Schema Drift):** Present in C6 (`capabilities`, `policies`, `taint_sources`), but official adds `fields`, `sha` (causing `ERR_UNEXPECTED_ARGUMENT` in `adapters.py`) and makes `path` optional for directory listings (`extract_path_arguments` would reject omitted `path` if constrained). |
| `get_label` | Yes (RO) | `github.get_label` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; label description can carry untrusted text. |
| `get_latest_release` | Yes (RO) | `github.get_latest_release` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; release notes/body are contributor/repo-author controlled (`U`). |
| `get_me` | Yes (RO) | `github.get_me` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; returns authenticated user identity metadata. |
| `get_release_by_tag` | Yes (RO) | `github.get_release_by_tag` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; release body is untrusted external text (`U`). |
| `get_tag` | Yes (RO) | `github.get_tag` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; tag annotation message is untrusted text (`U`). |
| `get_team_members` | Yes (RO) | `github.get_team_members` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; structural org team username roster. |
| `get_teams` | Yes (RO) | `github.get_teams` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; structural org team list. |
| `issue_read` | Yes (RO) | `github.issue_read` | `[network_read]` | **`U`** | **BREAKS (Renamed / Consolidated):** C6 `capabilities`, `policies`, `taint_sources`, and `adapters.py` reference `github.get_issue`; official uses `issue_read` (`method`, `page`, `perPage`). Fails closed AND lacks `U` taint source if allowlisted without updating `taint_sources`. |
| `issue_write` | No (Write) | `github.issue_write` | `[write, egress]` | `T` | **BREAKS (Missing / Replaced `create_issue`):** `adapters.py` has `github.create_issue` only (`title` req, different args); C6 omits both; default-denied. |
| `list_branches` | Yes (RO) | `github.list_branches` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; structural branch name list (conservative deployments could tag `U`). |
| `list_commits` | Yes (RO) | `github.list_commits` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, `taint_sources`, and `adapters.py`; returns commit messages authored by contributors (`U`). |
| `list_issue_fields` | Yes (RO) | `github.list_issue_fields` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; schema/field definitions metadata. |
| `list_issue_types` | Yes (RO) | `github.list_issue_types` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; structural issue type catalog. |
| `list_issues` | Yes (RO) | `github.list_issues` | `[network_read]` | **`U`** | **PARTIAL BREAK (Schema Drift):** Present in C6 (`capabilities`, `policies`, `taint_sources`), but official replaces `page`/`per_page`/`sort` with `after`/`perPage`/`orderBy` + `fields`/`field_filters`, failing `adapters.py` `ERR_UNEXPECTED_ARGUMENT`. |
| `list_pull_requests` | Yes (RO) | `github.list_pull_requests` | `[network_read]` | **`U`** | **PARTIAL BREAK (Schema Drift):** Present in C6 (`capabilities`, `policies`, `taint_sources`), but official uses `perPage` and `fields` (`ERR_UNEXPECTED_ARGUMENT`). |
| `list_releases` | Yes (RO) | `github.list_releases` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; release descriptions are untrusted text (`U`). |
| `list_repository_collaborators` | Yes (RO) | `github.list_repository_collaborators` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; collaborator username metadata. |
| `list_tags` | Yes (RO) | `github.list_tags` | `[network_read]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; tag names/SHA list metadata. |
| `merge_pull_request` | No (Write) | `github.merge_pull_request` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; merges remote code and posts commit messages; default-denied. |
| `pull_request_read` | Yes (RO) | `github.pull_request_read` | `[network_read]` | **`U`** | **BREAKS (Renamed / Consolidated):** C6 `capabilities`, `policies`, `taint_sources`, and `adapters.py` reference `github.get_pull_request`; official uses `pull_request_read` (`method`, `pullNumber`, `after`, `page`, `perPage`). Fails closed AND lacks `U` taint source! |
| `pull_request_review_write` | No (Write) | `github.pull_request_review_write` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; posts/submits PR reviews; default-denied. |
| `push_files` | No (Write) | `github.push_files` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; pushes multi-file commits; default-denied. |
| `request_copilot_review` | No (Write) | `github.request_copilot_review` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; triggers external bot review; default-denied. |
| `search_code` | Yes (RO) | `github.search_code` | `[network_read]` | **`U`** | **BREAKS (Required Param Renamed):** Official requires `query` instead of handwritten `q`, plus `perPage`, `fields`. Rejected by `adapters.py` (`ERR_UNEXPECTED_ARGUMENT`) despite `github.search_code` existing in C6. |
| `search_commits` | Yes (RO) | `github.search_commits` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 `capabilities`, `policies`, `taint_sources`, and `adapters.py`; returns public commit messages (`U`). |
| `search_issues` | Yes (RO) | `github.search_issues` | `[network_read]` | **`U`** | **BREAKS (Required Param Renamed):** Official requires `query` instead of `q`, plus `owner`, `repo`, `perPage`, `fields`. Rejected by `adapters.py` (`ERR_UNEXPECTED_ARGUMENT`). |
| `search_pull_requests` | Yes (RO) | `github.search_pull_requests` | `[network_read]` | **`U`** | **BREAKS (Missing):** Split out from `search_issues` in official server; omitted from C6 `capabilities`, `policies`, `taint_sources`, and `adapters.py`. |
| `search_repositories` | Yes (RO) | `github.search_repositories` | `[network_read]` | **`U`** | **PARTIAL BREAK (Schema Drift):** Present in C6 (`capabilities`, `policies`, `taint_sources`), but official adds `minimal_output`, `order`, `perPage`, `sort`, failing `adapters.py` `ERR_UNEXPECTED_ARGUMENT`. |
| `search_users` | Yes (RO) | `github.search_users` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; public user bio/display names are untrusted text (`U`). |
| `sub_issue_write` | No (Write) | `github.sub_issue_write` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; mutates issue links; default-denied. |
| `ui_get` | Yes (RO) | `github.ui_get` | `[network_read]` | **`U`** | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; fetches labels/milestones/assignees/issue fields for MCP Apps UI (`U` due to label/milestone descriptions). |
| `update_issue_comment` | No (Write) | `github.update_issue_comment` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; modifies issue/PR comments; default-denied. |
| `update_pull_request` | No (Write) | `github.update_pull_request` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; mutates PR title/body/state; default-denied. |
| `update_pull_request_branch` | No (Write) | `github.update_pull_request_branch` | `[write, egress]` | `T` | **BREAKS (Missing):** Omitted from C6 and `adapters.py`; merges base branch updates into PR branch; default-denied. |

---

## 3. Summary of C6 Breakage Count

- **C6 Entries Dead / Broken Against Official `github-mcp-server v2.3.0` (`3` of `9` C6 GitHub entries completely missing on official server):**
  1. `github.get_issue` $\rightarrow$ official server has `github.issue_read`
  2. `github.get_pull_request` $\rightarrow$ official server has `github.pull_request_read`
  3. `github.create_issue_comment` $\rightarrow$ official server has `github.add_issue_comment`
- **C6 Entries with Adapter Schema Drift (`6` of `9` C6 GitHub entries fail `adapters.py` strict args when official parameters are used):**
  - **Call-breaking required parameter renames:** `github.search_code` (`q` $\rightarrow$ `query`), `github.search_issues` (`q` $\rightarrow$ `query`)
  - **Pagination / field projection drift:** `github.list_issues` (`page`/`per_page`/`sort` $\rightarrow$ `after`/`perPage`/`orderBy` + `fields`/`field_filters`), `github.list_pull_requests` (`per_page` $\rightarrow$ `perPage` + `fields`), `github.search_repositories` (`per_page` $\rightarrow$ `perPage` + `minimal_output`/`order`/`sort`), `github.get_file_contents` (`path` optional + `fields`, `sha`)
- **Fail-Closed Safety Assessment:** Under C6, none of the schema drift or unmapped tools **fail open**—default-deny and `ERR_UNEXPECTED_ARGUMENT` reject unmapped/renamed tools cleanly—EXCEPT if a future policy added `github.issue_read` or `github.pull_request_read` to `policies` without simultaneously registering them in `taint_sources.untrusted_content`, reading poisoned issues/PRs would omit the `untrusted_content` taint label.
