# Taint Sources Audit (Pre-Execution Specification)

**Date:** 2026-11-04  
**Status:** Pre-registered audit and classification of tools across all test fixtures (`tests/fixtures/*.tools.json`) against active taint source configurations in `C2` / `E3`.  
**Classification Taxonomy:**
- **`U` (Untrusted Content):** The tool can return text, comments, markdown, or data authored or influenced by external third parties across the network or repositories.
- **`P` (Private Data):** The tool can read confidential local files, keys, environment variables, or private operational data when invoked with sensitive path arguments.
- **`T` (Neither / Clean / Structural):** The tool performs local structural queries, directory enumeration, metadata checks, or state modification without returning third-party text or reading file contents.

---

## 1. Comprehensive Tool Audit and Classification

### A. HTTP & Fetch Tools (`tests/fixtures/fetch.tools.json`)

| Tool Identifier | Classification | One-Line Justification |
|---|---|---|
| `fetch.fetch` | **`U`** | Ingests arbitrary remote HTTP/HTTPS response bodies and markdown authored by external web servers. |

### B. Filesystem Tools (`tests/fixtures/filesystem.tools.json`)

| Tool Identifier | Classification | One-Line Justification |
|---|---|---|
| `filesystem.read_file` | **`P`** | Reads complete file contents as text, exposing private credentials or keys if targeted at sensitive file paths. |
| `filesystem.read_text_file` | **`P`** | Reads single-file text contents with line offsets, exposing sensitive secrets or configuration when targeting private paths. |
| `filesystem.read_media_file` | **`P`** | Reads file as base64-encoded binary or media block, exposing private binary secrets or credentials on sensitive paths. |
| `filesystem.read_multiple_files` | **`P`** | Reads multiple files simultaneously in batch, exposing private data if any requested path targets sensitive patterns. |
| `filesystem.write_file` | **`T`** | Filesystem write sink that creates or overwrites file content; does not ingest third-party text or return private data. |
| `filesystem.edit_file` | **`T`** | Filesystem mutation sink that performs targeted line replacements; returns operational diff without exposing private data. |
| `filesystem.create_directory` | **`T`** | Structural directory creation operation that modifies filesystem state without reading or returning content. |
| `filesystem.list_directory` | **`T`** | Enumerates directory entries returning only filenames and directory markers without reading file content. |
| `filesystem.list_directory_with_sizes` | **`T`** | Enumerates directory entries returning filenames and byte sizes without reading or exposing file content. |
| `filesystem.directory_tree` | **`T`** | Recursively traverses directory hierarchy returning tree structure metadata without reading file content. |
| `filesystem.move_file` | **`T`** | Relocates or renames files on disk without returning file contents or external third-party data. |
| `filesystem.search_files` | **`T`** | Matches local filenames against glob patterns returning path names without reading file contents. |
| `filesystem.get_file_info` | **`T`** | Queries filesystem inode metadata (size, timestamps, permissions) without reading file content. |
| `filesystem.list_allowed_directories` | **`T`** | Returns static configured server sandbox root paths without reading or returning external data. |

### C. GitHub Integration Tools (`tests/fixtures/github.tools.json`)

| Tool Identifier | Classification | One-Line Justification |
|---|---|---|
| `github.get_issue` | **`U`** | Returns issue titles, descriptions, and discussion comments authored by arbitrary GitHub users. |
| `github.get_pull_request` | **`U`** | Returns pull request metadata, descriptions, review comments, and branch diffs authored by remote contributors. |
| `github.get_file_contents` | **`U`** | Retrieves repository source code, documentation, or config files authored by remote project collaborators. |
| `github.list_issues` | **`U`** | Returns filtered lists of repository issue summaries and bodies authored by public third parties. |
| `github.list_pull_requests` | **`U`** | Returns filtered lists of pull request titles, descriptions, and user discussions authored by external contributors. |
| `github.search_repositories` | **`U`** | Returns repository names, descriptions, and indexed README snippets authored by external GitHub accounts. |
| `github.search_code` | **`U`** | Returns source code excerpts and matching file content authored by third-party GitHub repository owners. |
| `github.search_issues` | **`U`** | Returns search match excerpts across issues and pull requests authored by public repository users. |

---

## 2. Comparison Against C2 / E3 Baseline Configurations

In the `C2` and `E3` baseline configurations, `taint_sources` were declared as:

```yaml
taint_sources:
  private_data:
    - tool: fs.read_file
      args: { path: ["**/.env*", "**/id_rsa*", "**/*secret*", "**/*credential*", "**/database.yml*", "**/auth.json*", "**/customers.csv*", "**/signing_key*", "**/api_keys*"] }
    - tool: filesystem.read_file
      args: { path: ["**/.env*", "**/id_rsa*", "**/*secret*", "**/*credential*", "**/database.yml*", "**/auth.json*", "**/customers.csv*", "**/signing_key*", "**/api_keys*"] }
  untrusted_content:
    - tool: github.get_issue
    - tool: github.search_repositories
    - tool: fetch.fetch
    - tool: http.fetch
```

### 3. Taint Source Gap List

Comparing the audit classification against `C2` / `E3` reveals the following critical omissions:

1. **Untrusted Content Gaps (`U`):**
   - **`github.list_issues`**: Omitted in C2/E3. Directly causes false negatives or missed taint tracking in batch triage workflows (e.g., `BENIGN-42`).
   - **`github.get_pull_request`**: Omitted in C2/E3. Untrusted PR comments or descriptions can bypass taint tracking.
   - **`github.get_file_contents`**: Omitted in C2/E3. Remote repository content ingested without taint labeling.
   - **`github.list_pull_requests`**: Omitted in C2/E3. PR listings contain third-party text.
   - **`github.search_code`**: Omitted in C2/E3. Code search matches contain third-party repository code.
   - **`github.search_issues`**: Omitted in C2/E3. Issue search matches contain third-party user text.

2. **Private Data Gaps (`P`):**
   - **`filesystem.read_text_file` / `fs.read_text_file`**: Omitted in C2/E3. Modern text reading tool is unmonitored for private paths.
   - **`filesystem.read_media_file` / `fs.read_media_file`**: Omitted in C2/E3. Binary/media read tool is unmonitored for private paths.
   - **`filesystem.read_multiple_files` / `fs.read_multiple_files`**: Omitted in C2/E3. Batch file read tool is unmonitored for private paths.

---

## 4. Audited Configuration `C5.yaml`

To remediate these gaps, `benchmark/configs/C5.yaml` is defined as `E3` extended with the complete set of audited `taint_sources`:
- All 8 `github.*` read tools and `fetch` tools labeled under `untrusted_content`.
- All `filesystem.*` and `fs.*` read tools (`read_file`, `read_text_file`, `read_media_file`, `read_multiple_files`) mapped under `private_data` with standard private path patterns.

---

## 5. File-Origin Taint Specification (Chunk 5.17c Experiment)

### The File-Origin Rule
A file is classified as **`U` (Untrusted Content)** upon read if either of the following conditions holds:
1. **Third-Party Dependency Directories:** It lives in a directory the project did not author (`**/node_modules/**`, `**/vendor/**`, `**/.venv/**`, `**/site-packages/**`, `**/downloads/**`). Third-party package archives and dependencies may contain prompt injection attacks, malicious documentation, or untrusted code comments.
2. **Agent Scratch Output Directories:** It lives in a directory the agent itself writes scratch output to (`sandbox/notes/**`), since agent-written text may carry injected content or persistent attacker instructions originating from earlier sessions.

### Application in Configuration `E5.yaml`
In `E5.yaml`, filesystem read tools (`fs.read_file`, `fs.read_text_file`, `fs.read_multiple_files`, `filesystem.read_file`, `filesystem.read_text_file`, `filesystem.read_multiple_files`) are registered as `untrusted_content` taint sources when reading paths matching:
- `**/node_modules/**`
- `**/vendor/**`
- `**/.venv/**`
- `**/site-packages/**`
- `**/downloads/**`
- `sandbox/notes/**`
- `**/sandbox/notes/**`
