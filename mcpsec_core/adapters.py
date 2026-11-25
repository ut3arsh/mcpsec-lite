"""Argument adapters and tool schemas for mcpsec-lite.

Provides registry of tool identifiers (<server>.<tool>) to argument schemas
for strict argument validation, path constraints, and domain constraints.
Also provides pure tool name mapping between agent-exposed (<server>__<tool>)
and policy (<server>.<tool>) formats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

# Allowed server name regex: lowercase alpha prefix, then alphanumeric or hyphen
SERVER_NAME_REGEX = re.compile(r"^[a-z][a-z0-9-]*$")

# MCP tool name charset: alphanumeric, underscore, hyphen, max 64 chars
EXPOSED_TOOL_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class ToolNameMappingError(ValueError):
    """Raised when tool name encoding or decoding fails validation."""


def encode_tool_name(server: str, tool: str) -> str:
    """Encode an upstream server name and tool name into an agent-exposed tool name.

    Exposed format: <server>__<tool>

    Validations (fail-closed):
    - server must match ^[a-z][a-z0-9-]*$
    - server must not contain '.' or '__'
    - tool must not be empty
    - exposed name must be <= 64 characters
    - exposed name must match ^[a-zA-Z0-9_-]+$
    """
    if not isinstance(server, str) or not isinstance(tool, str):
        raise ToolNameMappingError("Server and tool must be strings")

    if not SERVER_NAME_REGEX.match(server) or "." in server or "__" in server:
        raise ToolNameMappingError(
            f"Invalid server name '{server}': must match ^[a-z][a-z0-9-]*$ and not contain '.' or '__'"
        )

    if not tool:
        raise ToolNameMappingError("Tool name cannot be empty")

    exposed = f"{server}__{tool}"
    if len(exposed) > 64:
        raise ToolNameMappingError(
            f"Exposed tool name '{exposed}' exceeds maximum length of 64 characters ({len(exposed)})"
        )

    if not EXPOSED_TOOL_NAME_REGEX.match(exposed):
        raise ToolNameMappingError(
            f"Exposed tool name '{exposed}' contains forbidden characters; must match ^[a-zA-Z0-9_-]+$"
        )

    return exposed


def decode_tool_name(exposed_name: str) -> tuple[str, str]:
    """Decode an agent-exposed tool name (<server>__<tool>) into (server, tool).

    Fails closed on missing or multiple separators, invalid characters, or over-length names.
    """
    if not isinstance(exposed_name, str):
        raise ToolNameMappingError(
            f"Exposed tool name must be a string, got {type(exposed_name).__name__}"
        )

    if len(exposed_name) > 64:
        raise ToolNameMappingError(
            f"Exposed tool name '{exposed_name}' exceeds 64 characters ({len(exposed_name)})"
        )

    if not EXPOSED_TOOL_NAME_REGEX.match(exposed_name):
        raise ToolNameMappingError(
            f"Exposed tool name '{exposed_name}' contains invalid characters"
        )

    if "__" not in exposed_name:
        raise ToolNameMappingError(
            f"Exposed tool name '{exposed_name}' missing '__' server separator"
        )

    parts = exposed_name.split("__")
    if len(parts) != 2:
        raise ToolNameMappingError(
            f"Exposed tool name '{exposed_name}' has ambiguous multiple '__' separators"
        )

    server, tool = parts[0], parts[1]
    if not SERVER_NAME_REGEX.match(server) or not tool:
        raise ToolNameMappingError(
            f"Invalid server '{server}' or empty tool in exposed name '{exposed_name}'"
        )

    return server, tool


@dataclass(frozen=True)
class ToolAdapter:
    """Declared argument mapping and strict argument schema for a tool."""

    tool_id: str
    path_args: tuple[str, ...] = ()
    domain_args: tuple[str, ...] = ()
    all_args: frozenset[str] = frozenset()


@dataclass(frozen=True)
class OfficialGitHubToolSpec:
    """Reviewed static specification for an official github/github-mcp-server v2.3.0 tool."""

    tool_id: str
    adapter: ToolAdapter
    capabilities: tuple[str, ...]
    taint_class: Literal["U", "P", "T"]
    read_only: bool


# Reviewed pure-data table for all 46 default tools in tests/fixtures/github.tools.official.json
# Capabilities and U/P/T taint classes taken strictly from docs/github_tool_mapping.md (ADR-020).
# Anything not in this table stays unknown and denied by default policy (fail closed).
OFFICIAL_GITHUB_TOOL_TABLE: dict[str, OfficialGitHubToolSpec] = {
    "add_comment_to_pending_review": OfficialGitHubToolSpec(
        tool_id="github.add_comment_to_pending_review",
        adapter=ToolAdapter(
            tool_id="github.add_comment_to_pending_review",
            all_args=frozenset(
                {
                    "body",
                    "line",
                    "owner",
                    "path",
                    "pullNumber",
                    "repo",
                    "side",
                    "startLine",
                    "startSide",
                    "subjectType",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "add_issue_comment": OfficialGitHubToolSpec(
        tool_id="github.add_issue_comment",
        adapter=ToolAdapter(
            tool_id="github.add_issue_comment",
            all_args=frozenset({"body", "comment_id", "issue_number", "owner", "reaction", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "add_reply_to_pull_request_comment": OfficialGitHubToolSpec(
        tool_id="github.add_reply_to_pull_request_comment",
        adapter=ToolAdapter(
            tool_id="github.add_reply_to_pull_request_comment",
            all_args=frozenset({"body", "commentId", "owner", "pullNumber", "reaction", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "assign_copilot_to_issue": OfficialGitHubToolSpec(
        tool_id="github.assign_copilot_to_issue",
        adapter=ToolAdapter(
            tool_id="github.assign_copilot_to_issue",
            all_args=frozenset(
                {"base_ref", "custom_instructions", "issue_number", "owner", "repo"}
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "create_branch": OfficialGitHubToolSpec(
        tool_id="github.create_branch",
        adapter=ToolAdapter(
            tool_id="github.create_branch",
            all_args=frozenset({"branch", "from_branch", "owner", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "create_or_update_file": OfficialGitHubToolSpec(
        tool_id="github.create_or_update_file",
        adapter=ToolAdapter(
            tool_id="github.create_or_update_file",
            all_args=frozenset(
                {
                    "allow_symlink_write",
                    "branch",
                    "content",
                    "message",
                    "owner",
                    "path",
                    "repo",
                    "sha",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "create_pull_request": OfficialGitHubToolSpec(
        tool_id="github.create_pull_request",
        adapter=ToolAdapter(
            tool_id="github.create_pull_request",
            all_args=frozenset(
                {
                    "base",
                    "body",
                    "draft",
                    "head",
                    "maintainer_can_modify",
                    "owner",
                    "repo",
                    "reviewers",
                    "title",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "create_repository": OfficialGitHubToolSpec(
        tool_id="github.create_repository",
        adapter=ToolAdapter(
            tool_id="github.create_repository",
            all_args=frozenset({"autoInit", "description", "name", "organization", "private"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "delete_file": OfficialGitHubToolSpec(
        tool_id="github.delete_file",
        adapter=ToolAdapter(
            tool_id="github.delete_file",
            all_args=frozenset({"branch", "message", "owner", "path", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "fork_repository": OfficialGitHubToolSpec(
        tool_id="github.fork_repository",
        adapter=ToolAdapter(
            tool_id="github.fork_repository",
            all_args=frozenset({"organization", "owner", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "get_commit": OfficialGitHubToolSpec(
        tool_id="github.get_commit",
        adapter=ToolAdapter(
            tool_id="github.get_commit",
            all_args=frozenset({"detail", "owner", "page", "perPage", "repo", "sha"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "get_file_contents": OfficialGitHubToolSpec(
        tool_id="github.get_file_contents",
        adapter=ToolAdapter(
            tool_id="github.get_file_contents",
            all_args=frozenset({"fields", "owner", "path", "ref", "repo", "sha"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "get_label": OfficialGitHubToolSpec(
        tool_id="github.get_label",
        adapter=ToolAdapter(
            tool_id="github.get_label",
            all_args=frozenset({"name", "owner", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "get_latest_release": OfficialGitHubToolSpec(
        tool_id="github.get_latest_release",
        adapter=ToolAdapter(
            tool_id="github.get_latest_release",
            all_args=frozenset({"owner", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "get_me": OfficialGitHubToolSpec(
        tool_id="github.get_me",
        adapter=ToolAdapter(
            tool_id="github.get_me",
            all_args=frozenset(),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "get_release_by_tag": OfficialGitHubToolSpec(
        tool_id="github.get_release_by_tag",
        adapter=ToolAdapter(
            tool_id="github.get_release_by_tag",
            all_args=frozenset({"owner", "repo", "tag"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "get_tag": OfficialGitHubToolSpec(
        tool_id="github.get_tag",
        adapter=ToolAdapter(
            tool_id="github.get_tag",
            all_args=frozenset({"owner", "repo", "tag"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "get_team_members": OfficialGitHubToolSpec(
        tool_id="github.get_team_members",
        adapter=ToolAdapter(
            tool_id="github.get_team_members",
            all_args=frozenset({"org", "team_slug"}),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "get_teams": OfficialGitHubToolSpec(
        tool_id="github.get_teams",
        adapter=ToolAdapter(
            tool_id="github.get_teams",
            all_args=frozenset({"user"}),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "issue_read": OfficialGitHubToolSpec(
        tool_id="github.issue_read",
        adapter=ToolAdapter(
            tool_id="github.issue_read",
            all_args=frozenset({"issue_number", "method", "owner", "page", "perPage", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "issue_write": OfficialGitHubToolSpec(
        tool_id="github.issue_write",
        adapter=ToolAdapter(
            tool_id="github.issue_write",
            all_args=frozenset(
                {
                    "assignees",
                    "body",
                    "duplicate_of",
                    "issue_fields",
                    "issue_number",
                    "labels",
                    "method",
                    "milestone",
                    "owner",
                    "parent_issue_number",
                    "parent_owner",
                    "parent_repo",
                    "repo",
                    "state",
                    "state_reason",
                    "title",
                    "type",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "list_branches": OfficialGitHubToolSpec(
        tool_id="github.list_branches",
        adapter=ToolAdapter(
            tool_id="github.list_branches",
            all_args=frozenset({"owner", "page", "perPage", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "list_commits": OfficialGitHubToolSpec(
        tool_id="github.list_commits",
        adapter=ToolAdapter(
            tool_id="github.list_commits",
            all_args=frozenset(
                {
                    "author",
                    "fields",
                    "owner",
                    "page",
                    "path",
                    "perPage",
                    "repo",
                    "sha",
                    "since",
                    "until",
                }
            ),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "list_issue_fields": OfficialGitHubToolSpec(
        tool_id="github.list_issue_fields",
        adapter=ToolAdapter(
            tool_id="github.list_issue_fields",
            all_args=frozenset({"owner", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "list_issue_types": OfficialGitHubToolSpec(
        tool_id="github.list_issue_types",
        adapter=ToolAdapter(
            tool_id="github.list_issue_types",
            all_args=frozenset({"owner", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "list_issues": OfficialGitHubToolSpec(
        tool_id="github.list_issues",
        adapter=ToolAdapter(
            tool_id="github.list_issues",
            all_args=frozenset(
                {
                    "after",
                    "direction",
                    "field_filters",
                    "fields",
                    "labels",
                    "orderBy",
                    "owner",
                    "perPage",
                    "repo",
                    "since",
                    "state",
                }
            ),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "list_pull_requests": OfficialGitHubToolSpec(
        tool_id="github.list_pull_requests",
        adapter=ToolAdapter(
            tool_id="github.list_pull_requests",
            all_args=frozenset(
                {
                    "base",
                    "direction",
                    "fields",
                    "head",
                    "owner",
                    "page",
                    "perPage",
                    "repo",
                    "sort",
                    "state",
                }
            ),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "list_releases": OfficialGitHubToolSpec(
        tool_id="github.list_releases",
        adapter=ToolAdapter(
            tool_id="github.list_releases",
            all_args=frozenset({"fields", "owner", "page", "perPage", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "list_repository_collaborators": OfficialGitHubToolSpec(
        tool_id="github.list_repository_collaborators",
        adapter=ToolAdapter(
            tool_id="github.list_repository_collaborators",
            all_args=frozenset({"affiliation", "owner", "page", "perPage", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "list_tags": OfficialGitHubToolSpec(
        tool_id="github.list_tags",
        adapter=ToolAdapter(
            tool_id="github.list_tags",
            all_args=frozenset({"owner", "page", "perPage", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="T",
        read_only=True,
    ),
    "merge_pull_request": OfficialGitHubToolSpec(
        tool_id="github.merge_pull_request",
        adapter=ToolAdapter(
            tool_id="github.merge_pull_request",
            all_args=frozenset(
                {
                    "commit_message",
                    "commit_title",
                    "expectedHeadSha",
                    "merge_method",
                    "owner",
                    "pullNumber",
                    "repo",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "pull_request_read": OfficialGitHubToolSpec(
        tool_id="github.pull_request_read",
        adapter=ToolAdapter(
            tool_id="github.pull_request_read",
            all_args=frozenset(
                {"after", "method", "owner", "page", "perPage", "pullNumber", "repo"}
            ),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "pull_request_review_write": OfficialGitHubToolSpec(
        tool_id="github.pull_request_review_write",
        adapter=ToolAdapter(
            tool_id="github.pull_request_review_write",
            all_args=frozenset(
                {
                    "body",
                    "commitID",
                    "event",
                    "method",
                    "owner",
                    "pullNumber",
                    "repo",
                    "resolutionReason",
                    "threadId",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "push_files": OfficialGitHubToolSpec(
        tool_id="github.push_files",
        adapter=ToolAdapter(
            tool_id="github.push_files",
            all_args=frozenset({"branch", "files", "message", "owner", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "request_copilot_review": OfficialGitHubToolSpec(
        tool_id="github.request_copilot_review",
        adapter=ToolAdapter(
            tool_id="github.request_copilot_review",
            all_args=frozenset({"owner", "pullNumber", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "search_code": OfficialGitHubToolSpec(
        tool_id="github.search_code",
        adapter=ToolAdapter(
            tool_id="github.search_code",
            all_args=frozenset({"fields", "order", "page", "perPage", "query", "sort"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "search_commits": OfficialGitHubToolSpec(
        tool_id="github.search_commits",
        adapter=ToolAdapter(
            tool_id="github.search_commits",
            all_args=frozenset({"order", "page", "perPage", "query", "sort"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "search_issues": OfficialGitHubToolSpec(
        tool_id="github.search_issues",
        adapter=ToolAdapter(
            tool_id="github.search_issues",
            all_args=frozenset(
                {"fields", "order", "owner", "page", "perPage", "query", "repo", "sort"}
            ),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "search_pull_requests": OfficialGitHubToolSpec(
        tool_id="github.search_pull_requests",
        adapter=ToolAdapter(
            tool_id="github.search_pull_requests",
            all_args=frozenset(
                {"fields", "order", "owner", "page", "perPage", "query", "repo", "sort"}
            ),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "search_repositories": OfficialGitHubToolSpec(
        tool_id="github.search_repositories",
        adapter=ToolAdapter(
            tool_id="github.search_repositories",
            all_args=frozenset({"minimal_output", "order", "page", "perPage", "query", "sort"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "search_users": OfficialGitHubToolSpec(
        tool_id="github.search_users",
        adapter=ToolAdapter(
            tool_id="github.search_users",
            all_args=frozenset({"order", "page", "perPage", "query", "sort"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "sub_issue_write": OfficialGitHubToolSpec(
        tool_id="github.sub_issue_write",
        adapter=ToolAdapter(
            tool_id="github.sub_issue_write",
            all_args=frozenset(
                {
                    "after_id",
                    "before_id",
                    "issue_number",
                    "method",
                    "owner",
                    "replace_parent",
                    "repo",
                    "sub_issue_id",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "ui_get": OfficialGitHubToolSpec(
        tool_id="github.ui_get",
        adapter=ToolAdapter(
            tool_id="github.ui_get",
            all_args=frozenset({"method", "owner", "repo"}),
        ),
        capabilities=("network_read",),
        taint_class="U",
        read_only=True,
    ),
    "update_issue_comment": OfficialGitHubToolSpec(
        tool_id="github.update_issue_comment",
        adapter=ToolAdapter(
            tool_id="github.update_issue_comment",
            all_args=frozenset({"body", "comment_id", "owner", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "update_pull_request": OfficialGitHubToolSpec(
        tool_id="github.update_pull_request",
        adapter=ToolAdapter(
            tool_id="github.update_pull_request",
            all_args=frozenset(
                {
                    "base",
                    "body",
                    "draft",
                    "maintainer_can_modify",
                    "owner",
                    "pullNumber",
                    "repo",
                    "reviewers",
                    "state",
                    "title",
                }
            ),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
    "update_pull_request_branch": OfficialGitHubToolSpec(
        tool_id="github.update_pull_request_branch",
        adapter=ToolAdapter(
            tool_id="github.update_pull_request_branch",
            all_args=frozenset({"expectedHeadSha", "owner", "pullNumber", "repo"}),
        ),
        capabilities=("write", "egress"),
        taint_class="T",
        read_only=False,
    ),
}


def get_official_github_tool_spec(tool_name: str) -> OfficialGitHubToolSpec | None:
    """Return the reviewed official GitHub v2.3.0 specification for an upstream tool name."""
    clean_name = tool_name.removeprefix("github.")
    return OFFICIAL_GITHUB_TOOL_TABLE.get(clean_name)


# Built-in adapter registry mapping <server>.<tool> -> ToolAdapter
_BUILTIN_ADAPTERS: dict[str, ToolAdapter] = {
    # Filesystem tools ('fs' prefix)
    "fs.read_file": ToolAdapter(
        tool_id="fs.read_file",
        path_args=("path",),
        all_args=frozenset({"path", "tail", "head"}),
    ),
    "fs.read_text_file": ToolAdapter(
        tool_id="fs.read_text_file",
        path_args=("path",),
        all_args=frozenset({"path", "tail", "head"}),
    ),
    "fs.read_media_file": ToolAdapter(
        tool_id="fs.read_media_file",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "fs.read_multiple_files": ToolAdapter(
        tool_id="fs.read_multiple_files",
        all_args=frozenset({"paths"}),
    ),
    "fs.write_file": ToolAdapter(
        tool_id="fs.write_file",
        path_args=("path",),
        all_args=frozenset({"path", "content"}),
    ),
    "fs.edit_file": ToolAdapter(
        tool_id="fs.edit_file",
        path_args=("path",),
        all_args=frozenset({"path", "edits", "dryRun"}),
    ),
    "fs.create_directory": ToolAdapter(
        tool_id="fs.create_directory",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "fs.list_directory": ToolAdapter(
        tool_id="fs.list_directory",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "fs.directory_list": ToolAdapter(
        tool_id="fs.directory_list",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "fs.list_directory_with_sizes": ToolAdapter(
        tool_id="fs.list_directory_with_sizes",
        path_args=("path",),
        all_args=frozenset({"path", "sortBy"}),
    ),
    "fs.directory_tree": ToolAdapter(
        tool_id="fs.directory_tree",
        path_args=("path",),
        all_args=frozenset({"path", "excludePatterns"}),
    ),
    "fs.move_file": ToolAdapter(
        tool_id="fs.move_file",
        path_args=("source", "destination"),
        all_args=frozenset({"source", "destination"}),
    ),
    "fs.copy_file": ToolAdapter(
        tool_id="fs.copy_file",
        path_args=("source", "destination"),
        all_args=frozenset({"source", "destination"}),
    ),
    "fs.search_files": ToolAdapter(
        tool_id="fs.search_files",
        path_args=("path",),
        all_args=frozenset({"path", "pattern", "excludePatterns"}),
    ),
    "fs.get_file_info": ToolAdapter(
        tool_id="fs.get_file_info",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "fs.list_allowed_directories": ToolAdapter(
        tool_id="fs.list_allowed_directories",
        all_args=frozenset(),
    ),
    # Filesystem tools ('filesystem' prefix)
    "filesystem.read_file": ToolAdapter(
        tool_id="filesystem.read_file",
        path_args=("path",),
        all_args=frozenset({"path", "tail", "head"}),
    ),
    "filesystem.read_text_file": ToolAdapter(
        tool_id="filesystem.read_text_file",
        path_args=("path",),
        all_args=frozenset({"path", "tail", "head"}),
    ),
    "filesystem.read_media_file": ToolAdapter(
        tool_id="filesystem.read_media_file",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "filesystem.read_multiple_files": ToolAdapter(
        tool_id="filesystem.read_multiple_files",
        all_args=frozenset({"paths"}),
    ),
    "filesystem.write_file": ToolAdapter(
        tool_id="filesystem.write_file",
        path_args=("path",),
        all_args=frozenset({"path", "content"}),
    ),
    "filesystem.edit_file": ToolAdapter(
        tool_id="filesystem.edit_file",
        path_args=("path",),
        all_args=frozenset({"path", "edits", "dryRun"}),
    ),
    "filesystem.create_directory": ToolAdapter(
        tool_id="filesystem.create_directory",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "filesystem.list_directory": ToolAdapter(
        tool_id="filesystem.list_directory",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "filesystem.directory_list": ToolAdapter(
        tool_id="filesystem.directory_list",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "filesystem.list_directory_with_sizes": ToolAdapter(
        tool_id="filesystem.list_directory_with_sizes",
        path_args=("path",),
        all_args=frozenset({"path", "sortBy"}),
    ),
    "filesystem.directory_tree": ToolAdapter(
        tool_id="filesystem.directory_tree",
        path_args=("path",),
        all_args=frozenset({"path", "excludePatterns"}),
    ),
    "filesystem.move_file": ToolAdapter(
        tool_id="filesystem.move_file",
        path_args=("source", "destination"),
        all_args=frozenset({"source", "destination"}),
    ),
    "filesystem.copy_file": ToolAdapter(
        tool_id="filesystem.copy_file",
        path_args=("source", "destination"),
        all_args=frozenset({"source", "destination"}),
    ),
    "filesystem.search_files": ToolAdapter(
        tool_id="filesystem.search_files",
        path_args=("path",),
        all_args=frozenset({"path", "pattern", "excludePatterns"}),
    ),
    "filesystem.get_file_info": ToolAdapter(
        tool_id="filesystem.get_file_info",
        path_args=("path",),
        all_args=frozenset({"path"}),
    ),
    "filesystem.list_allowed_directories": ToolAdapter(
        tool_id="filesystem.list_allowed_directories",
        all_args=frozenset(),
    ),
    # HTTP & Fetch tools
    "fetch.fetch": ToolAdapter(
        tool_id="fetch.fetch",
        domain_args=("url",),
        all_args=frozenset({"url", "max_length", "start_index", "raw"}),
    ),
    "http.fetch": ToolAdapter(
        tool_id="http.fetch",
        domain_args=("url",),
        all_args=frozenset({"url", "max_length", "start_index", "raw", "headers"}),
    ),
    "http.get": ToolAdapter(
        tool_id="http.get",
        domain_args=("url",),
        all_args=frozenset({"url", "headers", "params"}),
    ),
    "http.post": ToolAdapter(
        tool_id="http.post",
        domain_args=("url",),
        all_args=frozenset({"url", "headers", "body", "json"}),
    ),
    # Official github/github-mcp-server v2.3.0 tools (from reviewed static table)
    **{spec.adapter.tool_id: spec.adapter for spec in OFFICIAL_GITHUB_TOOL_TABLE.values()},
    # Shell & Email
    "email.send": ToolAdapter(
        tool_id="email.send",
        all_args=frozenset({"to", "subject", "body"}),
    ),
    "shell.exec": ToolAdapter(
        tool_id="shell.exec",
        all_args=frozenset({"command", "args", "cwd", "env"}),
    ),
}


def get_adapter(tool_id: str) -> ToolAdapter | None:
    """Retrieve the ToolAdapter for a tool_id (<server>.<tool>)."""
    return _BUILTIN_ADAPTERS.get(tool_id)


def register_adapter(adapter: ToolAdapter) -> None:
    """Register or override a custom ToolAdapter."""
    _BUILTIN_ADAPTERS[adapter.tool_id] = adapter


def validate_tool_adapter_for_constraints(
    tool_id: str,
    has_path_constraint: bool,
    has_domain_constraint: bool,
) -> tuple[bool, str | None]:
    """Check if the tool has an adapter supporting the declared constraints (Rule 8).

    Returns (is_valid, error_message).
    """
    adapter = get_adapter(tool_id)
    if not adapter:
        if has_path_constraint or has_domain_constraint:
            return False, f"Tool '{tool_id}' has constraints but no registered argument adapter"
        return True, None

    if has_path_constraint and not adapter.path_args:
        return False, f"Tool '{tool_id}' declares path_allowlist but adapter has no path arguments"

    if has_domain_constraint and not adapter.domain_args:
        return (
            False,
            f"Tool '{tool_id}' declares domain_allowlist but adapter has no domain arguments",
        )

    return True, None


def validate_unexpected_arguments(
    tool_id: str,
    args: dict[str, Any],
) -> tuple[bool, str | None]:
    """Verify that all arguments passed to a tool are declared in its adapter.

    Fail-closed:
    If tool has an adapter with all_args declared, any key not in all_args is rejected
    with ERR_UNEXPECTED_ARGUMENT.
    """
    adapter = get_adapter(tool_id)
    if not adapter or not adapter.all_args:
        return True, None

    for k in args:
        if k not in adapter.all_args:
            return False, f"ERR_UNEXPECTED_ARGUMENT: unexpected argument '{k}' for tool '{tool_id}'"

    return True, None


def extract_path_arguments(
    tool_id: str,
    args: dict[str, Any],
) -> tuple[bool, list[str], str | None]:
    """Extract and validate path arguments from tool call args."""
    adapter = get_adapter(tool_id)
    if not adapter or not adapter.path_args:
        return True, [], None

    extracted: list[str] = []
    for arg_name in adapter.path_args:
        if arg_name not in args:
            return False, [], f"Missing expected path argument '{arg_name}'"
        val = args[arg_name]
        if not isinstance(val, str):
            return (
                False,
                [],
                f"Path argument '{arg_name}' must be a string, got {type(val).__name__}",
            )
        extracted.append(val)

    return True, extracted, None


def extract_domain_arguments(
    tool_id: str,
    args: dict[str, Any],
) -> tuple[bool, list[str], str | None]:
    """Extract and validate domain/URL arguments from tool call args."""
    adapter = get_adapter(tool_id)
    if not adapter or not adapter.domain_args:
        return True, [], None

    extracted: list[str] = []
    for arg_name in adapter.domain_args:
        if arg_name not in args:
            return False, [], f"Missing expected URL argument '{arg_name}'"
        val = args[arg_name]
        if not isinstance(val, str):
            return (
                False,
                [],
                f"URL argument '{arg_name}' must be a string, got {type(val).__name__}",
            )
        extracted.append(val)

    return True, extracted, None
