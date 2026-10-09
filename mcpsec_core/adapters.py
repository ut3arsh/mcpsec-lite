"""Argument adapters and tool schemas for mcpsec-lite.

Provides registry of tool identifiers (<server>.<tool>) to argument schemas
for strict argument validation, path constraints, and domain constraints.
Also provides pure tool name mapping between agent-exposed (<server>__<tool>)
and policy (<server>.<tool>) formats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

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
    # GitHub tools
    "github.get_issue": ToolAdapter(
        tool_id="github.get_issue",
        all_args=frozenset({"owner", "repo", "issue_number"}),
    ),
    "github.get_pull_request": ToolAdapter(
        tool_id="github.get_pull_request",
        all_args=frozenset({"owner", "repo", "pull_number"}),
    ),
    "github.get_file_contents": ToolAdapter(
        tool_id="github.get_file_contents",
        path_args=("path",),
        all_args=frozenset({"owner", "repo", "path", "ref"}),
    ),
    "github.list_issues": ToolAdapter(
        tool_id="github.list_issues",
        all_args=frozenset(
            {"owner", "repo", "state", "labels", "sort", "direction", "since", "page", "per_page"}
        ),
    ),
    "github.list_pull_requests": ToolAdapter(
        tool_id="github.list_pull_requests",
        all_args=frozenset(
            {"owner", "repo", "state", "head", "base", "sort", "direction", "page", "per_page"}
        ),
    ),
    "github.create_issue": ToolAdapter(
        tool_id="github.create_issue",
        all_args=frozenset({"owner", "repo", "title", "body", "assignees", "labels", "milestone"}),
    ),
    "github.create_pull_request": ToolAdapter(
        tool_id="github.create_pull_request",
        all_args=frozenset(
            {"owner", "repo", "title", "body", "head", "base", "draft", "maintainer_can_modify"}
        ),
    ),
    "github.search_repositories": ToolAdapter(
        tool_id="github.search_repositories",
        all_args=frozenset({"query", "page", "per_page"}),
    ),
    "github.search_code": ToolAdapter(
        tool_id="github.search_code",
        all_args=frozenset({"q", "sort", "order", "per_page", "page"}),
    ),
    "github.search_issues": ToolAdapter(
        tool_id="github.search_issues",
        all_args=frozenset({"q", "sort", "order", "per_page", "page"}),
    ),
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
