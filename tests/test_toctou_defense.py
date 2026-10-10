"""Tests verifying TOCTOU defense in depth via upstream native root confinement."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import mcp.types as types
import pytest

from tests.test_server import create_test_fs_server


@pytest.mark.asyncio
async def test_upstream_filesystem_native_root_confinement_refuses_out_of_root(
    tmp_path: Path,
) -> None:
    """Test that upstream filesystem server itself refuses out-of-root paths even if proxy is bypassed."""
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    secret_dir = tmp_path / "secret_dir"
    secret_dir.mkdir()
    secret_file = secret_dir / "secret.env"
    secret_file.write_text("AWS_KEY=SECRET12345", encoding="utf-8")

    safe_file = sandbox_dir / "hello.txt"
    safe_file.write_text("hello world", encoding="utf-8")

    # Upstream server configured with allowed_dir = sandbox_dir
    server = create_test_fs_server(sandbox_dir)
    handler = server._request_handlers["tools/call"].handler

    # 1. Allowed in-root read works
    req_allowed = types.CallToolRequestParams(
        name="read_file",
        arguments={"path": "hello.txt"},
    )
    res_allowed: Any = await handler(None, req_allowed)  # type: ignore[arg-type]
    assert isinstance(res_allowed, types.CallToolResult)
    assert not res_allowed.is_error
    assert isinstance(res_allowed.content[0], types.TextContent)
    assert res_allowed.content[0].text == "hello world"

    # 2. Out-of-root escape attempt via absolute path -> refused by upstream itself
    req_denied_abs = types.CallToolRequestParams(
        name="read_file",
        arguments={"path": str(secret_file)},
    )
    res_denied_abs: Any = await handler(None, req_denied_abs)  # type: ignore[arg-type]
    assert isinstance(res_denied_abs, types.CallToolResult)
    assert res_denied_abs.is_error
    assert isinstance(res_denied_abs.content[0], types.TextContent)
    assert "Access denied: path outside allowed root" in res_denied_abs.content[0].text

    # 3. Out-of-root escape attempt via traversal .. -> refused by upstream itself
    req_denied_traversal = types.CallToolRequestParams(
        name="read_file",
        arguments={"path": "../secret_dir/secret.env"},
    )
    res_denied_traversal: Any = await handler(None, req_denied_traversal)  # type: ignore[arg-type]
    assert isinstance(res_denied_traversal, types.CallToolResult)
    assert res_denied_traversal.is_error
    assert isinstance(res_denied_traversal.content[0], types.TextContent)
    assert "Access denied: path outside allowed root" in res_denied_traversal.content[0].text
