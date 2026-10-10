"""Tests for argument adapters registry, strict argument schemas, and tool name mapping."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mcpsec_core.adapters import (
    ToolNameMappingError,
    decode_tool_name,
    encode_tool_name,
    extract_domain_arguments,
    extract_path_arguments,
    get_adapter,
    validate_tool_adapter_for_constraints,
    validate_unexpected_arguments,
)


def test_builtin_adapters_registry() -> None:
    fs_read = get_adapter("fs.read_file")
    assert fs_read is not None
    assert fs_read.path_args == ("path",)
    assert "path" in fs_read.all_args
    assert "tail" in fs_read.all_args
    assert "head" in fs_read.all_args

    fs_move = get_adapter("fs.move_file")
    assert fs_move is not None
    assert fs_move.path_args == ("source", "destination")
    assert fs_move.all_args == frozenset({"source", "destination"})

    http_fetch = get_adapter("http.fetch")
    assert http_fetch is not None
    assert http_fetch.domain_args == ("url",)
    assert "url" in http_fetch.all_args


def test_extract_path_arguments_valid() -> None:
    ok, paths, err = extract_path_arguments("fs.read_file", {"path": "sandbox/file.txt"})
    assert ok
    assert paths == ["sandbox/file.txt"]
    assert err is None

    ok_multi, paths_multi, err_multi = extract_path_arguments(
        "fs.move_file",
        {"source": "a.txt", "destination": "b.txt"},
    )
    assert ok_multi
    assert paths_multi == ["a.txt", "b.txt"]
    assert err_multi is None


def test_extract_path_arguments_fail_closed() -> None:
    # Missing argument
    ok, paths, err = extract_path_arguments("fs.read_file", {})
    assert not ok
    assert "Missing expected path argument" in str(err)

    # Wrong argument type
    ok, paths, err = extract_path_arguments("fs.read_file", {"path": 12345})
    assert not ok
    assert "must be a string" in str(err)


def test_validate_unexpected_arguments_strict() -> None:
    # Valid arguments declared in adapter schema
    ok, err = validate_unexpected_arguments("fs.read_file", {"path": "a.txt", "tail": 10})
    assert ok
    assert err is None

    # Unknown argument 'destination' or 'file' on read_file
    ok_bad, err_bad = validate_unexpected_arguments(
        "fs.read_file", {"path": "a.txt", "destination": "b.txt"}
    )
    assert not ok_bad
    assert "ERR_UNEXPECTED_ARGUMENT" in str(err_bad)
    assert "destination" in str(err_bad)

    # Unknown argument 'secret_param'
    ok_bad2, err_bad2 = validate_unexpected_arguments(
        "http.fetch", {"url": "https://api.github.com", "secret_param": "val"}
    )
    assert not ok_bad2
    assert "ERR_UNEXPECTED_ARGUMENT" in str(err_bad2)


def test_extract_domain_arguments_valid() -> None:
    ok, domains, err = extract_domain_arguments("http.fetch", {"url": "https://api.github.com"})
    assert ok
    assert domains == ["https://api.github.com"]
    assert err is None


def test_extract_domain_arguments_fail_closed() -> None:
    # Missing url
    ok, domains, err = extract_domain_arguments("http.fetch", {})
    assert not ok
    assert "Missing expected URL argument" in str(err)

    # Wrong type
    ok, domains, err = extract_domain_arguments("http.fetch", {"url": ["https://evil.com"]})
    assert not ok
    assert "must be a string" in str(err)


def test_validate_tool_adapter_rule8() -> None:
    # Valid adapter
    valid, err = validate_tool_adapter_for_constraints("fs.read_file", True, False)
    assert valid
    assert err is None

    # Unknown tool without constraints -> valid
    valid_no_const, err_no_const = validate_tool_adapter_for_constraints(
        "custom.unconstrained", False, False
    )
    assert valid_no_const
    assert err_no_const is None

    # Unknown tool with constraints -> invalid
    valid, err = validate_tool_adapter_for_constraints("custom.unknown", True, False)
    assert not valid
    assert "no registered argument adapter" in str(err)

    # Tool without path args declaring path_allowlist
    valid, err = validate_tool_adapter_for_constraints("http.fetch", True, False)
    assert not valid
    assert "has no path arguments" in str(err)

    # Tool without domain args declaring domain_allowlist
    valid_dom, err_dom = validate_tool_adapter_for_constraints("fs.read_file", False, True)
    assert not valid_dom
    assert "has no domain arguments" in str(err_dom)


# ---------------------------------------------------------------------------
# Tool Name Mapping Tests (<server>__<tool> <-> <server>.<tool>)
# ---------------------------------------------------------------------------


def test_tool_name_encoding_and_decoding_basic() -> None:
    exposed = encode_tool_name("fs", "read_file")
    assert exposed == "fs__read_file"

    server, tool = decode_tool_name("fs__read_file")
    assert server == "fs"
    assert tool == "read_file"


def test_tool_name_encoding_validations() -> None:
    # Invalid server names
    with pytest.raises(ToolNameMappingError, match="Invalid server name"):
        encode_tool_name("FS", "read_file")  # Uppercase not allowed

    with pytest.raises(ToolNameMappingError, match="Invalid server name"):
        encode_tool_name("server.1", "tool")  # Dot not allowed

    with pytest.raises(ToolNameMappingError, match="Invalid server name"):
        encode_tool_name("server__sub", "tool")  # Double underscore not allowed

    with pytest.raises(ToolNameMappingError, match="Invalid server name"):
        encode_tool_name("1server", "tool")  # Leading digit not allowed

    # Empty tool name
    with pytest.raises(ToolNameMappingError, match="cannot be empty"):
        encode_tool_name("server", "")

    # Over 64 chars
    long_tool = "a" * 60
    with pytest.raises(ToolNameMappingError, match="exceeds maximum length of 64"):
        encode_tool_name("server", long_tool)

    # Forbidden characters in tool name
    with pytest.raises(ToolNameMappingError, match="forbidden characters"):
        encode_tool_name("server", "tool.name")

    with pytest.raises(ToolNameMappingError, match="forbidden characters"):
        encode_tool_name("server", "tool$name")


def test_tool_name_decoding_validations() -> None:
    # Missing '__'
    with pytest.raises(ToolNameMappingError, match="missing '__'"):
        decode_tool_name("read_file")

    # Multiple '__' (ambiguous)
    with pytest.raises(ToolNameMappingError, match="ambiguous multiple '__'"):
        decode_tool_name("server__tool__extra")

    # Over 64 chars
    with pytest.raises(ToolNameMappingError, match="exceeds 64 characters"):
        decode_tool_name("s__" + "a" * 65)

    # Invalid server name format
    with pytest.raises(ToolNameMappingError, match="Invalid server"):
        decode_tool_name("1server__tool")


@given(
    server=st.from_regex(r"^[a-z][a-z0-9-]{0,10}$", fullmatch=True),
    tool=st.from_regex(r"^[a-zA-Z0-9_]{1,20}$", fullmatch=True).filter(lambda s: "__" not in s),
)
def test_hypothesis_tool_name_roundtrip_property(server: str, tool: str) -> None:
    exposed = encode_tool_name(server, tool)
    assert len(exposed) <= 64
    assert "__" in exposed

    dec_server, dec_tool = decode_tool_name(exposed)
    assert dec_server == server
    assert dec_tool == tool
