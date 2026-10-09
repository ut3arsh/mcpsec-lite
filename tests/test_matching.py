"""Comprehensive tests for path and domain matching, security corpus, and hypothesis properties."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mcpsec_core.matching import (
    WIN_RESERVED_NAMES,
    DomainSecurityError,
    PathSecurityError,
    compile_domain_pattern,
    compile_path_glob,
    match_domain,
    match_path,
    normalize_domain_or_url,
    normalize_path,
)

# ---------------------------------------------------------------------------
# Traversal & Security Bypass Corpus Tests
# ---------------------------------------------------------------------------


def test_path_normalization_basic(tmp_path: Path) -> None:
    test_file = tmp_path / "hello.txt"
    test_file.write_text("content", encoding="utf-8")

    norm = normalize_path(str(test_file))
    assert norm == normalize_path(norm)  # Idempotent
    assert norm.endswith("hello.txt")


def test_path_traversal_dot_dot_denied_outside_root(tmp_path: Path) -> None:
    allowed_root = tmp_path / "sandbox"
    allowed_root.mkdir()
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("secret", encoding="utf-8")

    traversal_path = str(allowed_root / ".." / "secret.txt")
    norm_traversal = normalize_path(traversal_path)

    # Glob only allows sandbox/**
    glob_pat = compile_path_glob(f"{allowed_root}/**")
    assert not match_path(norm_traversal, [glob_pat])


def test_path_nul_byte_rejected() -> None:
    with pytest.raises(PathSecurityError, match="NUL byte"):
        normalize_path("/home/user/file.txt\x00.evil")


def test_path_over_length_rejected() -> None:
    long_path = "/tmp/" + "a" * 5000
    with pytest.raises(PathSecurityError, match="exceeds maximum limit"):
        normalize_path(long_path)


def test_path_device_paths_rejected() -> None:
    for device_prefix in ["\\\\?\\C:\\Windows", "\\\\.\\pipe", "//?/C:/foo", "//./bar"]:
        with pytest.raises(PathSecurityError, match="device namespace"):
            normalize_path(device_prefix)


def test_path_unc_paths_rejected() -> None:
    for unc in ["\\\\server\\share\\file.txt", "//server/share/file.txt"]:
        with pytest.raises(PathSecurityError, match="UNC network share"):
            normalize_path(unc)


def test_path_alternate_data_streams_rejected() -> None:
    if os.name == "nt":
        with pytest.raises(PathSecurityError, match="Alternate Data Streams"):
            normalize_path("C:\\sandbox\\file.txt:hidden_stream")
        with pytest.raises(PathSecurityError, match="Alternate Data Streams"):
            normalize_path("file.txt:stream")


def test_path_dos_reserved_device_names_rejected() -> None:
    for res_name in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1", "con.txt", "aux.json"]:
        path = f"/tmp/{res_name}" if os.name != "nt" else f"C:\\temp\\{res_name}"
        with pytest.raises(PathSecurityError, match="Reserved device name"):
            normalize_path(path)


def test_path_symlink_escape_resolution(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "secret.txt"
    target.write_text("secret_val", encoding="utf-8")

    link = sandbox / "escape_link"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        if os.name == "nt":
            pytest.skip("Symlink creation not supported without elevation on Windows")
        raise

    norm_link = normalize_path(str(link))
    pattern = compile_path_glob(f"{sandbox}/**")
    # Must resolve to outside, so matching against sandbox/** fails!
    assert not match_path(norm_link, [pattern])


def test_path_junction_escape_resolution_windows(tmp_path: Path) -> None:
    """Directory junction escape test on Windows (runs without elevated privilege)."""
    if os.name != "nt":
        pytest.skip("Windows directory junctions are Windows-specific")

    import _winapi

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target_file = outside / "secret.txt"
    target_file.write_text("secret_data", encoding="utf-8")

    junction_path = sandbox / "junc_escape"
    _winapi.CreateJunction(str(outside), str(junction_path))

    # Resolving path through junction must resolve to 'outside'
    norm_junc = normalize_path(str(junction_path / "secret.txt"))
    pattern = compile_path_glob(f"{sandbox}/**")
    assert not match_path(norm_junc, [pattern])


def test_path_non_existent_target_parent_resolution(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    non_existent_file = sandbox / "subdir" / "newfile.txt"

    norm = normalize_path(str(non_existent_file))
    assert norm == normalize_path(norm)
    pattern = compile_path_glob(f"{sandbox}/**")
    assert match_path(norm, [pattern])


def test_path_unicode_nfc_normalization() -> None:
    # NFD decomposed character vs NFC composed
    # e.g., 'e' + combining acute accent (\u0301) vs '\u00e9'
    nfd_str = "caf\u0065\u0301.txt"
    nfc_str = "caf\u00e9.txt"

    norm1 = normalize_path(nfd_str)
    norm2 = normalize_path(nfc_str)
    assert norm1 == norm2


# ---------------------------------------------------------------------------
# Domain & URL Matching Tests
# ---------------------------------------------------------------------------


def test_domain_normalization_and_userinfo_rejection() -> None:
    # Reject userinfo
    with pytest.raises(DomainSecurityError, match="userinfo"):
        normalize_domain_or_url("https://api.github.com@evil.com/path")

    with pytest.raises(DomainSecurityError, match="userinfo"):
        normalize_domain_or_url("https://user:password@legit.com/")


def test_domain_scheme_restrictions() -> None:
    with pytest.raises(DomainSecurityError, match="Unsupported URL scheme"):
        normalize_domain_or_url("ftp://files.example.com/data")

    with pytest.raises(DomainSecurityError, match="Unsupported URL scheme"):
        normalize_domain_or_url("javascript:alert(1)")


def test_domain_subdomain_wildcard_matching() -> None:
    rules = [
        compile_domain_pattern("*.githubusercontent.com"),
        compile_domain_pattern("api.github.com"),
    ]

    # Matching subdomains
    h1, ip1 = normalize_domain_or_url("https://raw.githubusercontent.com/file")
    assert match_domain(h1, ip1, rules)

    h2, ip2 = normalize_domain_or_url("https://a.b.c.githubusercontent.com/file")
    assert match_domain(h2, ip2, rules)

    # Apex must NOT match *.githubusercontent.com
    h3, ip3 = normalize_domain_or_url("https://githubusercontent.com")
    assert not match_domain(h3, ip3, rules)

    # Look-alikes must NOT match
    h4, ip4 = normalize_domain_or_url("https://evil-githubusercontent.com")
    assert not match_domain(h4, ip4, rules)

    h5, ip5 = normalize_domain_or_url("https://githubusercontent.com.evil.com")
    assert not match_domain(h5, ip5, rules)

    # Exact match api.github.com
    h6, ip6 = normalize_domain_or_url("https://api.github.com/v1")
    assert match_domain(h6, ip6, rules)


def test_domain_ip_literal_matching() -> None:
    rules = [
        compile_domain_pattern("192.168.1.50"),
        compile_domain_pattern("*.example.com"),
    ]

    h_allowed_ip, is_ip = normalize_domain_or_url("http://192.168.1.50/api")
    assert is_ip
    assert match_domain(h_allowed_ip, is_ip, rules)

    h_unallowed_ip, is_ip2 = normalize_domain_or_url("http://192.168.1.99/api")
    assert is_ip2
    assert not match_domain(h_unallowed_ip, is_ip2, rules)


def test_domain_idn_punycode_handling() -> None:
    # German umlaut domain e.g. münchen.de -> xn--mnchen-3ya.de
    host, _ = normalize_domain_or_url("https://münchen.de/")
    assert host.startswith("xn--")

    rule = compile_domain_pattern("münchen.de")
    assert match_domain(host, False, [rule])


def test_matching_edge_cases_and_error_handling() -> None:
    # Non-string path
    with pytest.raises(PathSecurityError):
        normalize_path(12345)  # type: ignore[arg-type]

    # Non-string domain
    with pytest.raises(DomainSecurityError):
        normalize_domain_or_url(None)  # type: ignore[arg-type]

    # Empty domain
    with pytest.raises(DomainSecurityError, match="cannot be empty"):
        normalize_domain_or_url("   ")

    # Domain with trailing dot
    host, _ = normalize_domain_or_url("https://api.github.com./")
    assert host == "api.github.com"

    # URL without hostname
    with pytest.raises(DomainSecurityError, match="empty or missing hostname"):
        normalize_domain_or_url("http://")

    # Path glob with ?
    q_pattern = compile_path_glob("/home/user/file?.txt")
    norm_match = normalize_path("/home/user/file1.txt")
    norm_no_match = normalize_path("/home/user/file12.txt")
    assert match_path(norm_match, [q_pattern])
    assert not match_path(norm_no_match, [q_pattern])


# ---------------------------------------------------------------------------
# Hypothesis Property-Based Tests (≥ 500 examples each)
# ---------------------------------------------------------------------------


@settings(max_examples=500, deadline=None)
@given(
    st.lists(
        st.text(
            alphabet=st.characters(
                whitelist_categories=["Lu", "Ll", "Nd"],
                whitelist_characters=["_", "-", "."],
            ),
            min_size=1,
            max_size=15,
        ).filter(
            lambda s: (
                not s.startswith(".")
                and not s.endswith(".")
                and s.upper() not in WIN_RESERVED_NAMES
            )
        ),
        min_size=1,
        max_size=5,
    )
)
def test_hypothesis_path_normalization_idempotent(parts: list[str]) -> None:
    raw = "/".join(parts)
    norm1 = normalize_path(raw)
    norm2 = normalize_path(norm1)
    assert norm1 == norm2


@settings(max_examples=500, deadline=None)
@given(
    sub=st.text(
        alphabet=st.characters(whitelist_categories=["Ll", "Nd"], whitelist_characters=["-"]),
        min_size=1,
        max_size=20,
    ).filter(lambda s: not s.startswith("-") and not s.endswith("-"))
)
def test_hypothesis_subdomain_matching_property(sub: str) -> None:
    domain_rule = compile_domain_pattern("*.testdomain.com")
    rules = [domain_rule]

    full_url = f"https://{sub}.testdomain.com/path"
    host, is_ip = normalize_domain_or_url(full_url)
    assert match_domain(host, is_ip, rules)

    # Property: Apex never matches wildcard
    apex_host, apex_ip = normalize_domain_or_url("https://testdomain.com")
    assert not match_domain(apex_host, apex_ip, rules)

    # Property: Suffix look-alike never matches
    lookalike_host, lookalike_ip = normalize_domain_or_url(
        f"https://{sub}.testdomain.com.attacker.com"
    )
    assert not match_domain(lookalike_host, lookalike_ip, rules)
