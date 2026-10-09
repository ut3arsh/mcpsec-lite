"""Path and domain matching engine for mcpsec-lite.

Provides pure normalization, security validation, and pattern compilation
for path and domain allowlists across Windows and Linux.
"""

from __future__ import annotations

import ipaddress
import os
import re
import unicodedata
from urllib.parse import urlsplit

# Windows reserved device names
WIN_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
)

MAX_PATH_LENGTH = 4096


class PathSecurityError(ValueError):
    """Raised when a path fails security checks (NUL bytes, device names, ADS, etc.)."""


class DomainSecurityError(ValueError):
    """Raised when a domain or URL fails security checks (userinfo, invalid scheme, etc.)."""


def normalize_path(raw_path: str) -> str:
    """Normalize a path idempotently with strict cross-platform security validation.

    Ensures:
    1. Unicode NFC normalization.
    2. Rejection of NUL bytes and over-length paths.
    3. Rejection of Windows device paths (\\\\?\\, \\\\.\\), UNC shares, alternate data streams (:),
       and DOS device reserved names (CON, NUL, ...).
    4. Resolution of ~, .., symlinks, junctions, and 8.3 short names.
    5. Parent directory resolution for non-existent target paths.
    6. Trailing dot/space stripping per component on Windows.
    7. Idempotent return value: normalize_path(normalize_path(p)) == normalize_path(p).
    """
    if not isinstance(raw_path, str):
        raise PathSecurityError(f"Path must be a string, got {type(raw_path).__name__}")

    # 1. Unicode NFC normalization (fast path for ASCII)
    p_str = raw_path if raw_path.isascii() else unicodedata.normalize("NFC", raw_path)

    # 2. Basic boundary checks
    if "\x00" in p_str:
        raise PathSecurityError("Path contains NUL byte")

    if len(p_str) > MAX_PATH_LENGTH and len(p_str.encode("utf-8")) > MAX_PATH_LENGTH:
        raise PathSecurityError(f"Path length exceeds maximum limit of {MAX_PATH_LENGTH} bytes")

    # 3. Windows security checks
    # Reject device namespaces (\\?\, \\.\, //?/, //./) and UNC
    if p_str.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
        raise PathSecurityError("Windows device namespace paths are forbidden")

    if p_str.startswith(("\\\\", "//")):
        raise PathSecurityError("UNC network share paths are forbidden")

    # Check for Alternate Data Streams (':') after the drive letter
    check_str = p_str
    if os.name == "nt" and len(check_str) >= 2 and check_str[1] == ":" and check_str[0].isalpha():
        check_str = check_str[2:]
    if ":" in check_str:
        raise PathSecurityError("Alternate Data Streams (':') in path are forbidden")

    # Expand user directory (~)
    expanded = os.path.expanduser(p_str) if "~" in p_str else p_str

    # Convert separators to OS standard for processing
    standardized = os.path.normpath(expanded)

    # Check reserved device names and strip trailing dots/spaces
    parts = standardized.replace("\\", "/").split("/")
    cleaned_parts: list[str] = []
    for i, part in enumerate(parts):
        if not part:
            cleaned_parts.append(part)
            continue
        if i == 0 and os.name == "nt" and len(part) == 2 and part[1] == ":" and part[0].isalpha():
            cleaned_parts.append(part)
            continue

        base_name = part.rstrip(". ").split(".")[0].upper()
        if base_name in WIN_RESERVED_NAMES:
            raise PathSecurityError(f"Reserved device name '{part}' is forbidden")

        if os.name == "nt":
            cleaned_parts.append(part.rstrip(". "))
        else:
            cleaned_parts.append(part)

    if os.name == "nt":
        standardized = os.sep.join(cleaned_parts)

    # 4. Resolve real path and symlinks
    try:
        resolved_str = os.path.realpath(standardized)
    except Exception as exc:
        raise PathSecurityError(f"Failed to resolve path: {exc}") from exc

    # Final normalization for cross-platform canonical representation
    norm_result = os.path.normcase(os.path.normpath(resolved_str))
    canonical = norm_result.replace("\\", "/")

    return canonical


def compile_path_glob(pattern: str) -> re.Pattern[str]:
    """Compile a path glob pattern (with * and **) into a compiled regex.

    - * matches within a single directory component (no /).
    - ** matches zero or more directory levels.
    Matching happens after normalization, against normalized allowlist roots.
    """
    p_str = unicodedata.normalize("NFC", pattern)
    expanded = os.path.expanduser(p_str)

    # Check if the pattern is absolute or rooted
    # Find the index of the first glob wildcard (* or ?)
    first_wildcard = len(expanded)
    for wildcard in ("*", "?"):
        idx = expanded.find(wildcard)
        if idx != -1 and idx < first_wildcard:
            first_wildcard = idx

    static_prefix = expanded[:first_wildcard]
    glob_suffix = expanded[first_wildcard:]

    # If static prefix has directory separators, normalize the static root
    last_sep = max(static_prefix.rfind("/"), static_prefix.rfind("\\"))
    if last_sep != -1:
        root_dir = static_prefix[:last_sep]
        remainder = static_prefix[last_sep:] + glob_suffix
        if root_dir:
            try:
                norm_root = normalize_path(root_dir)
            except Exception:
                norm_root = os.path.normcase(root_dir).replace("\\", "/")
        else:
            norm_root = "/" if os.name != "nt" else ""
    else:
        remainder = expanded
        norm_root = ""

    norm_remainder = os.path.normcase(remainder).replace("\\", "/")
    combined = (norm_root + norm_remainder) if norm_root else norm_remainder

    # Tokenize on ** and * and ?
    tokens = re.split(r"(\*\*|\*|\?)", combined)
    regex_parts: list[str] = []

    for token in tokens:
        if token == "**":
            regex_parts.append(r".*")
        elif token == "*":
            regex_parts.append(r"[^/]*")
        elif token == "?":
            regex_parts.append(r"[^/]")
        elif token:
            regex_parts.append(re.escape(token))

    full_regex = "^" + "".join(regex_parts) + "$"
    return re.compile(full_regex, re.IGNORECASE if os.name == "nt" else 0)


def match_path(normalized_path: str, compiled_patterns: list[re.Pattern[str]]) -> bool:
    """Check if normalized_path matches any of the compiled path patterns."""
    for pattern in compiled_patterns:
        if pattern.search(normalized_path):
            return True
    return False


def normalize_domain_or_url(url_or_domain: str) -> tuple[str, bool]:
    """Parse and normalize a URL or domain string.

    Returns:
        (normalized_host, is_ip_literal)

    Raises DomainSecurityError on:
        - Non-string value
        - Non-HTTP/HTTPS scheme
        - Userinfo (@ in authority)
        - Empty hostname
        - Invalid hostname syntax
    """
    if not isinstance(url_or_domain, str):
        raise DomainSecurityError(
            f"URL/Domain must be a string, got {type(url_or_domain).__name__}"
        )

    val = url_or_domain.strip()
    if not val:
        raise DomainSecurityError("URL/Domain cannot be empty")

    parsed = urlsplit(val)
    if parsed.scheme:
        if parsed.scheme.lower() not in ("http", "https"):
            raise DomainSecurityError(
                f"Unsupported URL scheme: '{parsed.scheme}'. Only HTTP(S) is allowed"
            )
    else:
        parsed = urlsplit(f"http://{val}")

    # Reject userinfo (e.g. https://user:pass@evil.com or https://evil.com@other.com)
    if parsed.username or parsed.password or ("@" in parsed.netloc):
        raise DomainSecurityError("URL contains forbidden userinfo authority ('@')")

    raw_host = parsed.hostname
    if not raw_host:
        raise DomainSecurityError("URL has empty or missing hostname")

    # Lowercase host
    host = raw_host.lower()

    # Strip a single trailing dot
    if host.endswith("."):
        host = host[:-1]

    if not host:
        raise DomainSecurityError("Host is empty after stripping trailing dot")

    # Convert IDN (International Domain Names) to Punycode
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except Exception as exc:
        raise DomainSecurityError(f"Invalid domain name encoding (IDN): {exc}") from exc

    # Check if host is an IP literal
    is_ip = False
    try:
        ipaddress.ip_address(ascii_host)
        is_ip = True
    except ValueError:
        is_ip = False

    return ascii_host, is_ip


def compile_domain_pattern(pattern: str) -> tuple[str, bool, re.Pattern[str] | None]:
    """Compile a domain allowlist entry.

    Supports:
        - Exact host: "api.github.com"
        - Subdomain wildcard: "*.githubusercontent.com" (matches subdomains only, not apex)
        - IP literal: "192.168.1.1"

    Returns:
        (raw_host, is_wildcard, compiled_regex_or_none)
    """
    p = pattern.strip().lower()
    if p.endswith("."):
        p = p[:-1]

    if p.startswith("*."):
        suffix = p[2:]
        # Convert suffix to punycode if needed
        ascii_suffix = suffix.encode("idna").decode("ascii")
        # Match subdomains only: one or more labels before the suffix
        escaped_suffix = re.escape(ascii_suffix)
        regex_str = rf"^(?:[a-z0-9_\-]+\.)+{escaped_suffix}$"
        return p, True, re.compile(regex_str, re.IGNORECASE)
    else:
        ascii_host = p.encode("idna").decode("ascii")
        return ascii_host, False, None


def match_domain(
    normalized_host: str,
    is_ip_literal: bool,
    compiled_domain_rules: list[tuple[str, bool, re.Pattern[str] | None]],
) -> bool:
    """Evaluate whether normalized_host matches any domain allowlist entry.

    Fail-closed rules:
    - IP literals only match exact IP allowlist entries (never wildcards).
    - Exact entries match only exact host.
    - *.domain.com matches subdomains only (never apex, never look-alikes).
    """
    for raw_host, is_wildcard, regex in compiled_domain_rules:
        if is_ip_literal:
            # IP literals cannot match wildcard domain rules
            if not is_wildcard and normalized_host == raw_host:
                return True
            continue

        if is_wildcard:
            assert regex is not None
            if regex.match(normalized_host):
                return True
        else:
            if normalized_host == raw_host:
                return True

    return False
