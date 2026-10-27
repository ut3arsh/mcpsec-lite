"""Advisory detectors for secrets in arguments and injection heuristics in responses.

STATUS: FROZEN-CANDIDATE (ADR-003: Detectors are purely advisory and never alter decisions).

Constraints:
1. Purely in-memory response scanning; response contents are NEVER written to logs.
2. Linear-time regex patterns capped at 256 KiB per response.
3. Fail-safe: No detector exception may disrupt tool call forwarding (catches all exceptions and flags detector_error).
4. Decision Invariance: Tool call decisions and payload forwarding are 100% identical regardless of detector results.
"""

from __future__ import annotations

import math
import re
from typing import Any

# Byte cap for response scanning (256 KiB)
MAX_SCAN_BYTES = 256 * 1024

# Secrets regexes (linear-time, non-backtracking)
AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,82})\b")
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
HIGH_ENTROPY_BLOB_REGEX = re.compile(r"\b[A-Za-z0-9+/_-]{64,}={0,2}\b")
HEX_BLOB_REGEX = re.compile(r"\b[0-9a-fA-F]{64,}\b")

# Response injection heuristics
BIDI_ZERO_WIDTH_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2066-\u2069]")
COARSE_INJECTION_REGEX = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s+prompt\s*:|\[INST\]|<\|im_start\|>|SYSTEM:\s*|forget\s+all\s+prior\s+instructions)"
)
BASE64_PAYLOAD_REGEX = re.compile(r"\b[A-Za-z0-9+/]{128,}={0,2}\b")


def _calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies: dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _extract_text_from_mcp_content(item: Any) -> str:
    """Extract model-visible text from any MCP content item."""
    if hasattr(item, "text") and isinstance(item.text, str):
        return item.text
    if hasattr(item, "resource"):
        res = item.resource
        if hasattr(res, "text") and isinstance(res.text, str):
            return res.text
        if hasattr(res, "blob") and isinstance(res.blob, str):
            return res.blob
        if isinstance(res, dict):
            if "text" in res and isinstance(res["text"], str):
                return res["text"]
            if "blob" in res and isinstance(res["blob"], str):
                return res["blob"]
    if isinstance(item, dict):
        if "text" in item and isinstance(item["text"], str):
            return item["text"]
        if "resource" in item and isinstance(item["resource"], dict):
            res_dict = item["resource"]
            if "text" in res_dict and isinstance(res_dict["text"], str):
                return res_dict["text"]
            if "blob" in res_dict and isinstance(res_dict["blob"], str):
                return res_dict["blob"]
        import json

        return json.dumps(item, ensure_ascii=False)
    if isinstance(item, str):
        return item
    return str(item)


def scan_arguments(args: Any) -> list[str]:
    """Scan tool call arguments for high-confidence secrets (advisory only).

    Returns a list of flags (e.g. ['secret:aws_key', 'secret:github_token']).
    """
    flags: list[str] = []
    try:
        text_repr: str
        if isinstance(args, str):
            text_repr = args
        elif isinstance(args, dict | list):
            import json

            text_repr = json.dumps(args, ensure_ascii=False)
        else:
            text_repr = str(args)

        if AWS_KEY_REGEX.search(text_repr):
            flags.append("secret:aws_key")

        if GITHUB_TOKEN_REGEX.search(text_repr):
            flags.append("secret:github_token")

        if PRIVATE_KEY_REGEX.search(text_repr):
            flags.append("secret:private_key")

        blob_match = HIGH_ENTROPY_BLOB_REGEX.search(text_repr)
        if blob_match:
            blob = blob_match.group(0)
            is_hex = all(c in "0123456789abcdefABCDEF" for c in blob)
            entropy = _calculate_shannon_entropy(blob)
            if (is_hex and entropy > 3.5) or (not is_hex and entropy > 4.5):
                flags.append("secret:high_entropy_blob")

    except Exception:
        flags.append("detector_error:args_scan")

    return flags


def scan_response(content: Any, byte_cap: int = MAX_SCAN_BYTES) -> tuple[list[str], float]:
    """Scan upstream response content in memory for prompt injection markers.

    CRITICAL PRIVACY & SECURITY REQUIREMENT:
    The response is scanned strictly in memory and NEVER logged or retained.
    Only the resulting flags and risk_score are returned.

    Returns (flags, risk_score).
    """
    flags: list[str] = []
    risk_score = 0.0

    try:
        extracted_text: str
        if isinstance(content, str):
            extracted_text = content
        elif isinstance(content, list):
            extracted_text = "\n".join(_extract_text_from_mcp_content(item) for item in content)
        elif isinstance(content, dict):
            extracted_text = _extract_text_from_mcp_content(content)
        elif hasattr(content, "text") or hasattr(content, "resource"):
            extracted_text = _extract_text_from_mcp_content(content)
        else:
            extracted_text = str(content)

        encoded_bytes = extracted_text.encode("utf-8")
        if len(encoded_bytes) > byte_cap:
            flags.append("scan_truncated")
            # Truncate by bytes safely
            extracted_text = encoded_bytes[:byte_cap].decode("utf-8", errors="ignore")

        # 1. Invisible or bidi characters
        if BIDI_ZERO_WIDTH_REGEX.search(extracted_text):
            flags.append("injection:invisible_or_bidi")
            risk_score = max(risk_score, 0.70)

        # 2. Coarse injection markers
        if COARSE_INJECTION_REGEX.search(extracted_text):
            flags.append("injection:coarse_marker")
            risk_score = max(risk_score, 0.85)

        # 3. Base64 payload detection
        if BASE64_PAYLOAD_REGEX.search(extracted_text):
            flags.append("injection:base64_payload")
            risk_score = max(risk_score, 0.50)

        if len(flags) > 1:
            risk_score = min(1.0, risk_score + 0.10)

    except Exception:
        flags.append("detector_error:response_scan")
        risk_score = 0.0

    return flags, round(risk_score, 2)
