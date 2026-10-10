"""Taint tracking and label updating across session lifecycle.

Strictly adheres to docs/policy_schema.md §4.
Pure functions over explicit, immutable SessionState.
"""

from __future__ import annotations

from typing import Any

import mcp.types as types

from mcpsec_core.matching import match_path, normalize_path
from mcpsec_core.models import ResponseSummary, SessionState, ToolCall


def is_response_successful(response: Any) -> bool:
    """Determine if a tool execution response succeeded."""
    if response is None:
        return False
    if isinstance(response, types.CallToolResult):
        return not response.is_error
    if isinstance(response, ResponseSummary):
        return response.status == "ok"
    if isinstance(response, dict):
        if response.get("is_error") is True or response.get("isError") is True:
            return False
        if response.get("status") == "error":
            return False
        return True
    if isinstance(response, bool):
        return response
    return True


def update_taint(
    call: ToolCall,
    response: Any,
    session_state: SessionState,
    policy: Any,
) -> SessionState:
    """Update session taint state based on tool execution response.

    Pure, immutable function:
    - Never mutates session_state or policy.
    - Labels are applied only after successful execution (errors/denials do not taint).
    - Returns a new SessionState instance.
    - O(1) source lookup via precomputed policy.taint_sources_by_tool index.
    - Missing or unparsable arguments for private_data sources fail closed toward tainting.
    """
    if not is_response_successful(response):
        return SessionState(
            session_id=session_state.session_id,
            taint=set(session_state.taint),
            call_count=session_state.call_count,
            deny_count=session_state.deny_count,
            agent_id=session_state.agent_id,
            mode=session_state.mode,
        )

    if policy is None or not hasattr(policy, "taint_sources_by_tool"):
        return SessionState(
            session_id=session_state.session_id,
            taint=set(session_state.taint),
            call_count=session_state.call_count,
            deny_count=session_state.deny_count,
            agent_id=session_state.agent_id,
            mode=session_state.mode,
        )

    tool_id = call.tool if "." in call.tool else f"{call.server}.{call.tool}"
    sources = policy.taint_sources_by_tool.get(tool_id, ())
    new_taint = set(session_state.taint)

    for source in sources:
        if not source.args_patterns:
            # Unconditional taint source for this tool
            new_taint.add(source.label)
        else:
            all_args_match = True
            for arg_name, patterns in source.args_patterns.items():
                if arg_name not in call.args:
                    if source.label == "private_data":
                        # Fail-closed toward tainting for missing private_data args
                        continue
                    else:
                        all_args_match = False
                        break

                raw_val = call.args[arg_name]
                if not isinstance(raw_val, str):
                    if source.label == "private_data":
                        # Fail-closed toward tainting for unparsable private_data args
                        continue
                    else:
                        all_args_match = False
                        break

                try:
                    norm_p = normalize_path(raw_val)
                    if not match_path(norm_p, list(patterns)):
                        all_args_match = False
                        break
                except Exception:
                    if source.label == "private_data":
                        # Fail closed toward tainting on path normalization errors
                        continue
                    else:
                        all_args_match = False
                        break

            if all_args_match:
                new_taint.add(source.label)

    return SessionState(
        session_id=session_state.session_id,
        taint=new_taint,
        call_count=session_state.call_count,
        deny_count=session_state.deny_count,
        agent_id=session_state.agent_id,
        mode=session_state.mode,
    )
