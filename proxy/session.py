"""Proxy session management and multi-upstream tool-call lifecycle coordination."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Literal

import anyio
import mcp.types as types

from mcpsec_core.adapters import ToolNameMappingError, decode_tool_name
from mcpsec_core.approvals import ApprovalManager
from mcpsec_core.audit import AuditLogger
from mcpsec_core.flow import check_flow
from mcpsec_core.models import (
    LatencyMs,
    ResponseSummary,
    SessionState,
    ToolCall,
)
from mcpsec_core.pinning import check_pinning
from mcpsec_core.policy import check_policy
from mcpsec_core.taint import update_taint
from proxy.supervisor import UpstreamManager


def compute_content_bytes(content: list[Any]) -> int:
    """Calculate the byte size of MCP tool response content items."""
    total_bytes = 0
    for item in content:
        if isinstance(item, types.TextContent):
            total_bytes += len(item.text.encode("utf-8"))
        elif isinstance(item, types.ImageContent | types.AudioContent):
            total_bytes += len(str(item.data).encode("utf-8"))
        elif isinstance(item, types.EmbeddedResource):
            if hasattr(item.resource, "text") and item.resource.text:
                total_bytes += len(item.resource.text.encode("utf-8"))
            elif hasattr(item.resource, "blob") and item.resource.blob:
                total_bytes += len(str(item.resource.blob).encode("utf-8"))
        elif isinstance(item, str):
            total_bytes += len(item.encode("utf-8"))
        elif isinstance(item, dict):
            text_val = item.get("text", "")
            if text_val:
                total_bytes += len(str(text_val).encode("utf-8"))
    return total_bytes


class ProxySession:
    """Manages an active proxy session spanning all upstream MCP servers."""

    def __init__(
        self,
        session_id: str,
        upstream_manager: UpstreamManager,
        audit_logger: AuditLogger,
        policy_hash: str = "",
        agent_id: str = "dev-agent",
        mode: Literal["audit", "enforce"] = "enforce",
        policy_data: Any = None,
        approval_manager: ApprovalManager | None = None,
    ) -> None:
        self.session_id = session_id
        self.upstream_manager = upstream_manager
        self.audit_logger = audit_logger
        self.policy_hash = policy_hash
        self.agent_id = agent_id
        self.mode = mode
        self.policy_data = policy_data
        self.approval_manager = approval_manager or ApprovalManager()

        # Single SessionState spanning all upstreams
        self.session_state = SessionState(
            session_id=session_id,
            taint=set(),
            call_count=0,
            deny_count=0,
            agent_id=agent_id,
            mode=mode,
        )
        self._lock = anyio.Lock()
        self._closed = False

    def start(self, client_info: dict[str, Any] | None = None) -> None:
        """Record session_start in audit log."""
        self.audit_logger.log_session_start(
            session_id=self.session_id,
            agent_id=self.agent_id,
            policy_hash=self.policy_hash,
            client_info=client_info,
            mode=self.mode,
        )

    def close(self, reason: Literal["disconnect", "shutdown", "error"] = "disconnect") -> None:
        """Record session_end in audit log."""
        if self._closed:
            return
        self._closed = True
        self.audit_logger.log_session_end(
            session_id=self.session_id,
            reason=reason,
            final_taint=sorted(self.session_state.taint),
            call_count=self.session_state.call_count,
            deny_count=self.session_state.deny_count,
        )

    async def list_tools(self) -> types.ListToolsResult:
        """Return deterministic, sorted union of all healthy upstreams' tools."""
        tools = self.upstream_manager.list_all_tools()
        return types.ListToolsResult(tools=tools)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None,
    ) -> types.CallToolResult:
        """Execute a tool call with name resolution, policy checks, timing, taint, and audit logging."""
        should_serialize = True
        if self.policy_data is not None and hasattr(self.policy_data, "serialize_calls"):
            should_serialize = self.policy_data.serialize_calls

        if should_serialize:
            async with self._lock:
                return await self._call_tool_internal(name, arguments)
        else:
            return await self._call_tool_internal(name, arguments)

    async def _await_approval(self, call_id: str, timeout_seconds: float) -> bool:
        """Poll and await operator approval decision until timeout."""
        start = time.perf_counter()
        while (time.perf_counter() - start) < timeout_seconds:
            all_apprs = self.approval_manager.get_all_approvals()
            if call_id in all_apprs:
                status = all_apprs[call_id].status
                if status == "approved":
                    return True
                elif status in ("denied", "timeout"):
                    return False
            await asyncio.sleep(0.02)

        self.approval_manager.record_timeout(call_id)
        return False

    async def _call_tool_internal(
        self,
        name: str,
        arguments: dict[str, Any] | None,
    ) -> types.CallToolResult:
        call_id = str(uuid.uuid4())
        raw_args = arguments or {}
        capabilities: list[str] = []

        t_proxy_start = time.perf_counter()
        taint_before = sorted(self.session_state.taint)

        # 1. Decode exposed name (<server>__<tool>)
        server_name: str
        upstream_tool_name: str
        try:
            server_name, upstream_tool_name = decode_tool_name(name)
        except (ToolNameMappingError, ValueError) as err:
            # Unknown prefix or invalid format -> deny ERR_UNKNOWN_TOOL
            post_duration_ms = (time.perf_counter() - t_proxy_start) * 1000.0
            self.session_state.deny_count += 1
            self.session_state.call_count += 1

            self.audit_logger.log_tool_call(
                session_id=self.session_id,
                call_id=call_id,
                agent_id=self.agent_id,
                server="unknown",
                tool=name,
                capabilities=[],
                raw_args=raw_args,
                decision="deny",
                effective_decision="blocked",
                decision_layer="policy",
                decision_reason=f"ERR_UNKNOWN_TOOL: {err}",
                pin_status="unchecked",
                latency_ms=LatencyMs(proxy=round(post_duration_ms, 3), upstream=None),
                taint_before=taint_before,
                taint_after=taint_before,
                response_summary=None,
                error=f"ERR_UNKNOWN_TOOL: {err}",
            )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="Denied by mcpsec policy")],
                is_error=True,
            )

        # 2. Check if upstream server exists and is healthy
        if (
            server_name not in self.upstream_manager.servers
            or not self.upstream_manager.servers[server_name].is_healthy
        ):
            post_duration_ms = (time.perf_counter() - t_proxy_start) * 1000.0
            self.session_state.deny_count += 1
            self.session_state.call_count += 1

            self.audit_logger.log_tool_call(
                session_id=self.session_id,
                call_id=call_id,
                agent_id=self.agent_id,
                server=server_name,
                tool=upstream_tool_name,
                capabilities=[],
                raw_args=raw_args,
                decision="deny",
                effective_decision="blocked",
                decision_layer="policy",
                decision_reason=f"ERR_UNKNOWN_TOOL: server '{server_name}' is not found or degraded",
                pin_status="unchecked",
                latency_ms=LatencyMs(proxy=round(post_duration_ms, 3), upstream=None),
                taint_before=taint_before,
                taint_after=taint_before,
                response_summary=None,
                error=f"ERR_UNKNOWN_TOOL: server '{server_name}' unavailable",
            )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="Denied by mcpsec policy")],
                is_error=True,
            )

        # 3. Policy evaluation on <server>.<tool>
        tool_id = f"{server_name}.{upstream_tool_name}"
        if self.policy_data is not None and hasattr(self.policy_data, "capabilities"):
            capabilities = list(self.policy_data.capabilities.get(tool_id, ()))
        else:
            capabilities = []

        tool_call = ToolCall(
            call_id=call_id,
            session_id=self.session_id,
            agent_id=self.agent_id,
            server=server_name,
            tool=upstream_tool_name,
            args=raw_args,
            capabilities=capabilities,
        )

        decision: Literal["allow", "deny", "require_approval"] = "allow"
        decision_layer: Literal["pinning", "policy", "flow", "approval", "none"] = "none"
        decision_reason = (
            "pass-through (no policy)" if self.policy_data is None else "allowed by policy"
        )
        effective_decision: Literal["forwarded", "blocked", "held"] = "forwarded"

        rule_id: str | None = None

        try:
            # 3.1 Pinning check
            pinning_decision = check_pinning(server_name, None)
            if not pinning_decision.is_allowed:
                decision = pinning_decision.decision
                decision_layer = pinning_decision.layer
                decision_reason = pinning_decision.reason
                rule_id = pinning_decision.rule_id
            else:
                # 3.2 Policy check
                policy_decision = check_policy(tool_call, self.policy_data)
                if not policy_decision.is_allowed:
                    decision = policy_decision.decision
                    decision_layer = policy_decision.layer
                    decision_reason = policy_decision.reason
                    rule_id = policy_decision.rule_id
                else:
                    decision_reason = policy_decision.reason
                    decision_layer = policy_decision.layer
                    # 3.3 Flow check
                    flow_decision = check_flow(self.session_state, tool_call, self.policy_data)
                    if not flow_decision.is_allowed:
                        decision = flow_decision.decision
                        decision_layer = flow_decision.layer
                        decision_reason = flow_decision.reason
                        rule_id = flow_decision.rule_id
        except Exception as exc:
            decision = "deny"
            decision_layer = "policy"
            decision_reason = f"ERR_INTERNAL: internal error: {type(exc).__name__}: {exc}"
            rule_id = None

        if decision == "deny":
            effective_decision = "forwarded" if self.mode == "audit" else "blocked"
        elif decision == "require_approval":
            if self.mode == "audit":
                effective_decision = "forwarded"
            else:
                effective_decision = "held"

        pre_proxy_duration = time.perf_counter() - t_proxy_start

        # If require_approval in enforce mode: register request and await operator elevation
        if effective_decision == "held":
            timeout_sec = 120.0
            if (
                self.policy_data
                and hasattr(self.policy_data, "approval")
                and self.policy_data.approval
            ):
                timeout_sec = getattr(self.policy_data.approval, "timeout_seconds", 120.0) or 120.0

            self.approval_manager.request_approval(
                call_id=call_id,
                session_id=self.session_id,
                agent_id=self.agent_id,
                server=server_name,
                tool=upstream_tool_name,
                args=raw_args,
                capabilities=capabilities,
                taint_state=taint_before,
                rule_id=rule_id or "require-approval",
                timeout_seconds=timeout_sec,
            )

            is_approved = await self._await_approval(call_id, timeout_sec)
            if is_approved:
                effective_decision = "forwarded"
            else:
                effective_decision = "blocked"

        # If blocked in enforce mode: return generic error to agent and record audit event
        if effective_decision == "blocked":
            t_post_start = time.perf_counter()
            self.session_state.deny_count += 1
            self.session_state.call_count += 1
            post_proxy_duration = time.perf_counter() - t_post_start
            total_proxy_ms = (pre_proxy_duration + post_proxy_duration) * 1000.0

            self.audit_logger.log_tool_call(
                session_id=self.session_id,
                call_id=call_id,
                agent_id=self.agent_id,
                server=server_name,
                tool=upstream_tool_name,
                capabilities=capabilities,
                raw_args=raw_args,
                decision=decision,
                effective_decision=effective_decision,
                decision_layer=decision_layer,
                decision_reason=decision_reason,
                rule_id=rule_id,
                pin_status="unchecked",
                latency_ms=LatencyMs(proxy=round(total_proxy_ms, 3), upstream=None),
                taint_before=taint_before,
                taint_after=taint_before,
                response_summary=None,
                error=decision_reason,
            )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="Denied by mcpsec policy")],
                is_error=True,
            )

        # 4. Forward call to the targeted upstream server
        upstream_error: str | None = None
        upstream_result: types.CallToolResult | None = None
        upstream_start = time.perf_counter()

        try:
            upstream_result = await self.upstream_manager.call_tool(
                server_name=server_name,
                tool_name=upstream_tool_name,
                arguments=raw_args,
            )
            upstream_duration_ms = (time.perf_counter() - upstream_start) * 1000.0
        except Exception as exc:
            upstream_duration_ms = (time.perf_counter() - upstream_start) * 1000.0
            upstream_error = str(exc)

        # 5. Post-upstream processing and audit logging
        t_post_start = time.perf_counter()

        if upstream_result is not None:
            self.session_state = update_taint(
                tool_call,
                upstream_result,
                self.session_state,
                self.policy_data,
            )
            content_bytes = compute_content_bytes(upstream_result.content)
            status_str: Literal["ok", "error"] = "error" if upstream_result.is_error else "ok"
            response_summary = ResponseSummary(status=status_str, bytes=content_bytes)
        else:
            response_summary = None

        taint_after = sorted(self.session_state.taint)
        self.session_state.call_count += 1

        post_proxy_duration = time.perf_counter() - t_post_start
        total_proxy_ms = (pre_proxy_duration + post_proxy_duration) * 1000.0

        self.audit_logger.log_tool_call(
            session_id=self.session_id,
            call_id=call_id,
            agent_id=self.agent_id,
            server=server_name,
            tool=upstream_tool_name,
            capabilities=capabilities,
            raw_args=raw_args,
            decision=decision,
            effective_decision=effective_decision,
            decision_layer=decision_layer,
            decision_reason=decision_reason,
            rule_id=rule_id,
            pin_status="unchecked",
            latency_ms=LatencyMs(
                proxy=round(total_proxy_ms, 3),
                upstream=round(upstream_duration_ms, 3),
            ),
            taint_before=taint_before,
            taint_after=taint_after,
            response_summary=response_summary,
            error=upstream_error,
        )

        if upstream_error is not None:
            raise RuntimeError(f"Upstream MCP server error: {upstream_error}")

        assert upstream_result is not None
        return upstream_result
