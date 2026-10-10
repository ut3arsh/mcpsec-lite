"""Proxy session management and multi-upstream tool-call lifecycle coordination."""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Any, Literal

import anyio
import mcp.types as types

from mcpsec_core.adapters import ToolNameMappingError, decode_tool_name
from mcpsec_core.approvals import ApprovalManager
from mcpsec_core.audit import AuditLogger
from mcpsec_core.detectors import scan_arguments, scan_response
from mcpsec_core.flow import check_flow
from mcpsec_core.models import (
    LatencyMs,
    ResponseSummary,
    SessionState,
    ToolCall,
)
from mcpsec_core.pinning import PinStore
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
        pin_store: PinStore | None = None,
    ) -> None:
        self.session_id = session_id
        self.upstream_manager = upstream_manager
        self.audit_logger = audit_logger
        self.policy_hash = policy_hash
        self.agent_id = agent_id
        self.mode = mode
        self.policy_data = policy_data
        self.approval_manager = approval_manager or ApprovalManager()

        # Initialize PinStore
        if pin_store is not None:
            self.pin_store = pin_store
        elif (
            self.policy_data is not None
            and hasattr(self.policy_data, "pinning")
            and self.policy_data.pinning
            and getattr(self.policy_data.pinning, "store", None)
        ):
            self.pin_store = PinStore(Path(self.policy_data.pinning.store))
        else:
            self.pin_store = PinStore("./pins.json")

        self.pin_store.load(fail_closed=(self.mode == "enforce"))

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
        """Return deterministic, sorted union of visible tools according to pinning policy."""
        all_tools = self.upstream_manager.list_all_tools()
        pinning_mode: Literal["audit", "strict"] = "audit"
        if (
            self.policy_data is not None
            and hasattr(self.policy_data, "pinning")
            and self.policy_data.pinning
        ):
            pinning_mode = getattr(self.policy_data.pinning, "mode", "audit")

        visible_tools: list[types.Tool] = []
        for t in all_tools:
            try:
                server_name, upstream_tool_name = decode_tool_name(t.name)
            except Exception:
                server_name, upstream_tool_name = "unknown", t.name

            in_schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", {})
            out_schema = getattr(t, "output_schema", None) or getattr(t, "outputSchema", None)
            tool_dict: dict[str, Any] = {
                "name": upstream_tool_name,
                "description": getattr(t, "description", None),
                "inputSchema": in_schema,
            }
            if getattr(t, "title", None) is not None:
                tool_dict["title"] = t.title
            if out_schema is not None:
                tool_dict["outputSchema"] = out_schema
            if getattr(t, "annotations", None) is not None:
                tool_dict["annotations"] = t.annotations

            status, diff_summary, new_hash = self.pin_store.check_tool(
                server=server_name,
                tool_def=tool_dict,
                mode=pinning_mode,
            )

            if pinning_mode == "strict":
                if status == "pinned":
                    visible_tools.append(t)
                else:
                    # OMIT unreviewed / changed tool from agent-facing list
                    action: Literal["first_seen", "changed"] = (
                        "first_seen" if status == "unpinned" else "changed"
                    )
                    old_pin = self.pin_store.get_tool_pin(server_name, upstream_tool_name)
                    old_hash = old_pin.tool_hash if old_pin else None
                    self.audit_logger.log_pin_event(
                        server=server_name,
                        tool=upstream_tool_name,
                        action=action,
                        old_hash=old_hash,
                        new_hash=new_hash,
                        diff_summary=diff_summary,
                        mode="strict",
                        effective_decision="blocked_until_approved",
                        session_id=self.session_id,
                    )
            else:
                # audit mode: expose all tools to agent
                visible_tools.append(t)
                if status == "unpinned":
                    self.audit_logger.log_pin_event(
                        server=server_name,
                        tool=upstream_tool_name,
                        action="first_seen",
                        old_hash=None,
                        new_hash=new_hash,
                        diff_summary=diff_summary,
                        mode="audit",
                        effective_decision="accepted",
                        session_id=self.session_id,
                    )
                    # Trust on first use in audit mode
                    self.pin_store.approve_tool(server_name, tool_dict)
                elif status == "changed":
                    old_pin = self.pin_store.get_tool_pin(server_name, upstream_tool_name)
                    old_hash = old_pin.tool_hash if old_pin else None
                    self.audit_logger.log_pin_event(
                        server=server_name,
                        tool=upstream_tool_name,
                        action="changed",
                        old_hash=old_hash,
                        new_hash=new_hash,
                        diff_summary=diff_summary,
                        mode="audit",
                        effective_decision="logged",
                        session_id=self.session_id,
                    )

        return types.ListToolsResult(tools=visible_tools)

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

        # Check pinning mode
        pinning_mode: Literal["audit", "strict"] = "audit"
        if (
            self.policy_data is not None
            and hasattr(self.policy_data, "pinning")
            and self.policy_data.pinning
        ):
            pinning_mode = getattr(self.policy_data.pinning, "mode", "audit")

        # Find tool definition for pinning check
        tool_dict: dict[str, Any] = {"name": upstream_tool_name}
        for t in self.upstream_manager.list_all_tools():
            if t.name == name:
                in_schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", {})
                out_schema = getattr(t, "output_schema", None) or getattr(t, "outputSchema", None)
                tool_dict["description"] = getattr(t, "description", None)
                tool_dict["inputSchema"] = in_schema
                if getattr(t, "title", None) is not None:
                    tool_dict["title"] = t.title
                if out_schema is not None:
                    tool_dict["outputSchema"] = out_schema
                if getattr(t, "annotations", None) is not None:
                    tool_dict["annotations"] = t.annotations
                break

        pin_status, diff_summary, current_hash = self.pin_store.check_tool(
            server=server_name,
            tool_def=tool_dict,
            mode=pinning_mode,
        )

        try:
            # 3.1 Pinning check in strict mode
            if pinning_mode == "strict" and pin_status != "pinned":
                decision = "deny"
                decision_layer = "pinning"
                decision_reason = (
                    f"Tool '{server_name}.{upstream_tool_name}' is {pin_status} under strict pinning"
                )
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

        flags: list[str] = []
        risk_score: float | None = None
        if (
            self.policy_data is not None
            and hasattr(self.policy_data, "detectors")
            and self.policy_data.detectors
        ):
            if getattr(self.policy_data.detectors, "secrets", False):
                flags.extend(scan_arguments(raw_args))

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
                pin_status=pin_status,
                flags=flags,
                risk_score=risk_score,
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

            # Advisory response scan in memory (never logged)
            if (
                self.policy_data is not None
                and hasattr(self.policy_data, "detectors")
                and self.policy_data.detectors
            ):
                if getattr(self.policy_data.detectors, "injection_heuristics", False):
                    resp_flags, resp_score = scan_response(upstream_result.content)
                    flags.extend(resp_flags)
                    risk_score = resp_score
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
            pin_status=pin_status,
            flags=flags,
            risk_score=risk_score,
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
