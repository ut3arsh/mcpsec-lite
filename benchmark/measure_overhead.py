"""Measure proxy overhead per call and report p50/p95 latency distributions."""

from __future__ import annotations

import statistics
import tempfile
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import SessionMessage  # type: ignore[attr-defined]

from mcpsec_core.audit import AuditLogger
from proxy.session import ProxySession
from proxy.supervisor import UpstreamManager
from tests.test_server import create_test_fs_server


async def measure_benchmark(
    num_calls: int = 100,
) -> tuple[float, float, float, float, list[float]]:
    """Run benchmark measuring proxy overhead on tool calls."""
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        sandbox_dir = tmp_dir / "sandbox"
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        audit_log = tmp_dir / "audit.jsonl"

        # Create a sample test file
        test_file = sandbox_dir / "bench.txt"
        test_file.write_text("benchmark test payload line\n" * 20, encoding="utf-8")

        upstream_server = create_test_fs_server(sandbox_dir)
        audit_logger = AuditLogger(log_path=audit_log, log_args="redacted")

        # Memory streams
        up_c2s_writer, up_c2s_reader = anyio.create_memory_object_stream[
            SessionMessage | Exception
        ](100)
        up_s2c_writer, up_s2c_reader = anyio.create_memory_object_stream[SessionMessage](100)

        agent_c2s_writer, agent_c2s_reader = anyio.create_memory_object_stream[
            SessionMessage | Exception
        ](100)
        agent_s2c_writer, agent_s2c_reader = anyio.create_memory_object_stream[SessionMessage](100)

        proxy_server = Server("mcpsec-proxy")

        async with anyio.create_task_group() as tg:
            # Run upstream server
            async def run_upstream() -> None:
                await upstream_server.run(
                    up_c2s_reader,
                    up_s2c_writer,
                    upstream_server.create_initialization_options(),
                    raise_exceptions=True,
                )

            tg.start_soon(run_upstream)

            async with ClientSession(up_s2c_reader, up_c2s_writer) as upstream_client:
                await upstream_client.initialize()

                from unittest.mock import AsyncMock

                tools_res = await upstream_client.list_tools()
                fs_proc = AsyncMock()
                fs_proc.is_healthy = True
                fs_proc.raw_tools = list(tools_res.tools)
                fs_proc.exposed_tools = list(tools_res.tools)

                upstream_mgr = AsyncMock(spec=UpstreamManager)
                upstream_mgr.servers = {"filesystem": fs_proc}
                upstream_mgr.call_tool = lambda srv, tool, args: upstream_client.call_tool(
                    tool, args or {}
                )

                proxy_session = ProxySession(
                    session_id="bench-session",
                    upstream_manager=upstream_mgr,
                    audit_logger=audit_logger,
                    policy_hash="bench-hash",
                    agent_id="bench-agent",
                    mode="enforce",
                )
                proxy_session.start()

                async def handle_list_tools(
                    req_ctx: Any,
                    params: types.PaginatedRequestParams,
                ) -> types.ListToolsResult:
                    return await proxy_session.list_tools()

                async def handle_call_tool(
                    req_ctx: Any,
                    params: types.CallToolRequestParams,
                ) -> types.CallToolResult:
                    return await proxy_session.call_tool(
                        name=params.name,
                        arguments=params.arguments,
                    )

                proxy_server.add_request_handler(
                    "tools/list", types.PaginatedRequestParams, handle_list_tools
                )
                proxy_server.add_request_handler(
                    "tools/call", types.CallToolRequestParams, handle_call_tool
                )

                async def run_proxy() -> None:
                    await proxy_server.run(
                        agent_c2s_reader,
                        agent_s2c_writer,
                        proxy_server.create_initialization_options(),
                        raise_exceptions=True,
                    )

                tg.start_soon(run_proxy)

                async with ClientSession(agent_s2c_reader, agent_c2s_writer) as agent_client:
                    await agent_client.initialize()

                    # Warmup
                    for _ in range(5):
                        await agent_client.call_tool("read_file", {"path": "bench.txt"})

                    # Benchmark measurement loop
                    for _ in range(num_calls):
                        res = await agent_client.call_tool("read_file", {"path": "bench.txt"})
                        assert not res.is_error

                    proxy_session.close()
                    tg.cancel_scope.cancel()

        # Parse audit log to get recorded proxy and upstream latencies
        from cli.replay import stream_audit_events
        from mcpsec_core.models import ToolCallEvent

        events = [ev for ev, _ in stream_audit_events(audit_log)]
        tool_events = [e for e in events if isinstance(e, ToolCallEvent)]
        # Exclude the 5 warmup calls
        measured_events = tool_events[5:]
        proxy_latencies = [e.latency_ms.proxy for e in measured_events]

        p50_proxy = statistics.median(proxy_latencies)
        quantiles = statistics.quantiles(proxy_latencies, n=100)
        p95_proxy = quantiles[94]  # 95th percentile
        mean_proxy = statistics.mean(proxy_latencies)
        max_proxy = max(proxy_latencies)

        return p50_proxy, p95_proxy, mean_proxy, max_proxy, proxy_latencies


def main() -> None:
    num_calls = 100
    print(f"Running benchmark over {num_calls} calls...")
    p50, p95, mean, max_val, _ = anyio.run(measure_benchmark, num_calls)

    print("\n" + "=" * 50)
    print("mcpsec-lite Proxy Overhead Benchmark (Week 1)")
    print("=" * 50)
    print(f"Total Calls Measured: {num_calls}")
    print(f"Proxy Overhead (p50): {p50:.3f} ms")
    print(f"Proxy Overhead (p95): {p95:.3f} ms")
    print(f"Proxy Overhead (mean): {mean:.3f} ms")
    print(f"Proxy Overhead (max): {max_val:.3f} ms")
    print(f"Target (< 10 ms):     {'PASSED (WELL BELOW TARGET)' if p95 < 10.0 else 'FAILED'}")
    print("=" * 50)


if __name__ == "__main__":
    main()
